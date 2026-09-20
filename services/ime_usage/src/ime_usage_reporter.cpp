/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ime_usage_reporter.h"

#include <algorithm>
#include <chrono>

#include "fold_status_adapter.h"
#include "global.h"
#include "hisysevent.h"

using namespace OHOS::MiscServices::ImeUsageEventSpace;
using OHOS::MiscServices::IME_USAGE_SUCCESS;
using OHOS::MiscServices::REPORT_TIME_NEVER;

namespace OHOS {
namespace MiscServices {
namespace {
// Daily report check interval: 5 minutes
constexpr uint64_t TIMER_INTERVAL_MS = 5ULL * 60 * MILLISECS_PER_SEC;
constexpr const char *TIMER_TASK_NAME = "ime_usage_daily_report";
} // namespace

ImeUsageReporter::~ImeUsageReporter()
{
    isRunning_ = false;
    if (eventHandler_ != nullptr) {
        // RemoveTask cancels pending (not yet dispatched) tasks only.
        // If OnTimeout is currently executing on the EventHandler thread,
        // it has already passed the isRunning_ check (line 129) and may
        // still be accessing members. This is safe because:
        //   1. The ImeUsageReporter is owned by InputMethodSystemAbility,
        //      which also owns the EventHandler. Destruction order is:
        //      ~ImeUsageReporter (this dtor) → member destruction → ~EventHandler.
        //   2. ~EventHandler joins its internal thread, so OnTimeout will
        //      complete before EventHandler is destroyed.
        //   3. OnTimeout's only state access after the check is the
        //      reportMutex_-protected ReportDailyEvent(), and the mutex
        //      itself is not destroyed until after EventHandler is destroyed.
        // Therefore the current running OnTimeout will finish safely before
        // any member is destroyed, and no new OnTimeout dispatch will occur
        // after RemoveTask returns.
        eventHandler_->RemoveTask(TIMER_TASK_NAME);
    }
}

int ImeUsageReporter::Init(const std::string &workPath)
{
    IMSA_HILOGI("ImeUsageReporter::Init start, workPath=%{public}s", workPath.c_str());
    workPath_ = workPath;

    int ret = CreateComponents(workPath);
    if (ret != 0) {
        // Don't return failure: keep the reporter alive so OnTimeout can retry
        // CreateComponents later (e.g., if the work directory wasn't ready at
        // early boot). All event callbacks (OnImeBind/OnImeUnbind/OnScreenStatusChanged)
        // check dataHelper_/eventCacher_ for null and degrade gracefully — events
        // are simply not cached until the retry succeeds.
        IMSA_HILOGW("CreateComponents failed, will retry on timer, ret=%{public}d", ret);
    } else {
        LoadReportStateAndCheckReport();
    }

    isRunning_ = true;

    uint64_t currentPeriodStart = OHOS::MiscServices::GetToday0ClockMs();
    uint64_t loggedLastReport = 0;
    uint64_t loggedNextReport = 0;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        loggedLastReport = lastReportTime_;
        loggedNextReport = nextReportTime_;
    }
    IMSA_HILOGI("ImeUsageReporter initialized, workPath=%{public}s, currentPeriodStart=%{public}llu, "
                "nextReportTime=%{public}llu, lastReportTime=%{public}llu",
        workPath.c_str(), static_cast<unsigned long long>(currentPeriodStart),
        static_cast<unsigned long long>(loggedNextReport), static_cast<unsigned long long>(loggedLastReport));
    return 0;
}

int ImeUsageReporter::CreateComponents(const std::string &workPath)
{
    // Build all components in locals first, then move to members only after
    // every step succeeds. This ensures members are never left in a
    // half-initialized state — critical for retry from OnTimeout, where
    // eventCacher_ must not be visible until its Init() has completed.
    // Note: make_shared/make_unique throw std::bad_alloc on failure, never
    // return null — no null check needed.
    auto dataHelper = std::make_shared<ImeUsageDataHelper>(workPath);
    if (!dataHelper->IsReady()) {
        IMSA_HILOGE("Failed to create dataHelper or JSON store init failed");
        return IME_USAGE_FAILED;
    }
    auto eventCacher = std::make_unique<ImeUsageEventCacher>();
    // Synchronize initial fold/vh state from FoldStatusAdapter to avoid
    // screenStatus=0 (uninitialized) when keyboard shows before the first
    // OnScreenStatusChanged callback arrives. GetScreenStatus() falls back to
    // UNFOLDED_PORTRAIT(12) when both are 0; the first callback will override.
    auto &foldAdapter = FoldStatusAdapter::GetInstance();
    int ret = eventCacher->Init(dataHelper, foldAdapter.GetFoldStatus(), foldAdapter.GetVhMode());
    if (ret != IME_USAGE_SUCCESS) {
        IMSA_HILOGE("eventCacher Init failed, ret=%{public}d", ret);
        return ret;
    }
    auto eventFactory = std::make_unique<ImeUsageEventFactory>(dataHelper);
    // All components created and initialized successfully — assign to members.
    dataHelper_ = std::move(dataHelper);
    eventCacher_ = std::move(eventCacher);
    eventFactory_ = std::move(eventFactory);
    return 0;
}

void ImeUsageReporter::LoadReportStateAndCheckReport()
{
    // Load persisted lastReportTime from DB
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        lastReportTime_ = LoadLastReportTime();
        nextReportTime_ = GetNextReportTimeMs();
    }
    // If last report was before the current report period, report immediately
    uint64_t currentPeriodStart = OHOS::MiscServices::GetToday0ClockMs();
    uint64_t localLastReportTime = 0;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        localLastReportTime = lastReportTime_;
    }
    if (localLastReportTime < currentPeriodStart) {
        IMSA_HILOGI("Init: unreported data detected, reporting immediately");
        InnerReportDailyEvent();
    }
}

void ImeUsageReporter::SetEventHandler(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    IMSA_HILOGI("SetEventHandler");
    eventHandler_ = handler;
    StartTimer();
}

void ImeUsageReporter::StartTimer()
{
    if (eventHandler_ == nullptr) {
        IMSA_HILOGE("eventHandler_ is nullptr, cannot start timer");
        return;
    }
    auto task = [this]() {
        OnTimeout();
    };
    eventHandler_->PostTask(task, TIMER_TASK_NAME, TIMER_INTERVAL_MS);
}

void ImeUsageReporter::OnTimeout()
{
    if (!isRunning_) {
        IMSA_HILOGI("OnTimeout: reporter not running, skip");
        return;
    }
    // Retry component initialization if it failed during Init (e.g., work
    // directory wasn't ready at early boot). On success, load report state
    // and check for pending reports. On failure, just re-schedule and try
    // again on the next timer tick.
    if (dataHelper_ == nullptr) {
        IMSA_HILOGI("OnTimeout: retrying CreateComponents");
        if (CreateComponents(workPath_) == 0) {
            LoadReportStateAndCheckReport();
        }
        StartTimer();
        return;
    }
    IMSA_HILOGD("OnTimeout: checking daily report, now=%{public}llu", static_cast<unsigned long long>(GetNowMs()));
    ReportDailyEvent();
    // Re-schedule the timer
    StartTimer();
}

void ImeUsageReporter::ReportDailyEvent()
{
    // Read state under lock to determine action, then release lock before I/O.
    // All callers of this method and InnerReportDailyEvent are serialized on
    // the WorkThread (single-threaded event loop), or on the main thread before
    // the timer starts. The lock protects only the brief state reads/writes,
    // not the I/O-heavy InnerReportDailyEvent/ReportSingleDay calls.
    uint64_t nowTime = GetNowMs();
    uint64_t nextReport = 0;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        nextReport = nextReportTime_;
    }

    // Time jumped forward > 1 day: report unreported data
    if (nowTime > (nextReport + MILLISECS_PER_DAY)) {
        IMSA_HILOGW("ReportDailyEvent: time jumped forward, now=%{public}llu, "
                    "nextReportTime=%{public}llu, reporting",
            static_cast<unsigned long long>(nowTime), static_cast<unsigned long long>(nextReport));
        InnerReportDailyEvent();
        return;
    }

    // Time jumped backward > 1 day (clock adjusted): reset baseline.
    // Set lastReportTime_ to the end of the day BEFORE now (day0 - 1ms), not
    // nowTime itself. A mid-day lastReportTime would cause CalcReportDayStart
    // to skip the entire current day in the next report cycle. Using day0 - 1
    // (yesterdayEnd) ensures the current day is treated as unreported and will
    // be picked up by the next report.
    if (nowTime < (nextReport - MILLISECS_PER_DAY)) {
        IMSA_HILOGW("ReportDailyEvent: time jumped backward, now=%{public}llu, "
                    "nextReportTime=%{public}llu, resetting",
            static_cast<unsigned long long>(nowTime), static_cast<unsigned long long>(nextReport));
        uint64_t nowDay0 = OHOS::MiscServices::DayStartFromMs(nowTime);
        uint64_t yesterdayEnd = nowDay0 > 0 ? nowDay0 - 1 : 0;
        {
            std::lock_guard<std::mutex> lock(reportMutex_);
            lastReportTime_ = yesterdayEnd;
            nextReportTime_ = GetNextReportTimeMs();
        }
        PersistLastReportTime();
        return;
    }

    // Normal day boundary crossing
    if (nowTime >= nextReport) {
        IMSA_HILOGD("ReportDailyEvent: day boundary crossed, "
                    "now=%{public}llu >= nextReportTime=%{public}llu",
            static_cast<unsigned long long>(nowTime), static_cast<unsigned long long>(nextReport));
        InnerReportDailyEvent();
    }
}

void ImeUsageReporter::InnerReportDailyEvent()
{
    if (dataHelper_ == nullptr) {
        IMSA_HILOGE("InnerReportDailyEvent: dataHelper is nullptr");
        return;
    }
    uint64_t today0Time = OHOS::MiscServices::GetToday0ClockMs();
    uint64_t reportDayStart = 0;
    if (!CalcReportDayStart(today0Time, reportDayStart)) {
        return;
    }
    uint64_t yesterdayEnd = today0Time > 0 ? today0Time - 1 : 0;
    bool anyReported = ReportUnreportedDays(reportDayStart, yesterdayEnd);

    // Clean up old data: report each expiring day (not yet reported) then delete.
    uint64_t clearDataTime =
        (today0Time > MILLISECS_PER_DAY * DATA_KEEP_DAY) ? (today0Time - MILLISECS_PER_DAY * DATA_KEEP_DAY) : 0;
    // Update and persist lastReportTime_ BEFORE cleanup so that
    // DeleteEventsByTime (which writes lastReportTime_ to JSON) uses the new value.
    // Set lastReportTime_ to yesterdayEnd (the end of the reported period), NOT
    // GetNowMs(): if we set it to now (which is today), CalcReportDayStart would
    // compute reportDayStart = today_day0 + 1 = tomorrow, skipping today's data
    // in the next report cycle. Using yesterdayEnd ensures the next cycle starts
    // from today (yesterdayEnd_day0 + 1 = today_day0).
    UpdateAndPersistReportTime(yesterdayEnd);
    if (clearDataTime > 0) {
        ReportAndCleanupOldData(clearDataTime);
    }

    uint64_t loggedLastReport = 0;
    uint64_t loggedNextReport = 0;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        loggedLastReport = lastReportTime_;
        loggedNextReport = nextReportTime_;
    }
    IMSA_HILOGD("Daily report completed, reportedDays=%{public}d, "
                "lastReportTime=%{public}llu, nextReportTime=%{public}llu",
        static_cast<int>(anyReported), static_cast<unsigned long long>(loggedLastReport),
        static_cast<unsigned long long>(loggedNextReport));
}

bool ImeUsageReporter::CalcReportDayStart(uint64_t today0Time, uint64_t &reportDayStart)
{
    uint64_t localLastReportTime = 0;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        localLastReportTime = lastReportTime_;
    }
    if (localLastReportTime == REPORT_TIME_NEVER) {
        int64_t earliestTime = dataHelper_->QueryEarliestEventTime();
        if (earliestTime <= 0) {
            IMSA_HILOGI("InnerReportDailyEvent: no data in DB, nothing to report");
            // Do NOT update lastReportTime_ here: it must remain REPORT_TIME_NEVER
            // so that when data arrives, the next report cycle correctly starts
            // from the earliest event day. Setting lastReportTime to now would
            // cause the first day's data to be skipped (reportDayStart = now_day
            // + 1 > yesterdayEnd). Only advance nextReportTime_ to avoid
            // repeatedly triggering InnerReportDailyEvent on every timer tick.
            {
                std::lock_guard<std::mutex> lock(reportMutex_);
                nextReportTime_ = GetNextReportTimeMs();
            }
            return false;
        }
        reportDayStart = OHOS::MiscServices::DayStartFromMs(static_cast<uint64_t>(earliestTime));
        return true;
    }
    // reportDayStart is the first day that may still have unreported data.
    // lastReportTime means "everything up to and including this moment is
    // reported", so the next unreported moment is lastReportTime + 1ms, and
    // the day containing that moment is where reporting should resume.
    //
    // This handles two cases correctly:
    //  1. Normal case: lastReportTime = 09-19 23:59:59.999 (a day-end value
    //     written by UpdateAndPersistReportTime(yesterdayEnd)). Then
    //     lastReportTime + 1 = 09-20 00:00:00.000, DayStart = 09-20 00:00 —
    //     the next unreported day. Identical to the old formula.
    //  2. Stale/mid-day lastReportTime (e.g., 09-20 00:24:34.899, written by
    //     older code that set lastReportTime = now, or by the time-jumped-
    //     backward branch). The old formula DayStartFromMs(lastReportTime) + 1
    //     day would yield 09-21 00:00, skipping 09-20 entirely. The new formula
    //     yields DayStart(09-20 00:24:34.900) = 09-20 00:00, so 09-20's data is
    //     reported (at worst re-reporting the portion before lastReportTime,
    //     which is acceptable and far better than losing the whole day).
    reportDayStart = OHOS::MiscServices::DayStartFromMs(localLastReportTime + 1);
    return true;
}

bool ImeUsageReporter::ReportUnreportedDays(uint64_t reportDayStart, uint64_t yesterdayEnd)
{
    // Each day is reported independently so that a failure on one day does
    // not block subsequent days.
    if (reportDayStart > yesterdayEnd) {
        IMSA_HILOGD("InnerReportDailyEvent: no unreported days to report");
        return false;
    }
    auto activeDays = dataHelper_->QueryActiveDays(reportDayStart, yesterdayEnd);
    IMSA_HILOGI("InnerReportDailyEvent: reporting %{public}zu unreported days "
                "[reportDayStart=%{public}llu, yesterdayEnd=%{public}llu]",
        activeDays.size(), static_cast<unsigned long long>(reportDayStart),
        static_cast<unsigned long long>(yesterdayEnd));
    bool anyReported = false;
    for (uint64_t dayStart : activeDays) {
        uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;
        std::string dateStr = FormatDateStr(dayStart);
        if (ReportSingleDay(dayStart, dayEnd, dateStr)) {
            anyReported = true;
        }
    }
    return anyReported;
}

void ImeUsageReporter::UpdateAndPersistReportTime(uint64_t reportEndTime)
{
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        lastReportTime_ = reportEndTime;
        nextReportTime_ = GetNextReportTimeMs();
    }
    PersistLastReportTime();
}

bool ImeUsageReporter::ReportSingleDay(uint64_t dayStartTime, uint64_t dayEndTime, const std::string &dateStr)
{
    if (eventFactory_ == nullptr) {
        return false;
    }

    IMSA_HILOGI("ReportSingleDay: date=%{public}s, dayStart=%{public}llu, dayEnd=%{public}llu", dateStr.c_str(),
        static_cast<unsigned long long>(dayStartTime), static_cast<unsigned long long>(dayEndTime));

    std::vector<ImeUsageInfo> infos;
    eventFactory_->Create(infos, dayStartTime, dayEndTime);

    IMSA_HILOGD("ReportSingleDay: date=%{public}s, aggregation produced %{public}zu IME entries", dateStr.c_str(),
        infos.size());

    bool allSuccess = true;
    for (const auto &info : infos) {
        if (!WriteImeUsageEvent(info, dateStr)) {
            allSuccess = false;
        }
    }
    return allSuccess;
}

bool ImeUsageReporter::WriteImeUsageEvent(const ImeUsageInfo &info, const std::string &dateStr)
{
    int ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::INPUTMETHOD_UE, EVENT_NAME,
        HiviewDFX::HiSysEvent::EventType::STATISTIC, KEY_OF_PACKAGE, info.package, KEY_OF_FOLD_PORTRAIT,
        info.durations[IDX_FOLD_PORTRAIT], KEY_OF_FOLD_LANDSCAPE, info.durations[IDX_FOLD_LANDSCAPE],
        KEY_OF_EXPAND_PORTRAIT, info.durations[IDX_EXPAND_PORTRAIT], KEY_OF_EXPAND_LANDSCAPE,
        info.durations[IDX_EXPAND_LANDSCAPE], KEY_OF_G_PORTRAIT, info.durations[IDX_G_PORTRAIT], KEY_OF_G_LANDSCAPE,
        info.durations[IDX_G_LANDSCAPE], KEY_OF_UNFOLDED_PORTRAIT, info.durations[IDX_UNFOLDED_PORTRAIT],
        KEY_OF_UNFOLDED_LANDSCAPE, info.durations[IDX_UNFOLDED_LANDSCAPE], KEY_OF_N_PORTRAIT,
        info.durations[IDX_N_PORTRAIT], KEY_OF_N_LANDSCAPE, info.durations[IDX_N_LANDSCAPE], KEY_OF_LM_PORTRAIT,
        info.durations[IDX_LM_PORTRAIT], KEY_OF_LM_LANDSCAPE, info.durations[IDX_LM_LANDSCAPE], KEY_OF_USAGE,
        info.usage, KEY_OF_DATE, dateStr, KEY_OF_SHOW_COUNT, info.showCount);
    if (ret != IME_USAGE_SUCCESS) {
        IMSA_HILOGE("HiSysEventWrite failed for %{public}s date=%{public}s, ret=%{public}d", info.package.c_str(),
            dateStr.c_str(), ret);
        return false;
    }

    IMSA_HILOGI("Reporting IME: pkg=%{public}s, usage=%{public}llu, showCount=%{public}u, "
                "foldV=%{public}u, foldH=%{public}u, expdV=%{public}u, expdH=%{public}u, "
                "gV=%{public}u, gH=%{public}u, unfoldV=%{public}u, unfoldH=%{public}u, "
                "nV=%{public}u, nH=%{public}u, lmV=%{public}u, lmH=%{public}u, "
                "HiSysEventWrite success, for %{public}s date=%{public}s",
        info.package.c_str(), static_cast<unsigned long long>(info.usage), info.showCount,
        info.durations[IDX_FOLD_PORTRAIT], info.durations[IDX_FOLD_LANDSCAPE], info.durations[IDX_EXPAND_PORTRAIT],
        info.durations[IDX_EXPAND_LANDSCAPE], info.durations[IDX_G_PORTRAIT], info.durations[IDX_G_LANDSCAPE],
        info.durations[IDX_UNFOLDED_PORTRAIT], info.durations[IDX_UNFOLDED_LANDSCAPE], info.durations[IDX_N_PORTRAIT],
        info.durations[IDX_N_LANDSCAPE], info.durations[IDX_LM_PORTRAIT], info.durations[IDX_LM_LANDSCAPE],
        info.package.c_str(), dateStr.c_str());
    return true;
}

void ImeUsageReporter::ReportAndCleanupOldData(uint64_t clearDataTime)
{
    if (eventFactory_ == nullptr || dataHelper_ == nullptr) {
        return;
    }

    // Data older than clearDataTime is about to be deleted. Before deleting,
    // report any days in that range that were NOT already covered by a previous
    // report (i.e. happenTime > lastReportTime). Days already reported
    // (happenTime <= lastReportTime) are just deleted — re-reporting them would
    // produce duplicates.
    //
    // The upper bound for the cleanup range is clearDataTime - 1 (exclusive of
    // clearDataTime itself, which is a day boundary). The lower bound for
    // *reporting* is lastReportTime + 1 (the first unreported moment). Anything
    // at or below lastReportTime has already been reported and needs no re-report.
    uint64_t reportEnd = clearDataTime > 0 ? clearDataTime - 1 : 0;
    uint64_t localLastReportTime = 0;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        localLastReportTime = lastReportTime_;
    }
    uint64_t unreportedStart = (localLastReportTime == REPORT_TIME_NEVER) ?
        0 :
        (localLastReportTime + 1 > reportEnd ? reportEnd + 1 : localLastReportTime + 1);

    auto activeDays = dataHelper_->QueryActiveDays(unreportedStart, reportEnd);

    IMSA_HILOGI("ReportAndCleanupOldData: clearDataTime=%{public}llu, reportEnd=%{public}llu, "
                "unreportedStart=%{public}llu, lastReportTime=%{public}llu, activeDays=%{public}zu",
        static_cast<unsigned long long>(clearDataTime), static_cast<unsigned long long>(reportEnd),
        static_cast<unsigned long long>(unreportedStart), static_cast<unsigned long long>(localLastReportTime),
        activeDays.size());

    // Report each unreported day that is about to be deleted.
    bool allReported = true;
    for (uint64_t dayStart : activeDays) {
        uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;
        std::string dateStr = FormatDateStr(dayStart);
        if (!ReportSingleDay(dayStart, dayEnd, dateStr)) {
            allReported = false;
        }
    }

    // Only delete if all reports succeeded; otherwise keep data for next attempt.
    // DeleteEventsByTime deletes events with happenTime < clearDataTime, which
    // covers both the days just reported and the already-reported days.
    if (allReported) {
        dataHelper_->DeleteEventsByTime(clearDataTime);
        IMSA_HILOGI("ReportAndCleanupOldData: completed, cleaned data before %{public}llu",
            static_cast<unsigned long long>(clearDataTime));
    } else {
        IMSA_HILOGW("ReportAndCleanupOldData: some reports failed, keeping data for retry");
    }
}

uint64_t ImeUsageReporter::GetNowMs() const
{
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
}

void ImeUsageReporter::OnImeBind(const std::string &bundleName)
{
    IMSA_HILOGI("OnImeBind: bundle=%{public}s", bundleName.c_str());
    if (eventCacher_ != nullptr) {
        eventCacher_->OnImeBind(bundleName);
    }
}

void ImeUsageReporter::OnImeUnbind(const std::string &bundleName)
{
    IMSA_HILOGI("OnImeUnbind: bundle=%{public}s", bundleName.c_str());
    if (eventCacher_ != nullptr) {
        eventCacher_->OnImeUnbind(bundleName);
    }
}

void ImeUsageReporter::OnScreenStatusChanged(int32_t preScreenStatus, int32_t newScreenStatus)
{
    IMSA_HILOGI("OnScreenStatusChanged: pre=%{public}d, new=%{public}d", preScreenStatus, newScreenStatus);
    if (eventCacher_ != nullptr) {
        eventCacher_->OnScreenStatusChanged(preScreenStatus, newScreenStatus);
    }
}

void ImeUsageReporter::OnBootCompleted()
{
    if (eventCacher_ != nullptr) {
        eventCacher_->RecoverActiveSession();
    }
    // Load report state and check for pending reports — same logic as Init.
    LoadReportStateAndCheckReport();
    uint64_t loggedLastReport = 0;
    uint64_t loggedNextReport = 0;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        loggedLastReport = lastReportTime_;
        loggedNextReport = nextReportTime_;
    }
    IMSA_HILOGI("OnBootCompleted: lastReportTime=%{public}llu, nextReportTime=%{public}llu",
        static_cast<unsigned long long>(loggedLastReport), static_cast<unsigned long long>(loggedNextReport));
}

void ImeUsageReporter::PersistLastReportTime()
{
    if (dataHelper_ == nullptr) {
        IMSA_HILOGE("PersistLastReportTime: dataHelper is nullptr");
        return;
    }
    uint64_t localLastReportTime = 0;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        localLastReportTime = lastReportTime_;
    }
    int ret = dataHelper_->SaveReportState(STATE_KEY_LAST_REPORT_TIME, localLastReportTime);
    if (ret != IME_USAGE_SUCCESS) {
        IMSA_HILOGE("PersistLastReportTime failed, ret=%{public}d", ret);
    }
}

uint64_t ImeUsageReporter::LoadLastReportTime()
{
    if (dataHelper_ == nullptr) {
        IMSA_HILOGE("LoadLastReportTime: dataHelper is nullptr");
        return REPORT_TIME_NEVER;
    }
    uint64_t value = 0;
    int ret = dataHelper_->LoadReportState(STATE_KEY_LAST_REPORT_TIME, value);
    if (ret != IME_USAGE_SUCCESS) {
        IMSA_HILOGI("LoadLastReportTime: not found or failed, defaulting to REPORT_TIME_NEVER");
        return REPORT_TIME_NEVER;
    }
    IMSA_HILOGD("LoadLastReportTime: loaded %{public}llu", static_cast<unsigned long long>(value));
    return value;
}

uint64_t ImeUsageReporter::GetNextReportTimeMs() const
{
    uint64_t today0 = OHOS::MiscServices::GetToday0ClockMs();
    if (today0 == REPORT_TIME_NEVER) {
        return GetNowMs() + MILLISECS_PER_DAY;
    }
    // Next midnight = today's 0:00 + 1 day
    return today0 + MILLISECS_PER_DAY;
}

} // namespace MiscServices
} // namespace OHOS
