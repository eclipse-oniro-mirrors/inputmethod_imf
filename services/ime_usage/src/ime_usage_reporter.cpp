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
 
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <ctime>
 
#include "fold_status_adapter.h"
#include "global.h"
#include "hisysevent.h"
 
using namespace OHOS::MiscServices::ImeUsageEventSpace;
 
namespace OHOS {
namespace MiscServices {
namespace {
constexpr uint64_t TIMER_INTERVAL_MS = 5ULL * 60 * 1000; // 5 minutes check interval
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
 
    // Create shared dbHelper instance
    auto dbHelper = std::make_shared<ImeUsageDbHelper>(workPath);
    if (dbHelper == nullptr || !dbHelper->IsReady()) {
        IMSA_HILOGE("Failed to create dbHelper or RDB store init failed");
        return -1;
    }
 
    eventCacher_ = std::make_unique<ImeUsageEventCacher>();
    if (eventCacher_ == nullptr) {
        IMSA_HILOGE("Failed to create eventCacher");
        return -1;
    }
    // Synchronize initial fold/vh state from FoldStatusAdapter to avoid
    // screenStatus=0 (uninitialized) when keyboard shows before the first
    // OnScreenStatusChanged callback arrives.
    // If FoldStatusAdapter has not yet registered its listeners, GetFoldStatus()
    // and GetVhMode() return 0. This is safe because eventCacher_->Init stores
    // these values, and GetScreenStatus() falls back to UNFOLDED_PORTRAIT(12)
    // when both are 0. Once the first OnScreenStatusChanged callback fires,
    // the correct values will be propagated and override the initial state.
    auto &foldAdapter = FoldStatusAdapter::GetInstance();
    int ret = eventCacher_->Init(dbHelper, foldAdapter.GetFoldStatus(), foldAdapter.GetVhMode());
    if (ret != 0) {
        IMSA_HILOGE("eventCacher Init failed, ret=%{public}d", ret);
        return ret;
    }
 
    eventFactory_ = std::make_unique<ImeUsageEventFactory>(dbHelper);
    if (eventFactory_ == nullptr) {
        IMSA_HILOGE("Failed to create eventFactory");
        return -1;
    }
 
    // Load persisted lastReportTime from DB
    lastReportTime_ = LoadLastReportTime();
 
    // Initialize report time tracking
    nextReportTime_ = GetNextReportTimeMs();
 
    // If last report was before the current report period, we need to catch up
    uint64_t currentPeriodStart = GetCurrentPeriodStartMs();
    if (lastReportTime_ < currentPeriodStart) {
        shouldReportLastData_ = true;
    }
 
    isRunning_ = true;
 
    IMSA_HILOGI("ImeUsageReporter initialized, workPath=%{public}s, currentPeriodStart=%{public}llu, "
        "nextReportTime=%{public}llu, lastReportTime=%{public}llu, shouldReportLastData=%{public}d",
        workPath.c_str(), static_cast<unsigned long long>(currentPeriodStart),
        static_cast<unsigned long long>(nextReportTime_),
        static_cast<unsigned long long>(lastReportTime_),
        shouldReportLastData_.load());
    return 0;
}
 
void ImeUsageReporter::SetEventHandler(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    IMSA_HILOGD("SetEventHandler, handler=%{public}p", handler.get());
    eventHandler_ = handler;
    StartTimer();
}
 
void ImeUsageReporter::StartTimer()
{
    if (eventHandler_ == nullptr) {
        IMSA_HILOGE("eventHandler_ is nullptr, cannot start timer");
        return;
    }
    auto task = [this]() { OnTimeout(); };
    eventHandler_->PostTask(task, TIMER_TASK_NAME, TIMER_INTERVAL_MS);
}
 
void ImeUsageReporter::OnTimeout()
{
    if (!isRunning_) {
        IMSA_HILOGD("OnTimeout: reporter not running, skip");
        return;
    }
    uint64_t nextReport = 0;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        nextReport = nextReportTime_;
    }
    IMSA_HILOGD("OnTimeout: checking daily report, now=%{public}llu, nextReportTime=%{public}llu",
        static_cast<unsigned long long>(GetNowMs()),
        static_cast<unsigned long long>(nextReport));
    ReportDailyEvent();
    // Re-schedule the timer
    StartTimer();
}
 
void ImeUsageReporter::ReportDailyEvent()
{
    std::lock_guard<std::mutex> lock(reportMutex_);
    // Scenario 1: missed periods from last boot (crash/reboot recovery)
    if (shouldReportLastData_) {
        IMSA_HILOGI("ReportDailyEvent: scenario1=crash/reboot recovery, triggering report");
        InnerReportDailyEvent();
        shouldReportLastData_ = false;
        return;
    }
 
    uint64_t nowTime = GetNowMs();
 
    // Scenario 2: time jumped forward (> 1 report interval gap)
    if (nowTime > (nextReportTime_ + MILLISECS_PER_DAY)) {
        IMSA_HILOGW("ReportDailyEvent: scenario2=time jumped forward, now=%{public}llu, "
            "nextReportTime=%{public}llu", static_cast<unsigned long long>(nowTime),
            static_cast<unsigned long long>(nextReportTime_));
        uint64_t currentPeriodStart = GetCurrentPeriodStartMs();
        if (lastReportTime_ < currentPeriodStart) {
            IMSA_HILOGI("ReportDailyEvent: scenario2 triggering report, lastReportTime=%{public}llu "
                "< currentPeriodStart=%{public}llu",
                static_cast<unsigned long long>(lastReportTime_),
                static_cast<unsigned long long>(currentPeriodStart));
            InnerReportDailyEvent();
        }
        return;
    }
 
    // Scenario 3: time jumped backward (clock adjusted)
    if (nowTime < (nextReportTime_ - MILLISECS_PER_DAY)) {
        IMSA_HILOGW("ReportDailyEvent: scenario3=time jumped backward, now=%{public}llu, "
            "nextReportTime=%{public}llu", static_cast<unsigned long long>(nowTime),
            static_cast<unsigned long long>(nextReportTime_));
        lastReportTime_ = nowTime;
        nextReportTime_ = GetNextReportTimeMs();
        PersistLastReportTime();
        // After clock adjustment, check if we now need to report
        uint64_t currentPeriodStart = GetCurrentPeriodStartMs();
        if (lastReportTime_ < currentPeriodStart) {
            IMSA_HILOGI("ReportDailyEvent: scenario3 triggering report after clock adjustment");
            InnerReportDailyEvent();
        }
        return;
    }
 
    // Scenario 4: normal report boundary crossing
    if (nowTime >= nextReportTime_) {
        IMSA_HILOGI("ReportDailyEvent: scenario4=normal boundary crossing, "
            "now=%{public}llu >= nextReportTime=%{public}llu",
            static_cast<unsigned long long>(nowTime),
            static_cast<unsigned long long>(nextReportTime_));
        InnerReportDailyEvent();
    }
}
 
void ImeUsageReporter::InnerReportDailyEvent()
{
    if (eventFactory_ == nullptr || eventFactory_->GetDbHelper() == nullptr) {
        IMSA_HILOGE("InnerReportDailyEvent: eventFactory_ or dbHelper is nullptr");
        return;
    }
 
    uint64_t today0Time = GetToday0ClockMs();
    uint64_t firstReportDayStart = 0;
 
    if (lastReportTime_ == 0) {
        int64_t earliestTime = eventFactory_->GetDbHelper()->QueryEarliestEventTime();
        if (earliestTime <= 0) {
            IMSA_HILOGI("InnerReportDailyEvent: no data in DB, nothing to report");
            lastReportTime_ = GetNowMs();
            nextReportTime_ = GetNextReportTimeMs();
            PersistLastReportTime();
            return;
        }
        firstReportDayStart = DayStartFromMs(static_cast<uint64_t>(earliestTime));
    } else {
        firstReportDayStart = DayStartFromMs(lastReportTime_);
    }
 
    // ReportCatchupDays already limits to MAX_CATCHUP_DAYS (7) to bound runtime.
    // Data cleanup (ReportAndCleanupOldData) is handled separately below.
    // If firstReportDayStart points to data that has already been cleaned,
    // the query simply returns 0 rows, which is harmless.
    // Do NOT cap firstReportDayStart here — capping with DATA_KEEP_DAY
    // would skip days that still have data (e.g., clock-adjusted scenario
    // where lastReportTime_ is 4 days old but data has not been cleaned yet).
 
    uint32_t daysReported = ReportCatchupDays(firstReportDayStart, today0Time);
 
    // Clean up old data: for each day about to expire, report first then delete.
    uint64_t clearDataTime = (today0Time > MILLISECS_PER_DAY * DATA_KEEP_DAY)
                                 ? (today0Time - MILLISECS_PER_DAY * DATA_KEEP_DAY)
                                 : 0;
    if (clearDataTime > 0 && firstReportDayStart > 0 && clearDataTime > firstReportDayStart) {
        ReportAndCleanupOldData(clearDataTime, firstReportDayStart);
    }
 
    lastReportTime_ = GetNowMs();
    nextReportTime_ = GetNextReportTimeMs();
    PersistLastReportTime();
 
    IMSA_HILOGI("Daily report completed, catchupDays=%{public}u, "
        "lastReportTime=%{public}llu, nextReportTime=%{public}llu",
        daysReported, static_cast<unsigned long long>(lastReportTime_),
        static_cast<unsigned long long>(nextReportTime_));
}
 
uint32_t ImeUsageReporter::ReportCatchupDays(uint64_t firstReportDayStart, uint64_t today0Time)
{
    if (eventFactory_ == nullptr || eventFactory_->GetDbHelper() == nullptr) {
        return 0;
    }
    // Only iterate days that actually have data in DB, instead of every calendar
    // day in the range. This avoids O(N) empty queries when the device was off
    // for months — typically only a handful of days have data.
    auto activeDays = eventFactory_->GetDbHelper()->QueryActiveDays(
        firstReportDayStart, today0Time - 1);
 
    uint32_t daysReported = 0;
    constexpr uint64_t REPORT_BUDGET_MS = 5000;
    auto reportStart = std::chrono::steady_clock::now();
 
    for (uint64_t dayStart : activeDays) {
        // Ensure dayStart is within the reporting range
        if (dayStart < firstReportDayStart || dayStart >= today0Time) {
            continue;
        }
        uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;
        std::string dateStr = FormatDateStr(dayStart);
        ReportSingleDay(dayStart, dayEnd, dateStr);
        daysReported++;
 
        auto elapsed = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - reportStart).count());
        if (elapsed >= REPORT_BUDGET_MS) {
            IMSA_HILOGW("ReportCatchupDays: budget exceeded after %{public}u days", daysReported);
            break;
        }
    }
    return daysReported;
}
 
bool ImeUsageReporter::ReportSingleDay(uint64_t dayStartTime, uint64_t dayEndTime, const std::string &dateStr)
{
    if (eventFactory_ == nullptr) {
        return false;
    }
 
    IMSA_HILOGI("ReportSingleDay: date=%{public}s, dayStart=%{public}llu, dayEnd=%{public}llu",
        dateStr.c_str(), static_cast<unsigned long long>(dayStartTime),
        static_cast<unsigned long long>(dayEndTime));
 
    std::vector<ImeUsageInfo> infos;
    eventFactory_->Create(infos, dayStartTime, dayEndTime);
 
    IMSA_HILOGD("ReportSingleDay: date=%{public}s, aggregation produced %{public}zu IME entries",
        dateStr.c_str(), infos.size());
 
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
    IMSA_HILOGI("Reporting IME: pkg=%{public}s, usage=%{public}llu, showCount=%{public}u, "
        "foldV=%{public}u, foldH=%{public}u, expdV=%{public}u, expdH=%{public}u, "
        "gV=%{public}u, gH=%{public}u, unfoldV=%{public}u, unfoldH=%{public}u, "
        "nV=%{public}u, nH=%{public}u, lmV=%{public}u, lmH=%{public}u",
        info.package.c_str(), static_cast<unsigned long long>(info.usage), info.showCount,
        info.foldPortraitDuration, info.foldLandscapeDuration,
        info.expandPortraitDuration, info.expandLandscapeDuration,
        info.gPortraitDuration, info.gLandscapeDuration,
        info.unFoldedPortraitDuration, info.unFoldedLandscapeDuration,
        info.nPortraitDuration, info.nLandscapeDuration,
        info.lmPortraitDuration, info.lmLandscapeDuration);
 
    int ret = HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::INPUTMETHOD_UE,
        EVENT_NAME,
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        KEY_OF_PACKAGE, info.package,
        KEY_OF_FOLD_PORTRAIT, info.foldPortraitDuration,
        KEY_OF_FOLD_LANDSCAPE, info.foldLandscapeDuration,
        KEY_OF_EXPAND_PORTRAIT, info.expandPortraitDuration,
        KEY_OF_EXPAND_LANDSCAPE, info.expandLandscapeDuration,
        KEY_OF_G_PORTRAIT, info.gPortraitDuration,
        KEY_OF_G_LANDSCAPE, info.gLandscapeDuration,
        KEY_OF_UNFOLDED_PORTRAIT, info.unFoldedPortraitDuration,
        KEY_OF_UNFOLDED_LANDSCAPE, info.unFoldedLandscapeDuration,
        KEY_OF_N_PORTRAIT, info.nPortraitDuration,
        KEY_OF_N_LANDSCAPE, info.nLandscapeDuration,
        KEY_OF_LM_PORTRAIT, info.lmPortraitDuration,
        KEY_OF_LM_LANDSCAPE, info.lmLandscapeDuration,
        KEY_OF_USAGE, info.usage,
        KEY_OF_DATE, dateStr,
        KEY_OF_SHOW_COUNT, info.showCount);
 
    if (ret != 0) {
        IMSA_HILOGE("HiSysEventWrite failed for %{public}s date=%{public}s, ret=%{public}d",
            info.package.c_str(), dateStr.c_str(), ret);
        return false;
    }
    IMSA_HILOGI("HiSysEventWrite success for %{public}s date=%{public}s",
        info.package.c_str(), dateStr.c_str());
    return true;
}
 
void ImeUsageReporter::ReportAndCleanupOldData(uint64_t clearDataTime, uint64_t alreadyReportedDay0)
{
    if (eventFactory_ == nullptr || eventFactory_->GetDbHelper() == nullptr) {
        return;
    }
 
    // Query the earliest event time from DB to know the actual data range
    int64_t earliestTime = eventFactory_->GetDbHelper()->QueryEarliestEventTime();
    if (earliestTime <= 0) {
        IMSA_HILOGI("ReportAndCleanupOldData: no data in DB, skip cleanup");
        return;
    }
 
    // Report each day from the earliest data day up to the day before
    // alreadyReportedDay0 (days from alreadyReportedDay0 onwards were covered
    // by the main loop). Only go up to clearDataTime for actual deletion.
    uint64_t scanStart = DayStartFromMs(static_cast<uint64_t>(earliestTime));
    uint64_t reportEnd = std::min(clearDataTime, alreadyReportedDay0);
 
    IMSA_HILOGI("ReportAndCleanupOldData: clearDataTime=%{public}llu, scanStart=%{public}llu, "
        "alreadyReportedDay0=%{public}llu, reportEnd=%{public}llu",
        static_cast<unsigned long long>(clearDataTime), static_cast<unsigned long long>(scanStart),
        static_cast<unsigned long long>(alreadyReportedDay0), static_cast<unsigned long long>(reportEnd));
 
    // Report each day that is about to be deleted and not already reported
    uint64_t dayStart = scanStart;
    bool allReported = true;
    while (dayStart < reportEnd) {
        uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;
 
        std::string dateStr = FormatDateStr(dayStart);
 
        if (!ReportSingleDay(dayStart, dayEnd, dateStr)) {
            allReported = false;
        }
        dayStart += MILLISECS_PER_DAY;
    }
 
    // Only delete if all reports succeeded; otherwise keep data for next attempt
    if (allReported) {
        eventFactory_->CleanupOldData(clearDataTime);
        IMSA_HILOGI("ReportAndCleanupOldData: completed, cleaned data before %{public}llu",
            static_cast<unsigned long long>(clearDataTime));
    } else {
        IMSA_HILOGW("ReportAndCleanupOldData: some reports failed, keeping data for retry");
    }
}
 
uint64_t ImeUsageReporter::GetToday0ClockMs() const
{
    return OHOS::MiscServices::GetToday0ClockMs();
}
 
uint64_t ImeUsageReporter::GetNowMs() const
{
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
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
    IMSA_HILOGI("OnBootCompleted: start recovery");
    if (eventCacher_ != nullptr) {
        eventCacher_->RecoverActiveSession();
    }
    // Load lastReportTime from DB outside the lock (DB I/O should not hold mutex)
    uint64_t loadedTime = LoadLastReportTime();
    std::lock_guard<std::mutex> lock(reportMutex_);
    lastReportTime_ = loadedTime;
    // Check if we need to report unreported periods
    uint64_t currentPeriodStart = GetCurrentPeriodStartMs();
    if (lastReportTime_ < currentPeriodStart) {
        shouldReportLastData_ = true;
    }
    IMSA_HILOGI("OnBootCompleted: shouldReportLastData=%{public}d, "
        "lastReportTime=%{public}llu, currentPeriodStart=%{public}llu",
        shouldReportLastData_.load(),
        static_cast<unsigned long long>(lastReportTime_),
        static_cast<unsigned long long>(currentPeriodStart));
}
 
void ImeUsageReporter::PersistLastReportTime()
{
    if (eventFactory_ == nullptr || eventFactory_->GetDbHelper() == nullptr) {
        IMSA_HILOGE("PersistLastReportTime: dbHelper is nullptr");
        return;
    }
    std::string value = std::to_string(static_cast<unsigned long long>(lastReportTime_));
    int ret = eventFactory_->GetDbHelper()->SaveReportState(STATE_KEY_LAST_REPORT_TIME, value);
    if (ret != 0) {
        IMSA_HILOGE("PersistLastReportTime failed, ret=%{public}d", ret);
    }
}
 
uint64_t ImeUsageReporter::LoadLastReportTime()
{
    if (eventFactory_ == nullptr || eventFactory_->GetDbHelper() == nullptr) {
        IMSA_HILOGE("LoadLastReportTime: dbHelper is nullptr");
        return 0;
    }
    std::string value;
    int ret = eventFactory_->GetDbHelper()->LoadReportState(STATE_KEY_LAST_REPORT_TIME, value);
    if (ret != 0 || value.empty()) {
        IMSA_HILOGI("LoadLastReportTime: not found or failed, defaulting to 0");
        return 0;
    }
    uint64_t time = 0;
    char *endPtr = nullptr;
    errno = 0;
    time = strtoull(value.c_str(), &endPtr, 10);
    if (endPtr == value.c_str() || errno != 0) {
        IMSA_HILOGE("LoadLastReportTime: invalid value=%{public}s", value.c_str());
        return 0;
    }
    IMSA_HILOGI("LoadLastReportTime: loaded %{public}llu", static_cast<unsigned long long>(time));
    return time;
}
 
uint64_t ImeUsageReporter::DayStartFromMs(uint64_t ms) const
{
    return OHOS::MiscServices::DayStartFromMs(ms);
}
 
uint64_t ImeUsageReporter::GetCurrentPeriodStartMs() const
{
    return GetToday0ClockMs();
}
 
uint64_t ImeUsageReporter::GetNextReportTimeMs() const
{
    uint64_t today0 = GetToday0ClockMs();
    if (today0 == 0) {
        return GetNowMs() + MILLISECS_PER_DAY;
    }
    // Next midnight = today's 0:00 + 1 day
    return today0 + MILLISECS_PER_DAY;
}
} // namespace MiscServices
} // namespace OHOS