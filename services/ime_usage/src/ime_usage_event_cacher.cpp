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

#include "ime_usage_event_cacher.h"

#include <chrono>
#include <ctime>
#include <sys/time.h>

#include "global.h"

using namespace OHOS::MiscServices::ImeUsageEventId;
using namespace OHOS::MiscServices::ImeScreenStatus;
using namespace OHOS::MiscServices::ImeFoldStatusBase;

namespace OHOS {
namespace MiscServices {

int ImeUsageEventCacher::Init(std::shared_ptr<ImeUsageDbHelper> dbHelper, int32_t foldStatus, int32_t vhMode)
{
    if (dbHelper == nullptr) {
        IMSA_HILOGE("Init: dbHelper is nullptr");
        return -1;
    }
    dbHelper_ = dbHelper;
    foldStatus_ = foldStatus;
    vhMode_ = vhMode;
    lastScreenStatus_ = GetScreenStatus();
    IMSA_HILOGD("ImeUsageEventCacher::Init success, fold=%{public}d, vh=%{public}d, screenStatus=%{public}d",
        foldStatus_, vhMode_, lastScreenStatus_);
    return 0;
}

uint64_t ImeUsageEventCacher::GetBootTimeMs() const
{
    struct timespec ts = { 0, 0 };
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000 + static_cast<uint64_t>(ts.tv_nsec) / 1000000;
}

uint64_t ImeUsageEventCacher::GetWallClockMs() const
{
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
}

int32_t ImeUsageEventCacher::GetScreenStatus() const
{
    int32_t status = EncodeScreenStatus(foldStatus_, vhMode_);
    // Fallback: if uninitialized (both 0), treat as UNFOLDED_PORTRAIT
    if (status == 0) {
        IMSA_HILOGW("GetScreenStatus: foldStatus=0, vhMode=0, fallback to UNFOLDED_PORTRAIT(12)");
        return ImeScreenStatus::UNFOLDED_PORTRAIT;
    }
    return status;
}

void ImeUsageEventCacher::OnImeBind(const std::string &bundleName)
{
    ShowPrepareResult result;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        result = PrepareShowEvent(bundleName);
    }
    // DB writes outside the lock to avoid holding mutex_ during I/O.
    if (result.hideRecord.rawid != 0 && result.showRecord.rawid != 0) {
        // IME switch: split into two independent operations to avoid
        // partial-write inconsistency on transaction failure.
        // Writing old IME's STOP+COUNT and new IME's START in one
        // transaction is risky: if the combined transaction fails and
        // the fallback also partially fails (STOP written but START
        // lost), the old IME's session becomes permanently unclosed.

        // Step 1: Write old IME's STOP + COUNT_DURATION atomically.
        // This must succeed before START to maintain row-ID ordering
        // (QueryFinalEventInfo relies on START having a higher row ID
        // than the preceding STOP).
        DurationMap hideDurations = CalculateDurationForRecord(result.hideRecord);
        ImeEventRecord countRecord;
        countRecord.rawid = EVENT_COUNT_DURATION;
        countRecord.ts = static_cast<int64_t>(GetBootTimeMs());
        countRecord.happenTime = static_cast<int64_t>(GetWallClockMs());
        countRecord.bundleName = result.hideRecord.bundleName;
        countRecord.preScreenStatus = result.hideRecord.preScreenStatus;
        countRecord.screenStatus = result.hideRecord.screenStatus;

        std::vector<std::pair<ImeEventRecord, DurationMap>> hideEvents;
        hideEvents.emplace_back(result.hideRecord, DurationMap {});
        hideEvents.emplace_back(countRecord, hideDurations);

        int hideRet = dbHelper_->AddEventsTransactional(hideEvents);
        if (hideRet != 0) {
            IMSA_HILOGE("OnImeBind: STOP+COUNT transaction failed, falling back to separate writes");
            dbHelper_->AddEvent(result.hideRecord);
            dbHelper_->AddEvent(countRecord, hideDurations);
        }

        // Step 2: Write new IME's START. Single-row insert is inherently
        // atomic. If this fails, the in-memory state (isKeyboardShowing_=true,
        // currentImeBundle_) remains correct; daily aggregation's foreground-
        // recovery channel will compensate for the missing START.
        int showRet = dbHelper_->AddEvent(result.showRecord);
        if (showRet != 0) {
            IMSA_HILOGE("OnImeBind: START AddEvent failed for %{public}s", result.showRecord.bundleName.c_str());
        }
    } else if (result.hideRecord.rawid != 0) {
        // Only hide (no show): use transactional write for STOP + COUNT_DURATION
        DurationMap hideDurations = CalculateDurationForRecord(result.hideRecord);
        ImeEventRecord countRecord;
        countRecord.rawid = EVENT_COUNT_DURATION;
        countRecord.ts = static_cast<int64_t>(GetBootTimeMs());
        countRecord.happenTime = static_cast<int64_t>(GetWallClockMs());
        countRecord.bundleName = result.hideRecord.bundleName;
        countRecord.preScreenStatus = result.hideRecord.preScreenStatus;
        countRecord.screenStatus = result.hideRecord.screenStatus;

        std::vector<std::pair<ImeEventRecord, DurationMap>> hideEvents;
        hideEvents.emplace_back(result.hideRecord, DurationMap {});
        hideEvents.emplace_back(countRecord, hideDurations);

        int hideRet = dbHelper_->AddEventsTransactional(hideEvents);
        if (hideRet != 0) {
            IMSA_HILOGE("OnImeBind: STOP+COUNT transaction failed, falling back to separate writes");
            dbHelper_->AddEvent(result.hideRecord);
            dbHelper_->AddEvent(countRecord, hideDurations);
        }
    } else if (result.showRecord.rawid != 0) {
        dbHelper_->AddEvent(result.showRecord);
    }
}

void ImeUsageEventCacher::OnImeUnbind(const std::string &bundleName)
{
    ImeEventRecord record;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        record = PrepareHideRecord(bundleName);
    }
    // DB writes outside the lock to avoid holding mutex_ during I/O.
    // Write STOP and COUNT_DURATION atomically in a single transaction
    // to guarantee no data loss on process crash.
    if (record.rawid != 0) {
        DurationMap durations = CalculateDurationForRecord(record);

        ImeEventRecord countRecord;
        countRecord.rawid = EVENT_COUNT_DURATION;
        countRecord.ts = static_cast<int64_t>(GetBootTimeMs());
        countRecord.happenTime = static_cast<int64_t>(GetWallClockMs());
        countRecord.bundleName = record.bundleName;
        countRecord.preScreenStatus = record.preScreenStatus;
        countRecord.screenStatus = record.screenStatus;

        std::vector<std::pair<ImeEventRecord, DurationMap>> events;
        events.emplace_back(record, DurationMap {});
        events.emplace_back(countRecord, durations);

        int ret = dbHelper_->AddEventsTransactional(events);
        if (ret != 0) {
            IMSA_HILOGE("OnImeUnbind: AddEventsTransactional failed, falling back to separate writes");
            dbHelper_->AddEvent(record);
            dbHelper_->AddEvent(countRecord, durations);
        }
    }
}

void ImeUsageEventCacher::OnScreenStatusChanged(int32_t preScreenStatus, int32_t newScreenStatus)
{
    ImeEventRecord statusRecord;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Update internal state from the callback's authoritative values
        // (FoldStatusAdapter has already computed the correct old/new screen status)
        DecodeScreenStatus(newScreenStatus, foldStatus_, vhMode_);
        statusRecord = ProcessScreenChangedEvent(preScreenStatus, newScreenStatus);
    }
    // DB write outside the lock to avoid holding mutex_ during I/O
    if (statusRecord.rawid != 0) {
        dbHelper_->AddEvent(statusRecord);
    }
}

ImeUsageEventCacher::ShowPrepareResult ImeUsageEventCacher::PrepareShowEvent(const std::string &bundleName)
{
    ShowPrepareResult result;
    if (dbHelper_ == nullptr) {
        IMSA_HILOGE("dbHelper_ is nullptr");
        return result;
    }
    // Same IME already showing: skip duplicate show (caused by screen rotation/fold
    // triggering panel re-show).
    if (isKeyboardShowing_ && currentImeBundle_ == bundleName) {
        IMSA_HILOGD("PrepareShowEvent: same IME already showing, skip for %{public}s", bundleName.c_str());
        return result;
    }
    // Different IME: close previous session first (state update only, DB outside lock)
    if (isKeyboardShowing_) {
        IMSA_HILOGD("PrepareShowEvent: switching IME from %{public}s to %{public}s", currentImeBundle_.c_str(),
            bundleName.c_str());
        result.hideRecord = PrepareHideRecord(currentImeBundle_);
    }

    result.showRecord.rawid = EVENT_INPUT_START;
    result.showRecord.ts = static_cast<int64_t>(GetBootTimeMs());
    result.showRecord.happenTime = static_cast<int64_t>(GetWallClockMs());
    result.showRecord.bundleName = bundleName;
    result.showRecord.preScreenStatus = GetScreenStatus();
    result.showRecord.screenStatus = GetScreenStatus();

    currentImeBundle_ = bundleName;
    isKeyboardShowing_ = true;
    lastScreenStatus_ = result.showRecord.screenStatus;

    IMSA_HILOGD("EVENT_INPUT_START: bundle=%{public}s, "
                "screenStatus=%{public}d, ts=%{public}lld, happenTime=%{public}lld",
        bundleName.c_str(), result.showRecord.screenStatus, static_cast<long long>(result.showRecord.ts),
        static_cast<long long>(result.showRecord.happenTime));

    return result;
}

ImeEventRecord ImeUsageEventCacher::PrepareHideRecord(const std::string &bundleName)
{
    if (dbHelper_ == nullptr || !isKeyboardShowing_) {
        IMSA_HILOGD(
            "PrepareHideRecord: skip, dbHelper=%{public}p, isShowing=%{public}d", dbHelper_.get(), isKeyboardShowing_);
        return {};
    }
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = static_cast<int64_t>(GetBootTimeMs());
    record.happenTime = static_cast<int64_t>(GetWallClockMs());
    record.bundleName = bundleName;
    record.preScreenStatus = GetScreenStatus();
    record.screenStatus = GetScreenStatus();

    IMSA_HILOGD("EVENT_INPUT_STOP: bundle=%{public}s, screenStatus=%{public}d, "
                "ts=%{public}lld, happenTime=%{public}lld",
        bundleName.c_str(), record.screenStatus, static_cast<long long>(record.ts),
        static_cast<long long>(record.happenTime));

    isKeyboardShowing_ = false;
    currentImeBundle_.clear();
    return record;
}

ImeEventRecord ImeUsageEventCacher::ProcessScreenChangedEvent(int32_t preScreenStatus, int32_t newScreenStatus)
{
    if (dbHelper_ == nullptr || !isKeyboardShowing_) {
        IMSA_HILOGD("ProcessScreenChangedEvent: skip, dbHelper=%{public}p, isShowing=%{public}d", dbHelper_.get(),
            isKeyboardShowing_);
        return {};
    }
    // Deduplicate: skip if new status is same as last recorded status
    if (newScreenStatus == lastScreenStatus_) {
        IMSA_HILOGD("ProcessScreenChangedEvent: skip duplicate, screenStatus=%{public}d unchanged", newScreenStatus);
        return {};
    }
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STATUS_CHANGED;
    record.ts = static_cast<int64_t>(GetBootTimeMs());
    record.happenTime = static_cast<int64_t>(GetWallClockMs());
    record.bundleName = currentImeBundle_;
    record.preScreenStatus = preScreenStatus;
    record.screenStatus = newScreenStatus;

    lastScreenStatus_ = newScreenStatus;

    IMSA_HILOGD("EVENT_INPUT_STATUS_CHANGED: bundle=%{public}s, pre=%{public}d, new=%{public}d, "
                "ts=%{public}lld, happenTime=%{public}lld",
        currentImeBundle_.c_str(), record.preScreenStatus, record.screenStatus, static_cast<long long>(record.ts),
        static_cast<long long>(record.happenTime));

    return record;
}

void ImeUsageEventCacher::CountDuration(ImeEventRecord &record)
{
    if (dbHelper_ == nullptr) {
        return;
    }
    DurationMap durations = CalculateDurationForRecord(record);
    ProcessCountDurationEvent(record, durations);
}

DurationMap ImeUsageEventCacher::CalculateDurationForRecord(const ImeEventRecord &record)
{
    DurationMap durations;
    if (dbHelper_ == nullptr) {
        return durations;
    }
    int32_t startIndex = GetStartIndex(record.bundleName);
    if (startIndex < 0) {
        IMSA_HILOGD("CalculateDurationForRecord: No START event found for %{public}s", record.bundleName.c_str());
        return durations;
    }
    uint64_t dayStartTime = OHOS::MiscServices::GetToday0ClockMs();
    std::vector<ImeEventRecord> records;
    dbHelper_->QueryEventRecords(startIndex, static_cast<int64_t>(dayStartTime), record.bundleName, records);

    // Append the current STOP event to the records for duration calculation.
    records.push_back(record);

    IMSA_HILOGD("CalculateDurationForRecord: bundle=%{public}s, startIndex=%{public}d, "
                "dayStartTime=%{public}llu, records=%{public}zu",
        record.bundleName.c_str(), startIndex, static_cast<unsigned long long>(dayStartTime), records.size());

    CalculateDuration(dayStartTime, records, durations);

    // Log each duration entry
    for (const auto &[status, duration] : durations) {
        IMSA_HILOGD("CalculateDurationForRecord: screenStatus=%{public}d, duration=%{public}llu ms", status,
            static_cast<unsigned long long>(duration));
    }

    return durations;
}

int ImeUsageEventCacher::GetStartIndex(const std::string &bundleName)
{
    if (dbHelper_ == nullptr) {
        return -1;
    }
    return dbHelper_->QueryRawEventIndex(bundleName, EVENT_INPUT_START);
}

void ImeUsageEventCacher::CalculateDuration(
    uint64_t dayStartTime, std::vector<ImeEventRecord> &records, DurationMap &durations)
{
    if (records.empty()) {
        IMSA_HILOGD("CalculateDuration: no records to calculate");
        return;
    }

    IMSA_HILOGD("CalculateDuration: processing %{public}zu records, dayStartTime=%{public}llu", records.size(),
        static_cast<unsigned long long>(dayStartTime));

    auto it = records.begin();

    // Handle cross-midnight: if first event is not START, duration from dayStartTime to first event
    if (it->rawid != EVENT_INPUT_START) {
        int32_t status = (it->rawid == EVENT_INPUT_STOP) ? it->screenStatus : it->preScreenStatus;
        // Fallback: screenStatus=0 means uninitialized; treat as UNFOLDED_PORTRAIT(12)
        if (status == 0) {
            IMSA_HILOGW("CalculateDuration: cross-midnight status=0, fallback to UNFOLDED_PORTRAIT(12)");
            status = ImeScreenStatus::UNFOLDED_PORTRAIT;
        }
        uint64_t duration = static_cast<uint64_t>(it->happenTime) - dayStartTime;
        IMSA_HILOGD("CalculateDuration: cross-midnight, first event rawId=%{public}d, "
                    "status=%{public}d, duration=%{public}llu ms",
            it->rawid, status, static_cast<unsigned long long>(duration));
        Accumulate(status, duration, durations);
    }

    auto preIt = it;
    ++it;

    for (; it != records.end(); ++it) {
        if (CanCalcDuration(preIt->rawid, it->rawid)) {
            // Use boot time (ts) for inter-event duration — monotonic, immune to
            // wall-clock adjustments (NTP, manual time change).
            uint64_t duration =
                (it->ts > static_cast<uint64_t>(preIt->ts)) ? static_cast<uint64_t>(it->ts - preIt->ts) : 0;
            // Fallback: screenStatus=0 means uninitialized; treat as UNFOLDED_PORTRAIT(12)
            int32_t status = preIt->screenStatus;
            if (status == 0) {
                IMSA_HILOGW("CalculateDuration: pair status=0, fallback to UNFOLDED_PORTRAIT(12)");
                status = ImeScreenStatus::UNFOLDED_PORTRAIT;
            }
            IMSA_HILOGD("CalculateDuration: pair rawId=%{public}d->%{public}d, "
                        "status=%{public}d, duration=%{public}llu ms",
                preIt->rawid, it->rawid, status, static_cast<unsigned long long>(duration));
            Accumulate(status, duration, durations);
        } else {
            IMSA_HILOGD(
                "CalculateDuration: skip pair rawId=%{public}d->%{public}d (cannot calc)", preIt->rawid, it->rawid);
        }
        preIt = it;
    }
}

bool ImeUsageEventCacher::CanCalcDuration(int32_t preRawId, int32_t rawId) const
{
    // Duration can be calculated between any pair of events except:
    // - two consecutive STOP events (should not happen)
    // - START followed by START (duplicate)
    if (preRawId == EVENT_INPUT_START && rawId == EVENT_INPUT_START) {
        return false;
    }
    if (preRawId == EVENT_INPUT_STOP && rawId == EVENT_INPUT_STOP) {
        return false;
    }
    return true;
}

void ImeUsageEventCacher::Accumulate(int32_t screenStatus, uint64_t duration, DurationMap &durations) const
{
    durations[screenStatus] += duration;
}

void ImeUsageEventCacher::ProcessCountDurationEvent(ImeEventRecord &record, const DurationMap &durations)
{
    if (dbHelper_ == nullptr) {
        return;
    }
    // Skip writing COUNT_DURATION when there are no durations to report
    // (e.g., no START event found for this bundle). Writing an empty
    // COUNT_DURATION wastes DB space and confuses downstream queries.
    if (durations.empty()) {
        IMSA_HILOGD("ProcessCountDurationEvent: skip, no durations for %{public}s", record.bundleName.c_str());
        return;
    }
    ImeEventRecord countRecord;
    countRecord.rawid = EVENT_COUNT_DURATION;
    countRecord.ts = static_cast<int64_t>(GetBootTimeMs());
    countRecord.happenTime = static_cast<int64_t>(GetWallClockMs());
    countRecord.bundleName = record.bundleName;
    countRecord.preScreenStatus = record.preScreenStatus;
    countRecord.screenStatus = record.screenStatus;

    dbHelper_->AddEvent(countRecord, durations);

    IMSA_HILOGD("EVENT_COUNT_DURATION: bundle=%{public}s, durationCount=%{public}zu", record.bundleName.c_str(),
        durations.size());
}

void ImeUsageEventCacher::RecoverActiveSession()
{
    if (dbHelper_ == nullptr) {
        IMSA_HILOGE("RecoverActiveSession: dbHelper is nullptr");
        return;
    }
    // Query the last event in DB to determine if an IME session was active
    // when the service was restarted.
    ImeUsageRawEvent lastEvent;
    dbHelper_->QueryFinalEventInfo(GetWallClockMs(), lastEvent);

    if (lastEvent.rawId == EVENT_INPUT_START || lastEvent.rawId == EVENT_INPUT_STATUS_CHANGED) {
        isKeyboardShowing_ = true;
        currentImeBundle_ = lastEvent.package;
        DecodeScreenStatus(lastEvent.screenStatusAfter, foldStatus_, vhMode_);
        lastScreenStatus_ = lastEvent.screenStatusAfter;
        IMSA_HILOGD("RecoverActiveSession: recovered active session, "
                    "bundle=%{public}s, screenStatus=%{public}d",
            currentImeBundle_.c_str(), lastScreenStatus_);
    } else {
        isKeyboardShowing_ = false;
        currentImeBundle_.clear();
        IMSA_HILOGD("RecoverActiveSession: no active session (lastRawId=%{public}d)", lastEvent.rawId);
    }
}

} // namespace MiscServices
} // namespace OHOS
