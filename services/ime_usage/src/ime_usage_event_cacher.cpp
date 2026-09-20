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

#include "global.h"

using namespace OHOS::MiscServices::ImeUsageEventId;
using namespace OHOS::MiscServices::ImeScreenStatus;
using namespace OHOS::MiscServices::ImeFoldStatusBase;
using OHOS::MiscServices::IME_INDEX_NOT_FOUND;
using OHOS::MiscServices::IME_USAGE_SUCCESS;
using OHOS::MiscServices::RAWID_NONE;
using OHOS::MiscServices::SCREEN_STATUS_UNINITIALIZED;

namespace OHOS {
namespace MiscServices {

int ImeUsageEventCacher::Init(std::shared_ptr<ImeUsageDataHelper> dataHelper, int32_t foldStatus, int32_t vhMode)
{
    if (dataHelper == nullptr) {
        IMSA_HILOGE("Init: dataHelper is nullptr");
        return IME_USAGE_FAILED;
    }
    dataHelper_ = dataHelper;
    foldStatus_ = foldStatus;
    vhMode_ = vhMode;
    lastScreenStatus_ = GetScreenStatus();
    IMSA_HILOGI("ImeUsageEventCacher::Init success, fold=%{public}d, vh=%{public}d, screenStatus=%{public}d",
        foldStatus_, vhMode_, lastScreenStatus_);
    return IME_USAGE_SUCCESS;
}

uint64_t ImeUsageEventCacher::GetBootTimeMs() const
{
    struct timespec ts = { 0, 0 };
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * MILLISECS_PER_SEC +
        static_cast<uint64_t>(ts.tv_nsec) / NANOSECS_PER_MILLISEC;
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
    if (status == SCREEN_STATUS_UNINITIALIZED) {
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
    // IME switch and only-hide paths share the same STOP+COUNT write logic.
    // The two operations are intentionally split (not merged into one
    // transaction) to avoid partial-write inconsistency: if a combined
    // transaction fails and the fallback also partially fails (STOP written
    // but START lost), the old IME's session becomes permanently unclosed.
    if (result.hideRecord.rawid != RAWID_NONE) {
        // Close previous IME's session: delete raw events (START, STATUS_CHANGED)
        // and insert a single COUNT_DURATION record atomically.
        // hideDurations was computed incrementally in PrepareShowEvent — no DB query needed.
        SettleSession(result.hideRecord, result.hideDurations, result.hideStartIndex);
    }
    if (result.showRecord.rawid != RAWID_NONE) {
        // Write new IME's START. Single-row insert is inherently atomic.
        // If this fails, the in-memory state (isKeyboardShowing_=true,
        // currentImeBundle_) remains correct; daily aggregation's foreground-
        // recovery channel will compensate for the missing START.
        int showRet = dataHelper_->AddEvent(result.showRecord);
        if (showRet != IME_USAGE_SUCCESS) {
            IMSA_HILOGE("OnImeBind: START AddEvent failed for %{public}s", result.showRecord.bundleName.c_str());
        }
    }
}

void ImeUsageEventCacher::OnImeUnbind(const std::string &bundleName)
{
    ImeEventRecord record;
    DurationMap durations {};
    int32_t startIndex = IME_INDEX_NOT_FOUND;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        record = PrepareHideRecord(bundleName);
        if (record.rawid != RAWID_NONE) {
            if (isSessionDurationsReady_) {
                // Incremental durations already accumulated — no DB query needed.
                durations = sessionDurations_;
                startIndex = GetStartIndex(record.bundleName);
            } else {
                // Fallback: session was recovered from DB, durations not tracked.
                // Use the DB-based calculation to compute durations from scratch.
                durations = CalculateDurationForRecord(record, startIndex);
            }
        }
    }
    // DB writes outside the lock to avoid holding mutex_ during I/O.
    if (record.rawid != RAWID_NONE) {
        SettleSession(record, durations, startIndex);
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
    if (statusRecord.rawid != RAWID_NONE) {
        int ret = dataHelper_->AddEvent(statusRecord);
        if (ret != IME_USAGE_SUCCESS) {
            IMSA_HILOGE("OnScreenStatusChanged: AddEvent failed for %{public}s, rawId=%{public}d",
                statusRecord.bundleName.c_str(), statusRecord.rawid);
        }
    }
}

ImeUsageEventCacher::ShowPrepareResult ImeUsageEventCacher::PrepareShowEvent(const std::string &bundleName)
{
    ShowPrepareResult result;
    if (dataHelper_ == nullptr) {
        IMSA_HILOGE("dataHelper_ is nullptr");
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
        // Copy the incrementally accumulated durations for the old session.
        // PrepareHideRecord already finalized the last segment into sessionDurations_.
        if (isSessionDurationsReady_) {
            result.hideDurations = sessionDurations_;
            result.hideStartIndex = GetStartIndex(result.hideRecord.bundleName);
        } else {
            // Fallback: session was recovered from DB, durations not tracked incrementally.
            result.hideDurations = CalculateDurationForRecord(result.hideRecord, result.hideStartIndex);
        }
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

    // Reset incremental duration tracking for the new session.
    sessionDurations_ = {};
    segmentStartBootTime_ = result.showRecord.ts;
    segmentScreenStatus_ = result.showRecord.screenStatus;
    isSessionDurationsReady_ = true;

    IMSA_HILOGD("EVENT_INPUT_START: bundle=%{public}s, "
                "screenStatus=%{public}d, ts=%{public}lld, happenTime=%{public}lld",
        bundleName.c_str(), result.showRecord.screenStatus, static_cast<long long>(result.showRecord.ts),
        static_cast<long long>(result.showRecord.happenTime));

    return result;
}

ImeEventRecord ImeUsageEventCacher::PrepareHideRecord(const std::string &bundleName)
{
    if (dataHelper_ == nullptr || !isKeyboardShowing_) {
        IMSA_HILOGW("PrepareHideRecord: skip, isShowing=%{public}d", isKeyboardShowing_);
        return {};
    }
    uint64_t nowBoot = GetBootTimeMs();
    uint64_t nowWall = GetWallClockMs();

    // Accumulate duration for the final segment before closing the session.
    if (isSessionDurationsReady_ && nowBoot > static_cast<uint64_t>(segmentStartBootTime_)) {
        Accumulate(segmentScreenStatus_, nowBoot - segmentStartBootTime_, sessionDurations_);
    }

    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = static_cast<int64_t>(nowBoot);
    record.happenTime = static_cast<int64_t>(nowWall);
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
    if (dataHelper_ == nullptr || !isKeyboardShowing_) {
        IMSA_HILOGW("ProcessScreenChangedEvent: skip, isShowing=%{public}d", isKeyboardShowing_);
        return {};
    }
    // Deduplicate: skip if new status is same as last recorded status
    if (newScreenStatus == lastScreenStatus_) {
        IMSA_HILOGD("ProcessScreenChangedEvent: skip duplicate, screenStatus=%{public}d unchanged", newScreenStatus);
        return {};
    }
    uint64_t nowBoot = GetBootTimeMs();
    uint64_t nowWall = GetWallClockMs();

    // Accumulate duration for the segment just ended.
    if (isSessionDurationsReady_ && nowBoot > static_cast<uint64_t>(segmentStartBootTime_)) {
        Accumulate(segmentScreenStatus_, nowBoot - segmentStartBootTime_, sessionDurations_);
    }

    // Start a new segment with the new screen status.
    segmentStartBootTime_ = static_cast<int64_t>(nowBoot);
    segmentScreenStatus_ = newScreenStatus;

    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STATUS_CHANGED;
    record.ts = static_cast<int64_t>(nowBoot);
    record.happenTime = static_cast<int64_t>(nowWall);
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

DurationMap ImeUsageEventCacher::CalculateDurationForRecord(const ImeEventRecord &record, int32_t &startIndex)
{
    DurationMap durations;
    startIndex = IME_INDEX_NOT_FOUND;
    if (dataHelper_ == nullptr) {
        return durations;
    }
    startIndex = GetStartIndex(record.bundleName);
    if (startIndex < 0) {
        IMSA_HILOGW("CalculateDurationForRecord: No START event found for %{public}s", record.bundleName.c_str());
        return durations;
    }
    uint64_t dayStartTime = OHOS::MiscServices::GetToday0ClockMs();
    std::vector<ImeEventRecord> records;
    dataHelper_->QueryEventRecords(startIndex, static_cast<int64_t>(dayStartTime), record.bundleName, records);

    // Append the current STOP event to the records for duration calculation.
    records.push_back(record);

    IMSA_HILOGD("CalculateDurationForRecord: bundle=%{public}s, startIndex=%{public}d, "
                "dayStartTime=%{public}llu, records=%{public}zu",
        record.bundleName.c_str(), startIndex, static_cast<unsigned long long>(dayStartTime), records.size());

    CalculateDuration(dayStartTime, records, durations);

    // Log each duration entry
    for (size_t i = 0; i < DURATION_COUNT; i++) {
        if (durations[i] > 0) {
            IMSA_HILOGD("CalculateDurationForRecord: idx=%{public}zu, duration=%{public}llu ms", i,
                static_cast<unsigned long long>(durations[i]));
        }
    }

    return durations;
}

int ImeUsageEventCacher::GetStartIndex(const std::string &bundleName)
{
    if (dataHelper_ == nullptr) {
        return IME_INDEX_NOT_FOUND;
    }
    return dataHelper_->QueryRawEventIndex(bundleName, EVENT_INPUT_START);
}

void ImeUsageEventCacher::CalculateDuration(
    uint64_t dayStartTime, std::vector<ImeEventRecord> &records, DurationMap &durations)
{
    if (records.empty()) {
        IMSA_HILOGW("CalculateDuration: no records to calculate");
        return;
    }

    IMSA_HILOGD("CalculateDuration: processing %{public}zu records, dayStartTime=%{public}llu", records.size(),
        static_cast<unsigned long long>(dayStartTime));
    auto it = records.begin();
    // Handle cross-midnight: if first event is not START, duration from dayStartTime to first event
    if (it->rawid != EVENT_INPUT_START) {
        int32_t status = (it->rawid == EVENT_INPUT_STOP) ? it->screenStatus : it->preScreenStatus;
        // Fallback: screenStatus=0 means uninitialized; treat as UNFOLDED_PORTRAIT(12)
        if (status == SCREEN_STATUS_UNINITIALIZED) {
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
            if (status == SCREEN_STATUS_UNINITIALIZED) {
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
    size_t idx = ScreenStatusToIndex(screenStatus);
    if (idx < DURATION_COUNT) {
        durations[idx] += duration;
    }
}

void ImeUsageEventCacher::SettleSession(
    const ImeEventRecord &stopRecord, const DurationMap &durations, int32_t startIndex)
{
    if (dataHelper_ == nullptr) {
        return;
    }
    ImeEventRecord countRecord;
    countRecord.rawid = EVENT_COUNT_DURATION;
    countRecord.ts = static_cast<int64_t>(GetBootTimeMs());
    countRecord.happenTime = static_cast<int64_t>(GetWallClockMs());
    countRecord.bundleName = stopRecord.bundleName;
    countRecord.preScreenStatus = stopRecord.preScreenStatus;
    countRecord.screenStatus = stopRecord.screenStatus;

    int64_t dayStartTime = static_cast<int64_t>(GetToday0ClockMs());

    if (startIndex >= 0) {
        // Atomic path: delete raw session events and upsert COUNT_DURATION in one transaction.
        // If an existing COUNT_DURATION for the same bundle exists within today,
        // durations are accumulated and show_count is incremented; otherwise a new
        // record with show_count = 1 is inserted.
        int ret = dataHelper_->DeleteAndUpsertTransactional(
            stopRecord.bundleName, startIndex, dayStartTime, countRecord, durations);
        if (ret == IME_USAGE_SUCCESS) {
            return;
        }
        IMSA_HILOGE("SettleSession: DeleteAndUpsertTransactional failed, falling back to separate operations");
        // Fallback: delete raw events then upsert COUNT_DURATION separately.
        dataHelper_->DeleteEventsByBundleAndStartIndex(stopRecord.bundleName, startIndex);
    }

    int ret = dataHelper_->UpsertCountDuration(stopRecord.bundleName, dayStartTime, countRecord, durations);
    if (ret != IME_USAGE_SUCCESS) {
        IMSA_HILOGE("SettleSession: UpsertCountDuration failed for %{public}s", stopRecord.bundleName.c_str());
    }
}

void ImeUsageEventCacher::RecoverActiveSession()
{
    if (dataHelper_ == nullptr) {
        IMSA_HILOGE("RecoverActiveSession: dataHelper is nullptr");
        return;
    }
    // Query the last event in DB to determine if an IME session was active
    // when the service was restarted. DB I/O is performed outside the lock
    // (consistent with OnImeBind/OnImeUnbind pattern); state mutation below
    // takes the lock.
    ImeUsageRawEvent lastEvent;
    dataHelper_->QueryFinalEventInfo(GetWallClockMs(), lastEvent);

    std::lock_guard<std::mutex> lock(mutex_);
    if (lastEvent.rawId == EVENT_INPUT_START || lastEvent.rawId == EVENT_INPUT_STATUS_CHANGED) {
        isKeyboardShowing_ = true;
        currentImeBundle_ = lastEvent.package;
        DecodeScreenStatus(lastEvent.screenStatusAfter, foldStatus_, vhMode_);
        lastScreenStatus_ = lastEvent.screenStatusAfter;
        // Initialize incremental tracking from the recovered event.
        // Durations accumulated before the crash are not available in memory;
        // on the next STOP event, the DB-based CalculateDurationForRecord
        // fallback will be used (isSessionDurationsReady_ = false).
        segmentStartBootTime_ = lastEvent.ts;
        segmentScreenStatus_ = lastEvent.screenStatusAfter;
        sessionDurations_ = {};
        isSessionDurationsReady_ = false;
        IMSA_HILOGD("RecoverActiveSession: recovered active session, "
                    "bundle=%{public}s, screenStatus=%{public}d",
            currentImeBundle_.c_str(), lastScreenStatus_);
    } else {
        isKeyboardShowing_ = false;
        currentImeBundle_.clear();
        sessionDurations_ = {};
        isSessionDurationsReady_ = false;
        IMSA_HILOGD("RecoverActiveSession: no active session (lastRawId=%{public}d)", lastEvent.rawId);
    }
}

} // namespace MiscServices
} // namespace OHOS
