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
    IMSA_HILOGI("ImeUsageEventCacher::Init success, fold=%{public}d, vh=%{public}d, screenStatus=%{public}d",
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
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
}
 
uint64_t ImeUsageEventCacher::GetToday0ClockMs() const
{
    return OHOS::MiscServices::GetToday0ClockMs();
}
 
int32_t ImeUsageEventCacher::GetScreenStatus() const
{
    // Encoding: foldStatus * 10 + vhMode
    int32_t status = foldStatus_ * 10 + vhMode_;
    // Fallback: if uninitialized (both 0), treat as UNFOLDED_PORTRAIT
    if (status == 0) {
        IMSA_HILOGW("GetScreenStatus: foldStatus=0, vhMode=0, fallback to UNFOLDED_PORTRAIT(12)");
        return ImeScreenStatus::UNFOLDED_PORTRAIT;
    }
    return status;
}
 
void ImeUsageEventCacher::OnImeBind(const std::string &bundleName)
{
    ImeEventRecord hideRecord;
    ImeEventRecord showRecord;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        hideRecord = PrepareShowEvent(bundleName, showRecord);
    }
    // DB writes outside the lock to avoid holding mutex_ during I/O
    if (hideRecord.rawid != 0) {
        dbHelper_->AddEvent(hideRecord);
        CountDuration(hideRecord);
    }
    if (showRecord.rawid != 0) {
        dbHelper_->AddEvent(showRecord);
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
    // STOP and COUNT_DURATION are written sequentially on the same thread,
    // so no interleaving with other events is possible. If the process
    // crashes between the two AddEvent calls, COUNT_DURATION is lost but
    // the daily settlement can rebuild duration from the raw START/STOP
    // events in DB. This is an accepted tradeoff: wrapping both writes in
    // a single DB transaction would guarantee atomicity but increase lock
    // hold time and complexity; the daily recovery path makes the loss
    // self-healing.
    if (record.rawid != 0) {
        dbHelper_->AddEvent(record);
        CountDuration(record);
    }
}
 
void ImeUsageEventCacher::OnScreenStatusChanged(int32_t preScreenStatus, int32_t newScreenStatus)
{
    ImeEventRecord statusRecord;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Update internal state from the callback's authoritative values
        // (FoldStatusAdapter has already computed the correct old/new screen status)
        foldStatus_ = newScreenStatus / 10;
        vhMode_ = newScreenStatus % 10;
        statusRecord = ProcessScreenChangedEvent(preScreenStatus, newScreenStatus);
    }
    // DB write outside the lock to avoid holding mutex_ during I/O
    if (statusRecord.rawid != 0) {
        dbHelper_->AddEvent(statusRecord);
    }
}
 
ImeEventRecord ImeUsageEventCacher::PrepareShowEvent(const std::string &bundleName, ImeEventRecord &showRecord)
{
    if (dbHelper_ == nullptr) {
        IMSA_HILOGE("dbHelper_ is nullptr");
        return {};
    }
    // Same IME already showing: skip duplicate show (caused by screen rotation/fold
    // triggering panel re-show).
    if (isKeyboardShowing_ && currentImeBundle_ == bundleName) {
        IMSA_HILOGI("PrepareShowEvent: same IME already showing, skip for %{public}s",
            bundleName.c_str());
        return {};
    }
    // Different IME: close previous session first (state update only, DB outside lock)
    ImeEventRecord hideRecord;
    if (isKeyboardShowing_) {
        IMSA_HILOGI("PrepareShowEvent: switching IME from %{public}s to %{public}s",
            currentImeBundle_.c_str(), bundleName.c_str());
        hideRecord = PrepareHideRecord(currentImeBundle_);
    }
 
    showRecord.rawid = EVENT_INPUT_START;
    showRecord.ts = static_cast<int64_t>(GetBootTimeMs());
    showRecord.happenTime = static_cast<int64_t>(GetWallClockMs());
    showRecord.bundleName = bundleName;
    showRecord.preScreenStatus = GetScreenStatus();
    showRecord.screenStatus = GetScreenStatus();
 
    currentImeBundle_ = bundleName;
    isKeyboardShowing_ = true;
    lastScreenStatus_ = showRecord.screenStatus;
 
    IMSA_HILOGI("EVENT_INPUT_START: bundle=%{public}s, "
        "screenStatus=%{public}d, ts=%{public}lld, happenTime=%{public}lld",
        bundleName.c_str(), showRecord.screenStatus,
        static_cast<long long>(showRecord.ts), static_cast<long long>(showRecord.happenTime));
 
    return hideRecord;
}
 
ImeEventRecord ImeUsageEventCacher::PrepareHideRecord(const std::string &bundleName)
{
    if (dbHelper_ == nullptr || !isKeyboardShowing_) {
        IMSA_HILOGI("PrepareHideRecord: skip, dbHelper=%{public}p, isShowing=%{public}d",
            dbHelper_.get(), isKeyboardShowing_);
        return {};
    }
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = static_cast<int64_t>(GetBootTimeMs());
    record.happenTime = static_cast<int64_t>(GetWallClockMs());
    record.bundleName = bundleName;
    record.preScreenStatus = GetScreenStatus();
    record.screenStatus = GetScreenStatus();
 
    IMSA_HILOGI("EVENT_INPUT_STOP: bundle=%{public}s, screenStatus=%{public}d, "
        "ts=%{public}lld, happenTime=%{public}lld",
        bundleName.c_str(), record.screenStatus,
        static_cast<long long>(record.ts), static_cast<long long>(record.happenTime));
 
    isKeyboardShowing_ = false;
    currentImeBundle_.clear();
    return record;
}
 
ImeEventRecord ImeUsageEventCacher::ProcessScreenChangedEvent(int32_t preScreenStatus, int32_t newScreenStatus)
{
    if (dbHelper_ == nullptr || !isKeyboardShowing_) {
        IMSA_HILOGD("ProcessScreenChangedEvent: skip, dbHelper=%{public}p, isShowing=%{public}d",
            dbHelper_.get(), isKeyboardShowing_);
        return {};
    }
    // Deduplicate: skip if new status is same as last recorded status
    if (newScreenStatus == lastScreenStatus_) {
        IMSA_HILOGD("ProcessScreenChangedEvent: skip duplicate, screenStatus=%{public}d unchanged",
            newScreenStatus);
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
 
    IMSA_HILOGI("EVENT_INPUT_STATUS_CHANGED: bundle=%{public}s, pre=%{public}d, new=%{public}d, "
        "ts=%{public}lld, happenTime=%{public}lld",
        currentImeBundle_.c_str(), record.preScreenStatus, record.screenStatus,
        static_cast<long long>(record.ts), static_cast<long long>(record.happenTime));
 
    return record;
}
 
void ImeUsageEventCacher::CountDuration(ImeEventRecord &record)
{
    if (dbHelper_ == nullptr) {
        return;
    }
    int32_t startIndex = GetStartIndex(record.bundleName);
    if (startIndex < 0) {
        IMSA_HILOGI("CountDuration: No START event found for %{public}s", record.bundleName.c_str());
        return;
    }
    uint64_t dayStartTime = GetToday0ClockMs();
    std::vector<ImeEventRecord> records;
    dbHelper_->QueryEventRecords(startIndex, static_cast<int64_t>(dayStartTime), record.bundleName, records);
 
    // Append the current STOP event to the records for duration calculation.
    // ProcessHideEvent calls CountDuration before writing the STOP event to DB,
    // so we must include it here to form a complete START...STOP pair.
    records.push_back(record);
 
    IMSA_HILOGD("CountDuration: bundle=%{public}s, startIndex=%{public}d, "
        "dayStartTime=%{public}llu, records=%{public}zu",
        record.bundleName.c_str(), startIndex,
        static_cast<unsigned long long>(dayStartTime), records.size());
 
    DurationMap durations;
    CalculateDuration(dayStartTime, records, durations);
 
    // Log each duration entry
    for (const auto &[status, duration] : durations) {
        IMSA_HILOGD("CountDuration: screenStatus=%{public}d, duration=%{public}llu ms",
            status, static_cast<unsigned long long>(duration));
    }
 
    ProcessCountDurationEvent(record, durations);
}
 
int ImeUsageEventCacher::GetStartIndex(const std::string &bundleName)
{
    if (dbHelper_ == nullptr) {
        return -1;
    }
    return dbHelper_->QueryRawEventIndex(bundleName, EVENT_INPUT_START);
}
 
void ImeUsageEventCacher::CalculateDuration(uint64_t dayStartTime, std::vector<ImeEventRecord> &records,
    DurationMap &durations)
{
    if (records.empty()) {
        IMSA_HILOGD("CalculateDuration: no records to calculate");
        return;
    }
 
    IMSA_HILOGD("CalculateDuration: processing %{public}zu records, dayStartTime=%{public}llu",
        records.size(), static_cast<unsigned long long>(dayStartTime));
 
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
            uint64_t duration = (it->ts > static_cast<uint64_t>(preIt->ts))
                                   ? static_cast<uint64_t>(it->ts - preIt->ts)
                                   : 0;
            // Fallback: screenStatus=0 means uninitialized; treat as UNFOLDED_PORTRAIT(12)
            int32_t status = preIt->screenStatus;
            if (status == 0) {
                IMSA_HILOGW("CalculateDuration: pair status=0, fallback to UNFOLDED_PORTRAIT(12)");
                status = ImeScreenStatus::UNFOLDED_PORTRAIT;
            }
            IMSA_HILOGD("CalculateDuration: pair rawId=%{public}d->%{public}d, "
                "status=%{public}d, duration=%{public}llu ms",
                preIt->rawid, it->rawid, status,
                static_cast<unsigned long long>(duration));
            Accumulate(status, duration, durations);
        } else {
            IMSA_HILOGD("CalculateDuration: skip pair rawId=%{public}d->%{public}d (cannot calc)",
                preIt->rawid, it->rawid);
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
    if (durations.find(screenStatus) != durations.end()) {
        durations[screenStatus] += duration;
    } else {
        durations[screenStatus] = duration;
    }
}
 
void ImeUsageEventCacher::ProcessCountDurationEvent(ImeEventRecord &record, const DurationMap &durations)
{
    if (dbHelper_ == nullptr) {
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
 
    IMSA_HILOGI("EVENT_COUNT_DURATION: bundle=%{public}s, durationCount=%{public}zu",
        record.bundleName.c_str(), durations.size());
}
 
void ImeUsageEventCacher::RecoverActiveSession()
{
    // On service restart, we check if there was an active session.
    // The DB records will still be there; the daily settlement will
    // recover the foreground IME duration at day boundary.
    // We just need to reset our in-memory state.
    isKeyboardShowing_ = false;
    currentImeBundle_.clear();
    IMSA_HILOGI("RecoverActiveSession: in-memory state reset");
}
} // namespace MiscServices
} // namespace OHOS