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

#include "ime_usage_data_helper.h"

#include <algorithm>
#include <cinttypes>
#include <cstdlib>
#include <unordered_set>

#include "global.h"

using namespace OHOS::MiscServices::ImeScreenStatus;
using namespace OHOS::MiscServices::ImeUsageEventId;

namespace OHOS {
namespace MiscServices {
namespace {
using OHOS::MiscServices::IME_INDEX_NOT_FOUND;
using OHOS::MiscServices::IME_USAGE_FAILED;
using OHOS::MiscServices::IME_USAGE_SUCCESS;

constexpr int DB_SUCC = IME_USAGE_SUCCESS;
constexpr int DB_FAILED = IME_USAGE_FAILED;
// Threshold for ts vs happenTime divergence check (30 seconds)
constexpr int64_t DIVERGENCE_THRESHOLD_MS = 30000;

struct ForegroundRawEvt {
    int32_t rawId;
    std::string bundle;
    int32_t screenAfter;
    int32_t screenBefore;
    int64_t happenTime;
    int64_t ts;
};

// Collect foreground events from a vector of rows (reverse-ordered, newest first).
// Stops when an EVENT_INPUT_START is encountered.
void CollectForegroundEvents(
    const std::vector<ImeUsageEventRow> &rows, const std::string &targetBundle, std::vector<ForegroundRawEvt> &events)
{
    for (const auto &row : rows) {
        if (row.bundleName != targetBundle) {
            continue;
        }
        ForegroundRawEvt evt;
        evt.rawId = row.rawid;
        evt.bundle = row.bundleName;
        evt.ts = row.ts;
        evt.happenTime = row.happenTime;
        evt.screenAfter = row.screenStatus;
        evt.screenBefore = row.preScreenStatus;

        if (evt.rawId == ImeUsageEventId::EVENT_INPUT_START) {
            events.push_back(evt);
            break;
        }
        if (evt.rawId == ImeUsageEventId::EVENT_INPUT_STATUS_CHANGED) {
            events.push_back(evt);
        }
    }
}

void CalculateForegroundDuration(const std::vector<ForegroundRawEvt> &events, uint64_t startTime, uint64_t endTime,
    int32_t screenStatus, ImeUsageInfo &info)
{
    if (events.empty()) {
        uint32_t duration = static_cast<uint32_t>(endTime - startTime);
        size_t idx = ScreenStatusToIndex(screenStatus);
        if (idx < DURATION_COUNT) {
            info.durations[idx] += duration;
        }
        return;
    }
    auto &oldest = events.back();
    if (oldest.rawId == ImeUsageEventId::EVENT_INPUT_STATUS_CHANGED) {
        uint32_t duration = static_cast<uint32_t>(oldest.happenTime - startTime);
        size_t idx = ScreenStatusToIndex(oldest.screenBefore);
        if (idx < DURATION_COUNT) {
            info.durations[idx] += duration;
        }
    }
    for (int i = static_cast<int>(events.size()) - 1; i > 0; i--) {
        int64_t tsDelta = events[i - 1].ts - events[i].ts;
        int64_t htDelta = events[i - 1].happenTime - events[i].happenTime;
        if (tsDelta > 0 && htDelta > 0 && std::abs(tsDelta - htDelta) > DIVERGENCE_THRESHOLD_MS) {
            IMSA_HILOGW("CalculateForegroundDuration: ts/happenTime divergence at idx=%{public}d, "
                        "tsDelta=%{public}lld, htDelta=%{public}lld",
                i, static_cast<long long>(tsDelta), static_cast<long long>(htDelta));
        }
        uint32_t duration =
            (events[i - 1].ts > events[i].ts) ? static_cast<uint32_t>(events[i - 1].ts - events[i].ts) : 0;
        size_t idx = ScreenStatusToIndex(events[i].screenAfter);
        if (idx < DURATION_COUNT) {
            info.durations[idx] += duration;
        }
    }
    auto &newest = events[0];
    uint32_t duration =
        (static_cast<uint64_t>(newest.happenTime) < endTime) ? static_cast<uint32_t>(endTime - newest.happenTime) : 0;
    size_t idx = ScreenStatusToIndex(newest.screenAfter);
    if (idx < DURATION_COUNT) {
        info.durations[idx] += duration;
    }
}

// Build an ImeUsageEventRow from an ImeEventRecord + DurationMap.
ImeUsageEventRow MakeRow(const ImeEventRecord &record, const DurationMap &durations)
{
    ImeUsageEventRow row;
    row.rawid = record.rawid;
    row.ts = record.ts;
    row.happenTime = record.happenTime;
    row.bundleName = record.bundleName;
    row.preScreenStatus = record.preScreenStatus;
    row.screenStatus = record.screenStatus;
    row.durations = durations;
    row.showCount = record.showCount;
    return row;
}
} // namespace

int64_t ImeUsageDataHelper::FindLastRowLocked(const std::string &bundleName, int32_t rawId) const
{
    for (size_t i = events_.size(); i > 0; i--) {
        const auto &row = events_[i - 1];
        if (row.bundleName == bundleName && row.rawid == rawId) {
            return static_cast<int64_t>(i - 1);
        }
    }
    return -1;
}

int64_t ImeUsageDataHelper::FindLastCountDurationLocked(const std::string &bundleName, int64_t dayStartTime) const
{
    for (size_t i = events_.size(); i > 0; i--) {
        const auto &row = events_[i - 1];
        if (row.bundleName == bundleName && row.rawid == ImeUsageEventId::EVENT_COUNT_DURATION &&
            row.happenTime >= dayStartTime) {
            return static_cast<int64_t>(i - 1);
        }
    }
    return -1;
}

int64_t ImeUsageDataHelper::UpsertCountDurationLocked(const std::string &bundleName, int64_t dayStartTime,
    const ImeEventRecord &countRecord, const DurationMap &durations)
{
    int64_t existingIdx = FindLastCountDurationLocked(bundleName, dayStartTime);
    if (existingIdx >= 0) {
        auto &existing = events_[static_cast<size_t>(existingIdx)];
        for (size_t i = 0; i < DURATION_COUNT; i++) {
            existing.durations[i] += durations[i];
        }
        existing.showCount += 1;
        existing.ts = countRecord.ts;
        existing.happenTime = countRecord.happenTime;
        return existing.id;
    }
    // Insert new COUNT_DURATION record
    ImeEventRecord newRecord = countRecord;
    newRecord.showCount = 1;
    ImeUsageEventRow row = MakeRow(newRecord, durations);
    row.id = nextId_++;
    int64_t newId = row.id;
    events_.push_back(std::move(row));
    return newId;
}

ImeUsageDataHelper::ImeUsageDataHelper(const std::string &workPath)
{
    fileStore_ = std::make_unique<ImeUsageFileStore>(workPath);
    if (!fileStore_->IsReady()) {
        IMSA_HILOGE("ImeUsageFileStore not ready");
        return;
    }
    // Load persisted state; on corruption, start fresh (fileStore handles recovery).
    if (!fileStore_->LoadEvents(events_, nextId_, lastReportTime_)) {
        IMSA_HILOGW("LoadEvents failed, starting with empty events");
        events_.clear();
        nextId_ = 1;
        lastReportTime_ = 0;
    }
    ready_ = true;
    IMSA_HILOGI("ImeUsageDataHelper ready: %{public}zu events, nextId=%{public}" PRId64 ", lastReportTime=%{public}llu",
        events_.size(), nextId_, static_cast<unsigned long long>(lastReportTime_));
}

bool ImeUsageDataHelper::IsReady() const
{
    return ready_;
}

int ImeUsageDataHelper::AddEvent(const ImeEventRecord &record, const DurationMap &durations)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        IMSA_HILOGE("not ready");
        return DB_FAILED;
    }
    ImeUsageEventRow row = MakeRow(record, durations);
    row.id = nextId_++;
    events_.push_back(row);
    if (!fileStore_->WriteEvents(events_, nextId_, lastReportTime_)) {
        IMSA_HILOGE("WriteEvents failed, rawId=%{public}d, bundle=%{public}s", record.rawid, record.bundleName.c_str());
        events_.pop_back();
        nextId_--;
        return DB_FAILED;
    }
    IMSA_HILOGI("AddEvent: id=%{public}" PRId64 ", rawId=%{public}d, bundle=%{public}s, "
                "screenStatus=%{public}d, happenTime=%{public}" PRId64,
        row.id, record.rawid, record.bundleName.c_str(), record.screenStatus, record.happenTime);
    return DB_SUCC;
}

int ImeUsageDataHelper::DeleteEventsByBundleAndStartIndex(const std::string &bundleName, int32_t startIndex)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return DB_FAILED;
    }
    size_t oldSize = events_.size();
    auto eventsBackup = events_;
    events_.erase(
        std::remove_if(events_.begin(), events_.end(),
            [&](const ImeUsageEventRow &row) {
                return row.bundleName == bundleName && row.id >= startIndex;
            }),
        events_.end());
    if (events_.size() == oldSize) {
        IMSA_HILOGI("DeleteEventsByBundleAndStartIndex: no rows matched, bundle=%{public}s, from id=%{public}d",
            bundleName.c_str(), startIndex);
        return DB_SUCC;
    }
    if (!fileStore_->WriteEvents(events_, nextId_, lastReportTime_)) {
        IMSA_HILOGE("DeleteEventsByBundleAndStartIndex: WriteEvents failed");
        events_ = std::move(eventsBackup);
        return DB_FAILED;
    }
    IMSA_HILOGI(
        "DeleteEventsByBundleAndStartIndex: bundle=%{public}s, from id=%{public}d", bundleName.c_str(), startIndex);
    return DB_SUCC;
}

int ImeUsageDataHelper::DeleteAndUpsertTransactional(const std::string &bundleName, int32_t startIndex,
    int64_t dayStartTime, const ImeEventRecord &countRecord, const DurationMap &durations)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        IMSA_HILOGE("DeleteAndUpsertTransactional: not ready");
        return DB_FAILED;
    }
    // Snapshot for rollback
    auto eventsBackup = events_;
    int64_t nextIdBackup = nextId_;

    // Delete old session events from startIndex onwards
    events_.erase(
        std::remove_if(events_.begin(), events_.end(),
            [&](const ImeUsageEventRow &row) {
                return row.bundleName == bundleName && row.id >= startIndex;
            }),
        events_.end());

    int64_t upsertedId = UpsertCountDurationLocked(bundleName, dayStartTime, countRecord, durations);

    if (!fileStore_->WriteEvents(events_, nextId_, lastReportTime_)) {
        IMSA_HILOGE("DeleteAndUpsertTransactional: WriteEvents failed, rolling back");
        events_ = std::move(eventsBackup);
        nextId_ = nextIdBackup;
        return DB_FAILED;
    }
    IMSA_HILOGI("DeleteAndUpsertTransactional: bundle=%{public}s, startIndex=%{public}d, "
                "upsertedId=%{public}" PRId64,
        bundleName.c_str(), startIndex, upsertedId);
    return DB_SUCC;
}

int ImeUsageDataHelper::UpsertCountDuration(const std::string &bundleName, int64_t dayStartTime,
    const ImeEventRecord &countRecord, const DurationMap &durations)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        IMSA_HILOGE("UpsertCountDuration: not ready");
        return DB_FAILED;
    }
    // Snapshot for rollback
    auto eventsBackup = events_;
    int64_t nextIdBackup = nextId_;

    int64_t upsertedId = UpsertCountDurationLocked(bundleName, dayStartTime, countRecord, durations);

    if (!fileStore_->WriteEvents(events_, nextId_, lastReportTime_)) {
        IMSA_HILOGE("UpsertCountDuration: WriteEvents failed, upsertedId=%{public}" PRId64, upsertedId);
        events_ = std::move(eventsBackup);
        nextId_ = nextIdBackup;
        return DB_FAILED;
    }
    IMSA_HILOGI("UpsertCountDuration: upserted id=%{public}" PRId64 " for %{public}s", upsertedId, bundleName.c_str());
    return DB_SUCC;
}

int ImeUsageDataHelper::QueryRawEventIndex(const std::string &bundleName, int32_t rawId)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return IME_INDEX_NOT_FOUND;
    }
    int64_t idx = FindLastRowLocked(bundleName, rawId);
    if (idx < 0) {
        IMSA_HILOGI("QueryRawEventIndex: not found, bundle=%{public}s, rawId=%{public}d", bundleName.c_str(), rawId);
        return IME_INDEX_NOT_FOUND;
    }
    int64_t foundId = events_[static_cast<size_t>(idx)].id;
    IMSA_HILOGI("QueryRawEventIndex: bundle=%{public}s, rawId=%{public}d, foundId=%{public}" PRId64, bundleName.c_str(),
        rawId, foundId);
    return static_cast<int32_t>(foundId);
}

void ImeUsageDataHelper::QueryEventRecords(
    int32_t startIndex, int64_t dayStartTime, const std::string &bundleName, std::vector<ImeEventRecord> &records)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return;
    }
    records.clear();
    int checkpointCount = 0;
    // Forward scan, filter by bundle+id+dayStart
    for (const auto &row : events_) {
        if (row.bundleName != bundleName || row.id < startIndex || row.happenTime < dayStartTime) {
            continue;
        }
        if (row.rawid == ImeUsageEventId::EVENT_COUNT_DURATION) {
            checkpointCount++;
            if (!records.empty()) {
                IMSA_HILOGW("QueryEventRecords: COUNT_DURATION encountered with %{public}zu "
                            "unprocessed records, discarding (bundle=%{public}s)",
                    records.size(), row.bundleName.c_str());
            }
            records.clear();
            continue;
        }
        ImeEventRecord record;
        record.rawid = row.rawid;
        record.ts = row.ts;
        record.happenTime = row.happenTime;
        record.bundleName = row.bundleName;
        record.screenStatus = row.screenStatus;
        record.preScreenStatus = row.preScreenStatus;
        records.push_back(std::move(record));
    }
    IMSA_HILOGI("QueryEventRecords: bundle=%{public}s, startIndex=%{public}d, "
                "dayStartTime=%{public}" PRId64 ", resultCount=%{public}zu, checkpoints=%{public}d",
        bundleName.c_str(), startIndex, dayStartTime, records.size(), checkpointCount);
}

void ImeUsageDataHelper::QueryStatisticEventsInPeriod(
    uint64_t startTime, uint64_t endTime, std::unordered_map<std::string, ImeUsageInfo> &infos)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return;
    }
    IMSA_HILOGI("QueryStatisticEventsInPeriod: startTime=%{public}llu, endTime=%{public}llu",
        static_cast<unsigned long long>(startTime), static_cast<unsigned long long>(endTime));

    infos.clear();
    for (const auto &row : events_) {
        if (static_cast<uint64_t>(row.happenTime) < startTime || static_cast<uint64_t>(row.happenTime) > endTime) {
            continue;
        }
        auto &info = infos[row.bundleName];
        info.package = row.bundleName;
        for (size_t i = 0; i < DURATION_COUNT; i++) {
            info.durations[i] += row.durations[i];
        }
        // showCount: count INPUT_START rows + sum show_count of COUNT_DURATION rows
        if (row.rawid == ImeUsageEventId::EVENT_INPUT_START) {
            info.showCount += 1;
        } else if (row.rawid == ImeUsageEventId::EVENT_COUNT_DURATION) {
            info.showCount += row.showCount;
        }
    }
    for (auto &[bundle, info] : infos) {
        info.usage = info.GetAppUsage();
    }
    IMSA_HILOGI("QueryStatisticEventsInPeriod: found %{public}zu IME groups", infos.size());
}

void ImeUsageDataHelper::QueryFinalEventInfo(uint64_t endTime, ImeUsageRawEvent &event)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return;
    }
    // Reverse scan for first event with happenTime <= endTime
    for (size_t i = events_.size(); i > 0; i--) {
        const auto &row = events_[i - 1];
        if (static_cast<uint64_t>(row.happenTime) <= endTime) {
            event.id = row.id;
            event.rawId = row.rawid;
            event.package = row.bundleName;
            event.ts = row.ts;
            event.happenTime = row.happenTime;
            event.screenStatusAfter = row.screenStatus;
            event.screenStatusBefore = row.preScreenStatus;
            IMSA_HILOGI("QueryFinalEventInfo: id=%{public}" PRId64 ", rawId=%{public}d, "
                        "pkg=%{public}s, screenAfter=%{public}d, screenBefore=%{public}d",
                event.id, event.rawId, event.package.c_str(), event.screenStatusAfter, event.screenStatusBefore);
            return;
        }
    }
    IMSA_HILOGI(
        "QueryFinalEventInfo: no events found before endTime=%{public}llu", static_cast<unsigned long long>(endTime));
}

void ImeUsageDataHelper::QueryForegroundImeInfo(
    uint64_t startTime, uint64_t endTime, int32_t screenStatus, ImeUsageInfo &info)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return;
    }
    IMSA_HILOGI("QueryForegroundImeInfo: startTime=%{public}llu, endTime=%{public}llu, "
                "screenStatus=%{public}d, pkg=%{public}s",
        static_cast<unsigned long long>(startTime), static_cast<unsigned long long>(endTime), screenStatus,
        info.package.c_str());

    // Collect rows for this bundle in [startTime, endTime], reverse order (newest first)
    std::vector<ImeUsageEventRow> matchingRows;
    for (size_t i = events_.size(); i > 0; i--) {
        const auto &row = events_[i - 1];
        if (row.bundleName == info.package && static_cast<uint64_t>(row.happenTime) >= startTime &&
            static_cast<uint64_t>(row.happenTime) <= endTime) {
            matchingRows.push_back(row);
        }
    }
    IMSA_HILOGI("QueryForegroundImeInfo: collected %{public}zu matching rows", matchingRows.size());

    std::vector<ForegroundRawEvt> fgEvents;
    CollectForegroundEvents(matchingRows, info.package, fgEvents);
    IMSA_HILOGI("QueryForegroundImeInfo: collected %{public}zu foreground events", fgEvents.size());
    CalculateForegroundDuration(fgEvents, startTime, endTime, screenStatus, info);
}

int ImeUsageDataHelper::DeleteEventsByTime(uint64_t clearDataTime)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return DB_FAILED;
    }
    size_t oldSize = events_.size();
    auto eventsBackup = events_;
    events_.erase(
        std::remove_if(events_.begin(), events_.end(),
            [&](const ImeUsageEventRow &row) {
                return static_cast<uint64_t>(row.happenTime) < clearDataTime;
            }),
        events_.end());
    if (events_.size() == oldSize) {
        IMSA_HILOGI(
            "DeleteEventsByTime: no rows older than %{public}llu", static_cast<unsigned long long>(clearDataTime));
        return DB_SUCC;
    }
    if (!fileStore_->WriteEvents(events_, nextId_, lastReportTime_)) {
        IMSA_HILOGE("DeleteEventsByTime: WriteEvents failed");
        events_ = std::move(eventsBackup);
        return DB_FAILED;
    }
    IMSA_HILOGI("Deleted rows older than %{public}llu", static_cast<unsigned long long>(clearDataTime));
    return DB_SUCC;
}

int ImeUsageDataHelper::SaveReportState(const std::string &key, uint64_t value)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return DB_FAILED;
    }
    lastReportTime_ = value;
    if (!fileStore_->WriteEvents(events_, nextId_, lastReportTime_)) {
        IMSA_HILOGE("SaveReportState failed, key=%{public}s", key.c_str());
        return DB_FAILED;
    }
    IMSA_HILOGI(
        "SaveReportState: key=%{public}s, value=%{public}llu", key.c_str(), static_cast<unsigned long long>(value));
    return DB_SUCC;
}

int ImeUsageDataHelper::LoadReportState(const std::string &key, uint64_t &value)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return DB_FAILED;
    }
    value = lastReportTime_;
    IMSA_HILOGI(
        "LoadReportState: key=%{public}s, value=%{public}llu", key.c_str(), static_cast<unsigned long long>(value));
    return DB_SUCC;
}

int64_t ImeUsageDataHelper::QueryEarliestEventTime()
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (!ready_) {
        return IME_INDEX_NOT_FOUND;
    }
    int64_t earliestTime = IME_INDEX_NOT_FOUND;
    for (const auto &row : events_) {
        if (earliestTime == IME_INDEX_NOT_FOUND || row.happenTime < earliestTime) {
            earliestTime = row.happenTime;
        }
    }
    IMSA_HILOGI("QueryEarliestEventTime: %{public}" PRId64, earliestTime);
    return earliestTime;
}

std::vector<uint64_t> ImeUsageDataHelper::QueryActiveDays(uint64_t startTime, uint64_t endTime)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    std::vector<uint64_t> days;
    if (!ready_) {
        return days;
    }
    // Collect distinct day-start timestamps
    std::unordered_set<uint64_t> daySet;
    for (const auto &row : events_) {
        uint64_t ht = static_cast<uint64_t>(row.happenTime);
        if (ht < startTime || ht > endTime) {
            continue;
        }
        uint64_t dayStart = DayStartFromMs(ht);
        daySet.insert(dayStart);
    }
    days.assign(daySet.begin(), daySet.end());
    std::sort(days.begin(), days.end());
    IMSA_HILOGI("QueryActiveDays: found %{public}zu days in [%{public}llu, %{public}llu]", days.size(),
        static_cast<unsigned long long>(startTime), static_cast<unsigned long long>(endTime));
    return days;
}

} // namespace MiscServices
} // namespace OHOS
