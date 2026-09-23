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

#ifndef SERVICES_IME_USAGE_INCLUDE_IME_USAGE_DATA_HELPER_H
#define SERVICES_IME_USAGE_INCLUDE_IME_USAGE_DATA_HELPER_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "ime_usage_common.h"
#include "ime_usage_file_store.h"

namespace OHOS {
namespace MiscServices {

class ImeUsageDataHelper {
public:
    explicit ImeUsageDataHelper(const std::string &workPath);
    ~ImeUsageDataHelper() = default;

    bool IsReady() const;

    // Insert an event record with optional duration columns
    int AddEvent(const ImeEventRecord &record, const DurationMap &durations = {});

    // Delete events for a bundle from a start index onwards (standalone, for fallback)
    int DeleteEventsByBundleAndStartIndex(const std::string &bundleName, int32_t startIndex);

    // Delete raw session events and upsert COUNT_DURATION atomically in one write.
    // If an existing COUNT_DURATION record for the same bundle exists within the same day
    // (happen_time >= dayStartTime), accumulate durations and increment show_count;
    // otherwise insert a new COUNT_DURATION record with show_count = 1.
    int DeleteAndUpsertTransactional(const std::string &bundleName, int32_t startIndex, int64_t dayStartTime,
        const ImeEventRecord &countRecord, const DurationMap &durations);

    // Upsert COUNT_DURATION without transaction (fallback path).
    // Queries for existing COUNT_DURATION for the bundle within the same day; if found,
    // accumulates durations and increments show_count via update; otherwise inserts new.
    int UpsertCountDuration(const std::string &bundleName, int64_t dayStartTime, const ImeEventRecord &countRecord,
        const DurationMap &durations);

    // Find the most recent row id for a given bundle and event type
    int QueryRawEventIndex(const std::string &bundleName, int32_t rawId);

    // Fetch event records from startIndex onwards for a given bundle within a day
    void QueryEventRecords(
        int32_t startIndex, int64_t dayStartTime, const std::string &bundleName, std::vector<ImeEventRecord> &records);

    // Aggregate COUNT_DURATION records for a time period, grouped by package+version
    void QueryStatisticEventsInPeriod(
        uint64_t startTime, uint64_t endTime, std::unordered_map<std::string, ImeUsageInfo> &infos);

    // Get the most recent event before endTime (for foreground recovery)
    void QueryFinalEventInfo(uint64_t endTime, ImeUsageRawEvent &event);

    // Reconstruct foreground IME duration from raw events (for IMEs still active at day boundary)
    void QueryForegroundImeInfo(uint64_t startTime, uint64_t endTime, int32_t screenStatus, ImeUsageInfo &info);

    // Delete events older than clearDataTime
    int DeleteEventsByTime(uint64_t clearDataTime);

    // Persist/load last report time (stored in the events JSON file)
    int SaveReportState(const std::string &key, uint64_t value);
    int LoadReportState(const std::string &key, uint64_t &value);

    // Query the earliest happen_time in the events table
    int64_t QueryEarliestEventTime();

    // Query distinct day-start timestamps that have events in [startTime, endTime]
    std::vector<uint64_t> QueryActiveDays(uint64_t startTime, uint64_t endTime);

private:
    // All *Locked methods assume dbMutex_ is already held by the caller.
    // Reverse-scan for the last row matching bundleName + rawId. Returns index
    // into events_ or -1 if not found.
    int64_t FindLastRowLocked(const std::string &bundleName, int32_t rawId) const;
    // Reverse-scan for the last COUNT_DURATION row for bundleName with
    // happenTime >= dayStartTime. Returns index into events_ or -1 if not found.
    int64_t FindLastCountDurationLocked(const std::string &bundleName, int64_t dayStartTime) const;
    // Upsert a COUNT_DURATION record: if an existing row is found (via
    // FindLastCountDurationLocked), accumulate durations and increment
    // showCount; otherwise insert a new row. Returns the existing row id or
    // the new row id on success, -1 on insert failure (rollback done by caller).
    int64_t UpsertCountDurationLocked(const std::string &bundleName, int64_t dayStartTime,
        const ImeEventRecord &countRecord, const DurationMap &durations);

    bool ready_ = false;
    std::vector<ImeUsageEventRow> events_;
    uint64_t lastReportTime_ = 0;
    int64_t nextId_ = 1;
    std::unique_ptr<ImeUsageFileStore> fileStore_;
    std::mutex dbMutex_;
};

} // namespace MiscServices
} // namespace OHOS

#endif // SERVICES_IME_USAGE_INCLUDE_IME_USAGE_DATA_HELPER_H
