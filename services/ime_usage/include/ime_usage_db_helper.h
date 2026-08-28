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
 
#ifndef SERVICES_IME_USAGE_INCLUDE_IME_USAGE_DB_HELPER_H
#define SERVICES_IME_USAGE_INCLUDE_IME_USAGE_DB_HELPER_H
 
#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
 
#include "ime_usage_common.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
 
namespace OHOS {
namespace MiscServices {
class ImeUsageDbHelper {
public:
    explicit ImeUsageDbHelper(const std::string &workPath);
    ~ImeUsageDbHelper() = default;
 
    bool IsReady() const;
 
    // Insert an event record with optional duration columns
    int AddEvent(const ImeEventRecord &record, const DurationMap &durations = {});
 
    // Find the most recent row id for a given bundle and event type
    int QueryRawEventIndex(const std::string &bundleName, int32_t rawId);
 
    // Fetch event records from startIndex onwards for a given bundle within a day
    void QueryEventRecords(int32_t startIndex, int64_t dayStartTime, const std::string &bundleName,
        std::vector<ImeEventRecord> &records);
 
    // Aggregate COUNT_DURATION records for a time period, grouped by package+version
    void QueryStatisticEventsInPeriod(uint64_t startTime, uint64_t endTime,
        std::unordered_map<std::string, ImeUsageInfo> &infos);
 
    // Get the most recent event before endTime (for foreground recovery)
    void QueryFinalEventInfo(uint64_t endTime, ImeUsageRawEvent &event);
 
    // Reconstruct foreground IME duration from raw events (for IMEs still active at day boundary)
    void QueryForegroundImeInfo(uint64_t startTime, uint64_t endTime, int32_t screenStatus,
        ImeUsageInfo &info);
 
    // Delete events older than clearDataTime
    int DeleteEventsByTime(uint64_t clearDataTime);
 
    // Persist/load report state (key-value store)
    int SaveReportState(const std::string &key, const std::string &value);
    int LoadReportState(const std::string &key, std::string &value);
 
    // Query the earliest happen_time in the events table
    int64_t QueryEarliestEventTime();
 
    // Query distinct day-start timestamps that have events in [startTime, endTime]
    std::vector<uint64_t> QueryActiveDays(uint64_t startTime, uint64_t endTime);
 
private:
    bool CreateDbStore(const std::string &dbPath);
    bool VerifyAndRecoverStore(const std::string &dbFile, NativeRdb::RdbStoreConfig &config, int &errCode);
    bool EnsureDirectoryExist(const std::string &path);
    int CreateImeUsageTable();
    int CreateReportStateTable();
    int64_t GenerateTimestamp();
    std::shared_ptr<NativeRdb::RdbStore> GetRdbStoreWithRetry(
        NativeRdb::RdbStoreConfig &config, int version,
        NativeRdb::RdbOpenCallback &callback, int &errCode);
 
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    std::string dbPath_;
    std::mutex dbMutex_;
};
} // namespace MiscServices
} // namespace OHOS
 
#endif // SERVICES_IME_USAGE_INCLUDE_IME_USAGE_DB_HELPER_H