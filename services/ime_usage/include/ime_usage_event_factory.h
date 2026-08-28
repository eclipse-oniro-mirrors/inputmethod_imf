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
 
#ifndef SERVICES_IME_USAGE_INCLUDE_IME_USAGE_EVENT_FACTORY_H
#define SERVICES_IME_USAGE_INCLUDE_IME_USAGE_EVENT_FACTORY_H
 
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
 
#include "ime_usage_common.h"
#include "ime_usage_db_helper.h"
 
namespace OHOS { 
namespace MiscServices {
class ImeUsageEventFactory {
public:
    explicit ImeUsageEventFactory(std::shared_ptr<ImeUsageDbHelper> dbHelper);
    ~ImeUsageEventFactory() = default;
 
    // Perform daily aggregation for a specific day: query DB, merge foreground apps, generate report events
    void Create(std::vector<ImeUsageInfo> &infos, uint64_t dayStartTime, uint64_t dayEndTime);
 
    // Clean up data older than clearDataTime
    void CleanupOldData(uint64_t clearDataTime);
 
    // Get the shared dbHelper (for reporter to persist/load state and query earliest time)
    std::shared_ptr<ImeUsageDbHelper> GetDbHelper() const { return dbHelper_; }
 
private:
    void GetUsageInfo(std::vector<ImeUsageInfo> &infos, uint64_t startTime, uint64_t endTime);
    void MergeForegroundInfo(std::unordered_map<std::string, ImeUsageInfo> &statisticInfos,
        uint64_t startTime, uint64_t endTime);
    void CollectAndSortResults(std::unordered_map<std::string, ImeUsageInfo> &statisticInfos,
        std::vector<ImeUsageInfo> &infos);
    uint64_t GetToday0ClockMs() const;
 
    std::shared_ptr<ImeUsageDbHelper> dbHelper_;
};
} // namespace MiscServices
} // namespace OHOS
 
#endif // SERVICES_IME_USAGE_INCLUDE_IME_USAGE_EVENT_FACTORY_H