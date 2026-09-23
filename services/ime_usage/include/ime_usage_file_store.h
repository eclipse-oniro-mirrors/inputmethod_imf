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

#ifndef SERVICES_IME_USAGE_INCLUDE_IME_USAGE_FILE_STORE_H
#define SERVICES_IME_USAGE_INCLUDE_IME_USAGE_FILE_STORE_H

#include <cstdint>
#include <string>
#include <vector>

#include "ime_usage_common.h"

namespace OHOS {
namespace MiscServices {

// Isolated JSON file persistence for IME usage data.
// Handles serialization and file I/O only — all business logic
// (filtering, aggregation, upsert) lives in ImeUsageDataHelper.
class ImeUsageFileStore {
public:
    explicit ImeUsageFileStore(const std::string &workPath);
    ~ImeUsageFileStore() = default;

    bool IsReady() const
    {
        return !eventsFilePath_.empty();
    }

    // Events file: { "nextId": N, "lastReportTime": T, "events": [...] }
    bool LoadEvents(std::vector<ImeUsageEventRow> &events, int64_t &nextId, uint64_t &lastReportTime);
    bool WriteEvents(const std::vector<ImeUsageEventRow> &events, int64_t nextId, uint64_t lastReportTime);

private:
    bool EnsureDirectoryExist(const std::string &path);
    std::string eventsFilePath_;
};

} // namespace MiscServices
} // namespace OHOS

#endif // SERVICES_IME_USAGE_INCLUDE_IME_USAGE_FILE_STORE_H
