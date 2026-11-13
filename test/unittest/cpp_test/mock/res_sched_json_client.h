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

#ifndef IMF_MOCK_RES_SCHED_JSON_CLIENT_H
#define IMF_MOCK_RES_SCHED_JSON_CLIENT_H

#include <cstdint>
#include <mutex>

#include "nlohmann/json.hpp"

namespace OHOS {
namespace ResourceSchedule {
class ResSchedJsonClient {
public:
    static ResSchedJsonClient &GetInstance();
    int32_t ReportSyncEvent(
        const uint32_t resType, const int64_t value, const nlohmann::json &payload, nlohmann::json &reply);
    static void SetReportSyncEventRet(int32_t ret);
    static void SetReportSyncEventReply(const nlohmann::json &reply);

private:
    static std::mutex reportSyncEventLock_;
    static int32_t reportSyncEventRet_;
    static nlohmann::json reportSyncEventReply_;
};
} // namespace ResourceSchedule
} // namespace OHOS

#endif // IMF_MOCK_RES_SCHED_JSON_CLIENT_H
