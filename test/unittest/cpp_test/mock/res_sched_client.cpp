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

#include "res_sched_client.h"
#include "res_sched_json_client.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace ResourceSchedule {
std::mutex ResSchedJsonClient::reportSyncEventLock_;
int32_t ResSchedJsonClient::reportSyncEventRet_{ 0 };
nlohmann::json ResSchedJsonClient::reportSyncEventReply_;
ResSchedClient &ResSchedClient::GetInstance()
{
    static ResSchedClient client;
    return client;
}

void ResSchedClient::ReportData(
    uint32_t resType, int64_t value, const std::unordered_map<std::string, std::string> &mapPayload)
{
}

ResSchedJsonClient &ResSchedJsonClient::GetInstance()
{
    static ResSchedJsonClient client;
    return client;
}

int32_t ResSchedJsonClient::ReportSyncEvent(
    const uint32_t resType, const int64_t value, const nlohmann::json &payload, nlohmann::json &reply)
{
    std::lock_guard<std::mutex> lock(reportSyncEventLock_);
    reply = reportSyncEventReply_;
    return reportSyncEventRet_;
}

void ResSchedJsonClient::SetReportSyncEventRet(int32_t ret)
{
    std::lock_guard<std::mutex> lock(reportSyncEventLock_);
    reportSyncEventRet_ = ret;
}

void ResSchedJsonClient::SetReportSyncEventReply(const nlohmann::json &reply)
{
    std::lock_guard<std::mutex> lock(reportSyncEventLock_);
    reportSyncEventReply_ = reply;
}
} // namespace ResourceSchedule
} // namespace OHOS
