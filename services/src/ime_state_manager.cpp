/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <cinttypes>
#include "res_sched_client.h"
#include "system_ability_definition.h"
#include "ime_state_manager.h"

#include "global.h"

namespace OHOS {
namespace MiscServices {
std::shared_ptr<AppExecFwk::EventHandler> ImeStateManager::eventHandler_ = nullptr;
// LCOV_EXCL_START
bool ImeStateManager::IsIpcNeeded(RequestType type)
{
    // If ime is in use, no need to request hide.
    std::lock_guard<std::mutex> lock(mutex_);
    return !(type == RequestType::REQUEST_HIDE && !isImeInUse_);
}

void ImeStateManager::BeforeIpc(RequestType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (type == RequestType::START_INPUT || type == RequestType::REQUEST_SHOW) {
        isImeInUse_ = true;
    }
    if (!isFrozen_) {
        IMSA_HILOGD("not frozen already.");
        return;
    }
    isFrozen_ = false;
    ControlIme(false);
}

void ImeStateManager::AfterIpc(RequestType type, bool isSuccess)
{
    bool shouldFreeze = false;
    std::lock_guard<std::mutex> lock(mutex_);
    if (type == RequestType::START_INPUT || type == RequestType::REQUEST_SHOW) {
        isImeInUse_ = isSuccess;
    }
    if (type == RequestType::REQUEST_HIDE && isImeInUse_) {
        isImeInUse_ = !isSuccess;
    }
    if (type == RequestType::STOP_INPUT) {
        isImeInUse_ = false;
    }
    if (isFrozen_ == !isImeInUse_) {
        IMSA_HILOGD("frozen state already: %{public}d.", isFrozen_);
        return;
    }
    isFrozen_ = !isImeInUse_;
    shouldFreeze = isFrozen_;
    ControlIme(shouldFreeze);
}

void ImeStateManager::SetEventHandler(const std::shared_ptr<AppExecFwk::EventHandler> &eventHandler)
{
    eventHandler_ = eventHandler;
}

bool ImeStateManager::IsImeInUse()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return isImeInUse_;
}

void ImeStateManager::ReportQos(bool isStart, pid_t pid)
{
    auto type = ResourceSchedule::ResType::RES_TYPE_IME_QOS_CHANGE;
    auto state = isStart ? ResourceSchedule::ResType::ImeQosState::IME_START_UP :
                                ResourceSchedule::ResType::ImeQosState::IME_START_FINISH;
    std::unordered_map<std::string, std::string> payload = {
        { "saId",          std::to_string(INPUT_METHOD_SYSTEM_ABILITY_ID)                                      },
        { "saName",        std::string(INPUT_METHOD_SERVICE_SA_NAME)                                           },
        { "pid",           std::to_string(pid)                                                                 },
    };
    IMSA_HILOGI("report qos state: %{public}" PRId64 ".", state);
    ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, state, payload);
}
// LCOV_EXCL_STOP
} // namespace MiscServices
} // namespace OHOS