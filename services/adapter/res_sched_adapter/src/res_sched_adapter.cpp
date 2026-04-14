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

#include "res_sched_adapter.h"

#include "extension_ability_info.h"
#include "global.h"
#include "ipc_skeleton.h"
#include "res_sched_client.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::ResourceSchedule;
constexpr const char *INPUT_METHOD_SERVICE_SA_NAME = "inputmethod_service";
std::mutex ResSchedAdapter::lastPanelStatusMapLock_;
std::map<uint32_t, bool> ResSchedAdapter::lastPanelStatusMap_;
int32_t ResSchedAdapter::NotifyMakeImage(int32_t userId, const AAFwk::Want &want)
{
    auto resType = ResType::SYNC_RES_TYPE_NOTIFY_MAKE_IMAGE;
    nlohmann::json payload;
    auto bundleName = want.GetBundle();
    payload.emplace("bundleName", bundleName);
    auto wantUri = want.ToUri();
    payload.emplace("want", wantUri);
    payload.emplace("userId", userId);
    nlohmann::json reply;
    auto ret = ResSchedClient::GetInstance().ReportSyncEvent(resType, 0, payload, reply);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("%{public}d/%{public}s report failed:%{public}d.", userId, bundleName.c_str(), ret);
        return ret;
    }
    if (!reply.contains("errCode") || !reply["errCode"].is_number()) {
        IMSA_HILOGE("%{public}d/%{public}s abnormal reply.", userId, bundleName.c_str());
        return ErrorCode::ERROR_EX_SERVICE_SPECIFIC;
    }
    auto errCode = static_cast<int32_t>(reply["errCode"]);
    IMSA_HILOGI("%{public}d/%{public}s final reply ret:%{public}d.", userId, bundleName.c_str(), errCode);
    return errCode;
}

void ResSchedAdapter::NotifyPanelStatus(bool isPanelShow)
{
    auto pid = IPCSkeleton::GetCallingPid();
    {
        std::lock_guard<std::mutex> lock(lastPanelStatusMapLock_);
        auto it = lastPanelStatusMap_.find(pid);
        if (it == lastPanelStatusMap_.end()) {
            lastPanelStatusMap_[pid] = false;
        }
        if (isPanelShow == lastPanelStatusMap_[pid]) {
            IMSA_HILOGD("notify message repeat, isPanelShow: %{public}d.", isPanelShow);
            return;
        }
        lastPanelStatusMap_[pid] = isPanelShow;
    }

    auto type = ResType::RES_TYPE_INPUT_METHOD_CHANGE;
    auto status = isPanelShow ? ResType::InputMethodState::INPUT_METHOD_SHOW_PANEL :
                                ResType::InputMethodState::INPUT_METHOD_CLOSE_PANEL;
    std::unordered_map<std::string, std::string> payload = {
        { "saId",          std::to_string(INPUT_METHOD_SYSTEM_ABILITY_ID)                                      },
        { "saName",        std::string(INPUT_METHOD_SERVICE_SA_NAME)                                           },
        { "extensionType", std::to_string(static_cast<int32_t>(AppExecFwk::ExtensionAbilityType::INPUTMETHOD)) },
        { "pid",           std::to_string(pid)                                                                 },
        { "uid",           std::to_string(IPCSkeleton::GetCallingUid())                                        }
    };
    IMSA_HILOGD("report RSS isPanelShow: %{public}d.", isPanelShow);
    ResSchedClient::GetInstance().ReportData(type, status, payload);
}

void ResSchedAdapter::ResetPanelStatusFlag(uint32_t pid)
{
    std::lock_guard<std::mutex> lock(lastPanelStatusMapLock_);
    lastPanelStatusMap_.erase(pid);
}
} // namespace MiscServices
} // namespace OHOS