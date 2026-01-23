 /*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "app_mgr_adapter.h"

#include <cinttypes>

#include "app_mgr_client.h"
#include "global.h"
#include "singleton.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::AppExecFwk;
bool AppMgrAdapter::HasBundleName(pid_t pid, const std::string &bundleName)
{
    if (bundleName.empty()) {
        return false;
    }
    RunningProcessInfo info;
    auto ret = GetRunningProcessInfoByPid(pid, info);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetRunningProcessInfoByPid:%{public}d failed:%{public}d.", pid, ret);
        return false;
    }
    auto bundleNames = info.bundleNames;
    auto iter = std::find_if(bundleNames.begin(), bundleNames.end(),
        [&bundleName](const std::string &bundleNameTmp) { return bundleNameTmp == bundleName; });
    return iter != bundleNames.end();
}

int32_t AppMgrAdapter::GetRunningProcessInfoByPid(pid_t pid, RunningProcessInfo &info)
{
    auto appMgrClient = DelayedSingleton<AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        IMSA_HILOGE("appMgrClient is nullptr.");
        return ErrorCode::ERROR_IMSA_APP_MGR_ERROR;
    }
    auto ret = appMgrClient->GetRunningProcessInfoByPid(pid, info);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetRunningProcessInfoByPid:%{public}d failed:%{public}d.", pid, ret);
        return ErrorCode::ERROR_IMSA_APP_MGR_ERROR;
    }
    return ErrorCode::NO_ERROR;
}
} // namespace MiscServices
} // namespace OHOS