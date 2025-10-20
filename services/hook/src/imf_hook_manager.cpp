/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "imf_hook_manager.h"

#include "global.h"
#include "ime_enabled_info_manager.h"
#include "ime_info_inquirer.h"
#include "imf_module_manager.h"
namespace OHOS {
namespace MiscServices {
constexpr int32_t HOOK_EXEC_RESULT_SUCCESS = 0;
constexpr int64_t REPEAT_REPORT_INTERVAL = 1 * 60 * 60 * 1000; // hourly
ImfHookMgr &ImfHookMgr::GetInstance()
{
    static ImfHookMgr instance;
    return instance;
}

int32_t ImfHookMgr::ExecuteCurrentImeInfoReportHook(int32_t userId, const std::string &bundleName, int64_t timeStampMs)
{
    IMSA_HILOGD("%{public}d/%{public}s run in.", userId, bundleName.c_str());
    auto imeReportedInfo = GenerateImeReportedInfo(userId, bundleName, timeStampMs);
    if (!NeedReport(imeReportedInfo)) {
        return ErrorCode::NO_ERROR;
    }
    auto ret = ExecuteHook(ImfHookStage::REPORT_CURRENT_IME_INFO, static_cast<void *>(&imeReportedInfo));
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    UpdateImeReportedInfo(imeReportedInfo);
    if (imeReportedInfo.needSetConfig) {
        needSetConfig_.store(false);
    }
    return ErrorCode::NO_ERROR;
}

void ImfHookMgr::OnHaServiceStart()
{
    needSetConfig_.store(true);
}

int32_t ImfHookMgr::ExecuteHook(ImfHookStage stage, void *executionContext, const HOOK_EXEC_OPTIONS *options)
{
    auto ret = ImfModuleMgr::GetInstance().Scan(ImfModuleMgr::IMF_EXT_MODULE_PATH);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("module scan failed.");
        return ret;
    }
    ret = HookMgrExecute(GetImfHookMgr(), static_cast<int>(stage), executionContext, options);
    if (ret != HOOK_EXEC_RESULT_SUCCESS) {
        IMSA_HILOGE("%{public}d exec failed:%{public}d.", static_cast<int32_t>(stage), ret);
    }
    return ret != HOOK_EXEC_RESULT_SUCCESS ? ErrorCode::ERROR_OPERATION_NOT_ALLOWED : ErrorCode::NO_ERROR;
}

ImeReportedInfo ImfHookMgr::GenerateImeReportedInfo(int32_t userId, const std::string &bundleName, int64_t timeStampMs)
{
    ImeReportedInfo imeReportedInfo;
    imeReportedInfo.needSetConfig = needSetConfig_.load();
    imeReportedInfo.bundleName = bundleName;
    imeReportedInfo.timeStampMs = timeStampMs;
    imeReportedInfo.versionName = ImeInfoInquirer::GetInstance().GetImeVersionName(userId, bundleName);
    EnabledStatus status{ EnabledStatus::BASIC_MODE };
    ImeEnabledInfoManager::GetInstance().GetEnabledState(userId, bundleName, status);
    imeReportedInfo.securityMode = static_cast<int32_t>(status);
    IMSA_HILOGD("generate info:%{public}s.", imeReportedInfo.ToString().c_str());
    return imeReportedInfo;
}

bool ImfHookMgr::NeedReport(const ImeReportedInfo &info)
{
    std::lock_guard<std::mutex> lock(imeReportedInfoLock_);
    if (info.timeStampMs > imeReportedInfo_.timeStampMs) {
        auto timeDiffMs = info.timeStampMs - imeReportedInfo_.timeStampMs;
        if (info == imeReportedInfo_ && timeDiffMs < REPEAT_REPORT_INTERVAL) {
            IMSA_HILOGD("%{public}s is same in hourly, no need to report.", info.ToString().c_str());
            return false;
        }
    }
    return true;
}

void ImfHookMgr::UpdateImeReportedInfo(const ImeReportedInfo &info)
{
    std::lock_guard<std::mutex> lock(imeReportedInfoLock_);
    imeReportedInfo_ = info;
}
} // namespace MiscServices
} // namespace OHOS