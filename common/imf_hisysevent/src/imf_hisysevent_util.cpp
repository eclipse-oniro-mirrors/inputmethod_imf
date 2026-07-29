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

#include "imf_hisysevent_util.h"

#include <algorithm>
#include <map>
#include "accesstoken_kit.h"
#include "app_mgr_client.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "running_process_info.h"
#include "singleton.h"
#include "global.h"
namespace OHOS {
namespace MiscServices {
const std::map<int32_t, int32_t> ImfHiSysEventUtil::HIDUMPER_ERROR_CODE_MAP = {
    { EXCEPTION_PERMISSION, PERMISSION_CHECK_FAILED },
    { EXCEPTION_SYSTEM_PERMISSION, NOT_SYSTEM_APPLICATION },
    { EXCEPTION_CONFPERSIST, CONFIG_PERSISTENCE_ERROR },
    { EXCEPTION_IMMS, IME_MANAGER_SERVICE_ERROR },
    { EXCEPTION_USER_NOT_EXIST, USER_NOT_EXIST },
    { EXCEPTION_USER_NOT_IN_FOREGROUND, USER_NOT_FOREGROUND },
    { EXCEPTION_CROSS_USER_OPERATION_DENIED, CROSS_USER_OPERATION_DENIED },
};

const std::map<int32_t, int32_t> ImfHiSysEventUtil::ERROR_CODE_MAP = {
    { ErrorCode::ERROR_CONTROLLER_INVOKING_FAILED, EXCEPTION_CONTROLLER },
    { ErrorCode::ERROR_STATUS_PERMISSION_DENIED, EXCEPTION_PERMISSION },
    { ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION, EXCEPTION_SYSTEM_PERMISSION },
    { ErrorCode::ERROR_REMOTE_CLIENT_DIED, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_CLIENT_NOT_FOUND, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_CLIENT_NULL_POINTER, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_CLIENT_NOT_FOCUSED, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_CLIENT_NOT_EDITABLE, EXCEPTION_EDITABLE },
    { ErrorCode::ERROR_CLIENT_NOT_BOUND, EXCEPTION_DETACHED },
    { ErrorCode::ERROR_CLIENT_ADD_FAILED, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_NULL_POINTER, EXCEPTION_IMMS },
    { ErrorCode::ERROR_BAD_PARAMETERS, EXCEPTION_IMMS },
    { ErrorCode::ERROR_SERVICE_START_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_KBD_SHOW_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_KBD_HIDE_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IME_NOT_STARTED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_EX_NULL_POINTER, EXCEPTION_IMMS },
    { ErrorCode::ERROR_PERSIST_CONFIG, EXCEPTION_CONFPERSIST },
    { ErrorCode::ERROR_PACKAGE_MANAGER, EXCEPTION_PACKAGEMANAGER },
    { ErrorCode::ERROR_EX_UNSUPPORTED_OPERATION, EXCEPTION_IMMS },
    { ErrorCode::ERROR_EX_SERVICE_SPECIFIC, EXCEPTION_IMMS },
    { ErrorCode::ERROR_EX_PARCELABLE, EXCEPTION_IMMS },
    { ErrorCode::ERROR_EX_ILLEGAL_ARGUMENT, EXCEPTION_IMMS },
    { ErrorCode::ERROR_EX_ILLEGAL_STATE, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IME_START_INPUT_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_NOT_IME, EXCEPTION_IME },
    { ErrorCode::ERROR_IME, EXCEPTION_IMENGINE },
    { ErrorCode::ERROR_PARAMETER_CHECK_FAILED, EXCEPTION_PARAMCHECK },
    { ErrorCode::ERROR_NOT_DEFAULT_IME, EXCEPTION_DEFAULTIME },
    { ErrorCode::ERROR_ENABLE_IME, EXCEPTION_IMMS },
    { ErrorCode::ERROR_NOT_CURRENT_IME, EXCEPTION_IMMS },
    { ErrorCode::ERROR_PANEL_NOT_FOUND, EXCEPTION_PANEL_NOT_FOUND },
    { ErrorCode::ERROR_WINDOW_MANAGER, EXCEPTION_WINDOW_MANAGER },
    { ErrorCode::ERROR_GET_TEXT_CONFIG, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_INVALID_PRIVATE_COMMAND_SIZE, EXCEPTION_PARAMCHECK },
    { ErrorCode::ERROR_TEXT_LISTENER_ERROR, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_TEXT_PREVIEW_NOT_SUPPORTED, EXCEPTION_TEXT_PREVIEW_NOT_SUPPORTED },
    { ErrorCode::ERROR_INVALID_RANGE, EXCEPTION_PARAMCHECK },
    { ErrorCode::ERROR_SECURITY_MODE_OFF, EXCEPTION_BASIC_MODE },
    { ErrorCode::ERROR_MSG_HANDLER_NOT_REGIST, EXCEPTION_REQUEST_NOT_ACCEPT },
    { ErrorCode::ERROR_MESSAGE_HANDLER, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_INVALID_ARRAY_BUFFER_SIZE, EXCEPTION_PARAMCHECK },
    { ErrorCode::ERROR_INVALID_PANEL_TYPE, EXCEPTION_INVALID_PANEL_TYPE_FLAG },
    { ErrorCode::ERROR_INVALID_PANEL_FLAG, EXCEPTION_INVALID_PANEL_TYPE_FLAG },
    { ErrorCode::ERROR_IMA_CHANNEL_NULLPTR, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_IPC_REMOTE_NULLPTR, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMA_NULLPTR, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_INPUT_TYPE_NOT_FOUND, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_DEFAULT_IME_NOT_FOUND, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_CLIENT_INPUT_READY_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_MALLOC_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_NULLPTR, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_GET_IME_INFO_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_IME_TO_START_NULLPTR, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_REBOOT_OLD_IME_NOT_STOP, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_IME_EVENT_CONVERT_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_IME_CONNECT_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_IME_DISCONNECT_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_IME_START_TIMEOUT, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_IME_START_MORE_THAN_EIGHT_SECOND, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMSA_FORCE_STOP_IME_TIMEOUT, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMC_NULLPTR, EXCEPTION_IMMS },
    { ErrorCode::ERROR_DEVICE_UNSUPPORTED, EXCEPTION_UNSUPPORTED },
    { ErrorCode::ERROR_IME_NOT_FOUND, EXCEPTION_IME_NOT_FOUND },
    { ErrorCode::ERROR_OPERATE_SYSTEM_IME, EXCEPTION_OPERATE_DEFAULTIME },
    { ErrorCode::ERROR_SWITCH_IME, EXCEPTION_IMMS },
    { ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL, EXCEPTION_IMCLIENT },
    { ErrorCode::ERROR_IMA_INVALID_IMMERSIVE_EFFECT, EXCEPTION_INVALID_IMMERSIVE_EFFECT },
    { ErrorCode::ERROR_IMA_PRECONDITION_REQUIRED, EXCEPTION_PRECONDITION_REQUIRED },
    { ErrorCode::ERROR_INVALID_DISPLAYID, EXCEPTION_INVALID_DISPLAYID },
    { ErrorCode::ERROR_TRY_IME_START_FAILED, EXCEPTION_IMMS },
    { ErrorCode::ERROR_USER_NOT_EXIST, EXCEPTION_USER_NOT_EXIST },
    { ErrorCode::ERROR_USER_NOT_IN_FOREGROUND, EXCEPTION_USER_NOT_IN_FOREGROUND },
    { ErrorCode::ERROR_CROSS_USER_OPERATION_DENIED, EXCEPTION_CROSS_USER_OPERATION_DENIED },
    { ErrorCode::ERROR_SYSTEM_PANEL_ERROR, EXCEPTION_SYSTEM_PANEL_ERROR },
};
using namespace OHOS::AppExecFwk;
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;
using namespace Security::AccessToken;
void ImfHiSysEventUtil::ReportClientAttachFault(
    const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info)
{
    IMSA_HILOGD("run in.");
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, "CLIENT_ATTACH_FAILED", HiSysEvent::EventType::FAULT,
        "SELF_NAME", selfName, "PEER_NAME", info.peerName, "PEER_PID", info.peerPid, "PEER_USERID", info.peerUserId,
        "CLIENT_TYPE", info.clientType, "INPUT_PATTERN", info.inputPattern, "ISSHOWKEYBOARD", info.isShowKeyboard,
        "IME_NAME", info.imeName, "ERR_CODE", info.errCode, "FAULT_COUNT", faultNum);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d.", ret);
    }
}

void ImfHiSysEventUtil::ReportClientShowFault(
    const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info)
{
    IMSA_HILOGD("run in.");
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, "CLIENT_SHOW_FAILED", HiSysEvent::EventType::FAULT,
        "SELF_NAME", selfName, "PEER_NAME", info.peerName, "PEER_PID", info.peerPid, "PEER_USERID", info.peerUserId,
        "CLIENT_TYPE", info.clientType, "INPUT_PATTERN", info.inputPattern, "IME_NAME", info.imeName, "EVENT_CODE",
        info.eventCode, "ERR_CODE", info.errCode, "FAULT_COUNT", faultNum);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d.", ret);
    }
}

void ImfHiSysEventUtil::ReportImeStartInputFault(
    const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info)
{
    IMSA_HILOGD("run in.");
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, "IME_START_INPUT_FAILED", HiSysEvent::EventType::FAULT,
        "SELF_NAME", selfName, "PEER_NAME", info.peerName, "PEER_PID", info.peerPid, "ISSHOWKEYBOARD",
        info.isShowKeyboard, "EVENT_CODE", info.eventCode, "ERR_CODE", info.errCode, "FAULT_COUNT", faultNum);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d.", ret);
    }
}

void ImfHiSysEventUtil::ReportBaseTextOperationFault(
    const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info)
{
    IMSA_HILOGD("run in.");
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, "BASE_TEXT_OPERATION_FAILED",
        HiSysEvent::EventType::FAULT, "SELF_NAME", selfName, "PEER_NAME", info.peerName, "PEER_PID", info.peerPid,
        "CLIENT_TYPE", info.clientType, "EVENT_CODE", info.eventCode, "ERR_CODE", info.errCode, "FAULT_COUNT",
        faultNum);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d.", ret);
    }
}

void ImfHiSysEventUtil::ReportStatisticsEvent(const std::string &eventName, const std::vector<std::string> &imeNames,
    const std::vector<std::string> &appNames, const std::vector<std::string> &statistics)
{
    std::string infoStr;
    if (!statistics.empty()) {
        infoStr = statistics[0];
    }
    IMSA_HILOGD("run in, [%{public}s, %{public}s].", eventName.c_str(), infoStr.c_str());
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, eventName, HiSysEvent::EventType::STATISTIC,
        "IME_NAME", imeNames, "APP_NAME", appNames, "INFOS", statistics);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d.", ret);
    }
}

void ImfHiSysEventUtil::ReportStatisticsEvent(const std::string &eventName, const std::string &imeName,
    const std::vector<std::string> &appNames, const std::vector<std::string> &statistics)
{
    std::string infoStr;
    if (!statistics.empty()) {
        infoStr = statistics[0];
    }
    IMSA_HILOGD("run in, [%{public}s, %{public}s].", eventName.c_str(), infoStr.c_str());
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, eventName, HiSysEvent::EventType::STATISTIC,
        "SELF_NAME", imeName, "APP_NAME", appNames, "INFOS", statistics);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d.", ret);
    }
}

std::string ImfHiSysEventUtil::GetAppName(uint64_t fullTokenId)
{
    std::string name;
    uint32_t tokenId = static_cast<uint32_t>(fullTokenId);
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    switch (tokenType) {
        case ATokenTypeEnum::TOKEN_HAP: {
            if (fullTokenId == IPCSkeleton::GetSelfTokenID()) {
                RunningProcessInfo info;
                auto appMgrClient = DelayedSingleton<AppMgrClient>::GetInstance();
                if (appMgrClient != nullptr && appMgrClient->GetProcessRunningInformation(info) == 0) {
                    name = info.processName_;
                }
                break;
            }
            HapTokenInfo hapInfo;
            if (AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo) == 0) {
                name = hapInfo.bundleName;
            }
            break;
        }
        case ATokenTypeEnum::TOKEN_NATIVE:
        case ATokenTypeEnum::TOKEN_SHELL: {
            NativeTokenInfo tokenInfo;
            if (AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo) == 0) {
                name = tokenInfo.processName;
            }
            break;
        }
        default: {
            break;
        }
    }
    return name;
}

std::string ImfHiSysEventUtil::AddIfAbsent(const std::string &bundleName, std::vector<std::string> &bundleNames)
{
    auto it = std::find_if(bundleNames.begin(), bundleNames.end(),
        [&bundleName](const std::string &bundleNameTmp) { return bundleName == bundleNameTmp; });
    if (it == bundleNames.end()) {
        bundleNames.push_back(bundleName);
        return std::to_string(bundleNames.size() - 1);
    }
    return std::to_string(it - bundleNames.begin());
}

int32_t ImfHiSysEventUtil::HidumperConvertErrorCode(int32_t code)
{
    IMSA_HILOGD("HidumperConvert start.");
    auto iter = HIDUMPER_ERROR_CODE_MAP.find(code);
    if (iter != HIDUMPER_ERROR_CODE_MAP.end()) {
        IMSA_HILOGD("ErrorCode: %{public}d", iter->second);
        return iter->second;
    }
    IMSA_HILOGD("HidumperConvert fail.");
    return code;
}

int32_t ImfHiSysEventUtil::ConvertErrorCode(int32_t code)
{
    IMSA_HILOGD("HidumperConvert start.");
    auto iter = ERROR_CODE_MAP.find(code);
    if (iter != ERROR_CODE_MAP.end()) {
        IMSA_HILOGD("ErrorCode: %{public}d", iter->second);
        return HidumperConvertErrorCode(iter->second);
    }
    IMSA_HILOGD("HidumperConvert fail.");
    return code;
}

} // namespace MiscServices
} // namespace OHOS