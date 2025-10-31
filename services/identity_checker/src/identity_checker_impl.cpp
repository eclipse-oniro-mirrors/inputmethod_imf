/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "identity_checker_impl.h"

#include <cinttypes>

#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "global.h"
#include "ime_info_inquirer.h"
#include "tokenid_kit.h"
#include "window_adapter.h"

namespace OHOS {
namespace MiscServices {
using namespace Rosen;
using namespace Security::AccessToken;
using namespace OHOS::AAFwk;
bool IdentityCheckerImpl::IsFocused(int64_t callingPid, uint32_t callingTokenId, int64_t focusedPid, bool isAttach,
    sptr<IRemoteObject> abilityToken)
{
    if (focusedPid != INVALID_PID && callingPid == focusedPid) {
        IMSA_HILOGD("focused app, pid: %{public}" PRId64 "", callingPid);
        return true;
    }
    uint64_t displayId;
    if (abilityToken != nullptr) {
        displayId = WindowAdapter::GetDisplayIdByToken(abilityToken);
        IMSA_HILOGD("abilityToken not nullptr, displayId: %{public}" PRIu64 "", displayId);
    } else {
        displayId = WindowAdapter::GetDisplayIdByPid(callingPid);
    }
    if (focusedPid == INVALID_PID) {
        FocusChangeInfo focusInfo;
        WindowAdapter::GetFocusInfo(focusInfo, displayId);
        focusedPid = focusInfo.pid_;
        if (callingPid == focusedPid) {
            IMSA_HILOGD("focused app, pid: %{public}" PRId64 ", display: %{public}" PRIu64 "", callingPid, displayId);
            return true;
        }
    }
    if (isAttach && ImeInfoInquirer::GetInstance().IsInputMethodExtension(callingPid)) {
        return false;
    }
    bool isFocused = IsFocusedUIExtension(callingTokenId, abilityToken);
    if (!isFocused) {
        IMSA_HILOGE("not focused, focusedPid: %{public}" PRId64 ", callerPid: %{public}" PRId64 ", callerToken: "
                    "%{public}d",
            focusedPid, callingPid, callingTokenId);
    }
    return isFocused;
}

bool IdentityCheckerImpl::IsSystemApp(uint64_t fullTokenId)
{
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

bool IdentityCheckerImpl::IsBundleNameValid(uint32_t tokenId, const std::string &validBundleName)
{
    std::string bundleName = GetBundleNameByToken(tokenId);
    if (bundleName.empty()) {
        return false;
    }
    if (bundleName != validBundleName) {
        IMSA_HILOGE("bundleName is invalid, caller: %{public}s, current: %{public}s", bundleName.c_str(),
            validBundleName.c_str());
        return false;
    }
    IMSA_HILOGD("checked successfully.");
    return true;
}

bool IdentityCheckerImpl::HasPermission(uint32_t tokenId, const std::string &permission)
{
    if (AccessTokenKit::VerifyAccessToken(tokenId, permission) != PERMISSION_GRANTED) {
        IMSA_HILOGE("Permission [%{public}s] not granted!", permission.c_str());
        return false;
    }
    IMSA_HILOGD("verify AccessToken success.");
    return true;
}

bool IdentityCheckerImpl::IsBroker(AccessTokenID tokenId)
{
    if (!IsNativeSa(tokenId)) {
        return false;
    }
    NativeTokenInfo nativeTokenInfoRes;
    AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfoRes);
    return nativeTokenInfoRes.processName == "broker";
}

bool IdentityCheckerImpl::IsNativeSa(AccessTokenID tokenId)
{
    return AccessTokenKit::GetTokenTypeFlag(tokenId) == TypeATokenTypeEnum::TOKEN_NATIVE;
}

bool IdentityCheckerImpl::IsFormShell(AccessTokenID tokenId)
{
    return AccessTokenKit::GetTokenTypeFlag(tokenId) == TypeATokenTypeEnum::TOKEN_SHELL;
}

uint32_t IdentityCheckerImpl::GetUIExtensionWindowId(sptr<IRemoteObject> abilityToken)
{
    if (abilityToken == nullptr) {
        IMSA_HILOGD("abilityToken is nullptr");
        return INVALID_WINDOW_ID;
    }
    AAFwk::UIExtensionSessionInfo info;
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->GetUIExtensionSessionInfo(abilityToken, info);
    if (ret != ERR_OK) {
        IMSA_HILOGD("failed to GetUIExtensionSessionInfo, ret: %{public}d", ret);
        return INVALID_WINDOW_ID;
    }
    return info.hostWindowId;
}

bool IdentityCheckerImpl::IsFocusedUIExtension(uint32_t callingTokenId, sptr<IRemoteObject> abilityToken)
{
    uint32_t windowId = GetUIExtensionWindowId(abilityToken);
    if (windowId != INVALID_WINDOW_ID) {
        auto displayIdByWindow = WindowAdapter::GetDisplayIdByWindowId(windowId);
        IMSA_HILOGD("windowId is: %{public}d, displayId is %{public}" PRIu64 "", windowId, displayIdByWindow);
        if (displayIdByWindow != DEFAULT_DISPLAY_ID) {
            FocusChangeInfo focusInfo;
            WindowAdapter::GetFocusInfo(focusInfo, displayIdByWindow);
            return windowId == static_cast<uint32_t>(focusInfo.windowId_);
        }
    }

    bool isFocused = false;
    auto client = AbilityManagerClient::GetInstance();
    if (client == nullptr) {
        IMSA_HILOGE("AbilityManagerClient is nullptr");
        return false;
    }
    auto ret = client->CheckUIExtensionIsFocused(callingTokenId, isFocused);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to CheckUIExtensionIsFocused, ret: %{public}d", ret);
        return false;
    }
    IMSA_HILOGD("tokenId: %{public}d, isFocused: %{public}d", callingTokenId, isFocused);
    return isFocused;
}

std::string IdentityCheckerImpl::GetBundleNameByToken(uint32_t tokenId)
{
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType != TOKEN_HAP) {
        IMSA_HILOGE("invalid token!");
        return "";
    }
    HapTokenInfo info;
    int ret = AccessTokenKit::GetHapTokenInfo(tokenId, info);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get hap info, ret: %{public}d!", ret);
        return "";
    }
    return info.bundleName;
}

uint64_t IdentityCheckerImpl::GetDisplayIdByWindowId(int32_t callingWindowId)
{
    return WindowAdapter::GetDisplayIdByWindowId(callingWindowId);
}

uint64_t IdentityCheckerImpl::GetDisplayIdByPid(int64_t callingPid, sptr<IRemoteObject> abilityToken)
{
    uint64_t displayId = 0;
    bool ret = WindowAdapter::GetDisplayId(callingPid, displayId);
    if (ret || abilityToken == nullptr) {
        return displayId;
    }
    AAFwk::UIExtensionSessionInfo info;
    AAFwk::AbilityManagerClient::GetInstance()->GetUIExtensionSessionInfo(abilityToken, info);
    auto windowId = info.hostWindowId;
    displayId = WindowAdapter::GetDisplayIdByWindowId(windowId);
    IMSA_HILOGD("GetDisplayIdByPid displayId: %{public}" PRIu64 "", displayId);
    return displayId;
}

bool IdentityCheckerImpl::IsValidVirtualIme(int32_t callingUid)
{
    return ImeInfoInquirer::GetInstance().IsProxyIme(callingUid);
}

bool IdentityCheckerImpl::IsSpecialSaUid()
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    return ImeInfoInquirer::GetInstance().IsSpecialSaUid(callingUid);
}
} // namespace MiscServices
} // namespace OHOS