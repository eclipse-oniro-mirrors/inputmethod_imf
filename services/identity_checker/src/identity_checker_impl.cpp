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
#include "display_adapter.h"
#include "global.h"
#include "ime_info_inquirer.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "window_adapter.h"
namespace OHOS {
namespace MiscServices {
using namespace Rosen;
using namespace Security::AccessToken;
using namespace OHOS::AAFwk;

std::pair<bool, FocusedInfo> IdentityCheckerImpl::IsFocused(
    int64_t callingPid, uint32_t callingTokenId, uint32_t windowId, const sptr<IRemoteObject> &abilityToken)
{
#ifdef SCENE_BOARD_ENABLE
    std::vector<FocusChangeInfo> focusWindowInfos;
    WindowAdapter::GetAllFocusWindowInfos(focusWindowInfos);
    if (focusWindowInfos.empty()) {
        IMSA_HILOGF("focus window infos is empty!");
    }
    auto retInfo = IsFocusedUIAbility(callingPid, windowId, focusWindowInfos);
    if (retInfo.first) {
        IMSA_HILOGD("%{public}" PRId64 "/%{public}d is focused uiAbility!", callingPid, windowId);
        return retInfo;
    }
    if (ImeInfoInquirer::GetInstance().IsInputMethodExtension(callingPid)) {
        return retInfo;
    }
    retInfo = IsFocusedUIExtension(callingTokenId, abilityToken, focusWindowInfos);
    if (!retInfo.first) {
        IMSA_HILOGE("%{public}" PRId64 "/%{public}d/%{public}d is not focused!", callingPid, windowId, callingTokenId);
    }
    return retInfo;
#else
    return IsFocusedScbNotEnable(callingPid, callingTokenId, windowId, abilityToken);
#endif
}

bool IdentityCheckerImpl::IsFocusedUIExtension(uint32_t callingTokenId)
{
    std::vector<FocusChangeInfo> focusWindowInfos;
    WindowAdapter::GetAllFocusWindowInfos(focusWindowInfos);
    auto checkRet = IsFocusedUIExtension(callingTokenId, nullptr, focusWindowInfos);
    return checkRet.first;
}

std::pair<bool, FocusedInfo> IdentityCheckerImpl::IsFocusedUIAbility(
    int64_t callingPid, uint32_t windowId, const std::vector<FocusChangeInfo> &focusWindowInfos)
{
    std::pair<bool, FocusedInfo> retInfo{ false, {} };
    if (windowId != ImfCommonConst::INVALID_WINDOW_ID) {
        auto displayId = WindowAdapter::GetDisplayIdByWindowId(windowId);
        retInfo = IsFocusedUIAbility(callingPid, displayId, focusWindowInfos);
        if (retInfo.first) {
            return retInfo;
        }
    }
    return IsFocusedUIAbility(callingPid, focusWindowInfos);
}

std::pair<bool, FocusedInfo> IdentityCheckerImpl::IsFocusedUIAbility(
    int64_t callingPid, uint64_t displayId, const std::vector<FocusChangeInfo> &focusWindowInfos)
{
    auto displayGroupId = WindowAdapter::GetInstance().GetDisplayGroupId(displayId);
    std::pair<bool, FocusedInfo> retInfo{ false, {} };
    auto iter = std::find_if(
        focusWindowInfos.begin(), focusWindowInfos.end(), [callingPid, displayGroupId](const auto focusWindowInfo) {
            return focusWindowInfo.pid_ == callingPid && focusWindowInfo.displayGroupId_ == displayGroupId;
        });
    if (iter == focusWindowInfos.end()) {
        return retInfo;
    }
    retInfo.first = true;
    retInfo.second.displayId = iter->realDisplayId_;
    retInfo.second.windowId = iter->windowId_;
    retInfo.second.displayGroupId = iter->displayGroupId_;
    return retInfo;
}

std::pair<bool, FocusedInfo> IdentityCheckerImpl::IsFocusedUIAbility(
    int64_t callingPid, const std::vector<FocusChangeInfo> &focusWindowInfos)
{
    std::pair<bool, FocusedInfo> retInfo{ false, {} };
    auto iter = std::find_if(focusWindowInfos.begin(), focusWindowInfos.end(),
        [callingPid](const auto focusWindowInfo) { return focusWindowInfo.pid_ == callingPid; });
    if (iter == focusWindowInfos.end()) {
        return retInfo;
    }
    retInfo.first = true;
    retInfo.second.displayId = iter->realDisplayId_;
    retInfo.second.windowId = iter->windowId_;
    retInfo.second.displayGroupId = iter->displayGroupId_;
    return retInfo;
}
// LCOV_EXCL_START
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
// LCOV_EXCL_STOP
bool IdentityCheckerImpl::HasPermission(uint32_t tokenId, const std::string &permission)
{
    if (AccessTokenKit::VerifyAccessToken(tokenId, permission) != PERMISSION_GRANTED) {
        IMSA_HILOGE("Permission [%{public}s] not granted!", permission.c_str());
        return false;
    }
    IMSA_HILOGD("verify AccessToken success.");
    return true;
}

std::pair<bool, FocusedInfo> IdentityCheckerImpl::CheckBroker(AccessTokenID tokenId)
{
    std::pair<bool, FocusedInfo> retInfo{ false, {} };
    if (!IsBrokerInner(tokenId)) {
        return retInfo;
    }
    FocusChangeInfo focusInfo;
    WindowAdapter::GetFocusInfo(focusInfo);
    retInfo.first = true;
    retInfo.second.displayId = focusInfo.realDisplayId_;
    retInfo.second.windowId = focusInfo.windowId_;
    retInfo.second.displayGroupId = focusInfo.displayGroupId_;
    return retInfo;
}

bool IdentityCheckerImpl::IsBroker(AccessTokenID tokenId)
{
    return IsBrokerInner(tokenId);
}

bool IdentityCheckerImpl::IsBrokerInner(AccessTokenID tokenId)
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
// LCOV_EXCL_START
bool IdentityCheckerImpl::IsFormShell(AccessTokenID tokenId)
{
    return AccessTokenKit::GetTokenTypeFlag(tokenId) == TypeATokenTypeEnum::TOKEN_SHELL;
}
// LCOV_EXCL_STOP
uint32_t IdentityCheckerImpl::GetUIExtensionWindowId(sptr<IRemoteObject> abilityToken)
{
    if (abilityToken == nullptr) {
        IMSA_HILOGD("abilityToken is nullptr!");
        return INVALID_WINDOW_ID;
    }
    AAFwk::UIExtensionSessionInfo info;
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->GetUIExtensionSessionInfo(abilityToken, info);
    if (ret != ERR_OK) {
        IMSA_HILOGD("failed to GetUIExtensionSessionInfo, ret: %{public}d!", ret);
        return INVALID_WINDOW_ID;
    }
    return info.hostWindowId;
}

std::pair<bool, FocusedInfo> IdentityCheckerImpl::IsFocusedUIExtension(uint32_t callingTokenId,
    const sptr<IRemoteObject> &abilityToken, const std::vector<FocusChangeInfo> &focusWindowInfos)
{
    uint32_t windowId = GetUIExtensionWindowId(abilityToken);
    if (windowId != ImfCommonConst::INVALID_WINDOW_ID) {
        auto displayIdByWindow = WindowAdapter::GetDisplayIdByWindowId(windowId);
        IMSA_HILOGD("windowId is: %{public}d, displayId is %{public}" PRIu64 "", windowId, displayIdByWindow);
        if (displayIdByWindow != DEFAULT_DISPLAY_ID) {
            return IsFocusedUIExtension(windowId, displayIdByWindow, focusWindowInfos);
        }
    }

    std::pair<bool, FocusedInfo> retInfo{ false, {} };
    constexpr size_t MAX_FOCUS_UI_EXTENSION_CHECK_LOOP = 3;
    auto focusSize = focusWindowInfos.size();
    for (size_t i = 0; i < focusSize && i < MAX_FOCUS_UI_EXTENSION_CHECK_LOOP; i++) {
        retInfo = IsFocusedUIExtension(focusWindowInfos[i].realDisplayId_, callingTokenId, focusWindowInfos);
        if (retInfo.first) {
            IMSA_HILOGD(
                "loop %{public}zu, focus ui extension in %{public}" PRIu64 ".", i, focusWindowInfos[i].realDisplayId_);
            return retInfo;
        }
    }
    return retInfo;
}

std::pair<bool, FocusedInfo> IdentityCheckerImpl::IsFocusedUIExtension(
    uint32_t windowId, uint64_t displayId, const std::vector<FocusChangeInfo> &focusWindowInfos)
{
    std::pair<bool, FocusedInfo> retInfo{ false, {} };
    auto displayGroupId = WindowAdapter::GetInstance().GetDisplayGroupId(displayId);
    auto iter = std::find_if(
        focusWindowInfos.begin(), focusWindowInfos.end(), [displayGroupId, windowId](const auto focusWindowInfo) {
            return focusWindowInfo.displayGroupId_ == displayGroupId
                   && windowId == static_cast<uint32_t>(focusWindowInfo.windowId_);
        });
    if (iter == focusWindowInfos.end()) {
        return retInfo;
    }
    retInfo.first = true;
    retInfo.second. = iter->realDisplayId_;
    retInfo.second.windowId = iter->windowId_;
    retInfo.second.displayGroupId = iter->displayGroupId_;
    retInfo.second.uiExtensionHostPid = iter->pid_;
    return retInfo;
}

std::pair<bool, FocusedInfo> IdentityCheckerImpl::IsFocusedUIExtension(
    uint64_t displayId, uint32_t callingTokenId, const std::vector<FocusChangeInfo> &focusWindowInfos)
{
    std::pair<bool, FocusedInfo> retInfo{ false, {} };
    auto client = AbilityManagerClient::GetInstance();
    if (client == nullptr) {
        IMSA_HILOGE("AbilityManagerClient is nullptr!");
        return retInfo;
    }
    bool isFocused = false;
    auto ret = client->CheckUIExtensionIsFocused(callingTokenId, isFocused, displayId);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to CheckUIExtensionIsFocused, ret: %{public}d!", ret);
        return retInfo;
    }
    IMSA_HILOGD("tokenId: %{public}d, isFocused: %{public}d", callingTokenId, isFocused);
    if (!isFocused) {
        return retInfo;
    }
    auto iter =
        std::find_if(focusWindowInfos.begin(), focusWindowInfos.end(), [displayId](const auto &focusWindowInfo) {
            return focusWindowInfo.displayGroupId_ == WindowAdapter::GetInstance().GetDisplayGroupId(displayId);
    });
    if (iter == focusWindowInfos.end()) {
        return retInfo;
    }
    retInfo.first = true;
    retInfo.second.displayId = iter->realDisplayId_;
    retInfo.second.windowId = iter->windowId_;
    retInfo.second.displayGroupId = iter->displayGroupId_;
    retInfo.second.uiExtensionHostPid = iter->pid_;
    return retInfo;
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
// LCOV_EXCL_START
bool IdentityCheckerImpl::IsValidVirtualIme(int32_t callingUid)
{
    return ImeInfoInquirer::GetInstance().IsProxyIme(callingUid);
}

bool IdentityCheckerImpl::IsSpecialSaUid()
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    return ImeInfoInquirer::GetInstance().IsSpecialSaUid(callingUid);
}

bool IdentityCheckerImpl::IsUIExtension(int64_t pid)
{
    return ImeInfoInquirer::GetInstance().IsUIExtension(pid);
}

std::pair<bool, FocusedInfo> IdentityCheckerImpl::IsFocusedScbNotEnable(
    int64_t callingPid, uint32_t callingTokenId, uint32_t windowId, const sptr<IRemoteObject> &abilityToken)
{
    std::pair<bool, FocusedInfo> retInfo{ false, {} };
    retInfo.second.windowId = windowId;
    uint64_t displayId;
    if (abilityToken != nullptr) {
        displayId = WindowAdapter::GetDisplayIdByToken(abilityToken);
        IMSA_HILOGD("abilityToken not nullptr, displayId: %{public}" PRIu64 "", displayId);
    } else {
        displayId = WindowAdapter::GetDisplayIdByPid(callingPid);
    }
    FocusChangeInfo focusInfo;
    WindowAdapter::GetFocusInfo(focusInfo, displayId);
    auto focusedPid = focusInfo.pid_;
    if (callingPid == focusedPid) {
        IMSA_HILOGD("focused app, pid: %{public}" PRId64 ", display: %{public}" PRIu64 ",windowId: %{public}d",
            callingPid, displayId, focusInfo.windowId_);
        retInfo.first = true;
        return retInfo;
    }
    if (ImeInfoInquirer::GetInstance().IsInputMethodExtension(callingPid)) {
        return retInfo;
    }
    bool isFocused = IsFocusedUIExtension(callingTokenId, abilityToken);
    if (!isFocused) {
        IMSA_HILOGE("not focused, focusedPid: %{public}d, callerPid: %{public}" PRId64 ", callerToken: "
                    "%{public}d",
            focusedPid, callingPid, callingTokenId);
        return retInfo;
    }
    retInfo.first = true;
    return retInfo;
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
        IMSA_HILOGE("AbilityManagerClient is nullptr!");
        return false;
    }
    auto ret = client->CheckUIExtensionIsFocused(callingTokenId, isFocused);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to CheckUIExtensionIsFocused, ret: %{public}d!", ret);
        return false;
    }
    IMSA_HILOGD("tokenId: %{public}d, isFocused: %{public}d", callingTokenId, isFocused);
    return isFocused;
}
// LCOV_EXCL_STOP
} // namespace MiscServices
} // namespace OHOS