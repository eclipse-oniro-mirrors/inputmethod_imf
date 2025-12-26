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

#ifndef SERVICES_INCLUDE_IDENTITY_CHECKER_IMPL_H
#define SERVICES_INCLUDE_IDENTITY_CHECKER_IMPL_H

#include "focus_change_info.h"
#include "identity_checker.h"
namespace OHOS {
namespace MiscServices {
class IdentityCheckerImpl : public IdentityChecker {
public:
    std::pair<bool, FocusedInfo> IsFocused(int64_t callingPid, uint32_t callingTokenId, uint32_t windowId = 0,
        const sptr<IRemoteObject> &abilityToken = nullptr) override;
    bool IsSystemApp(uint64_t fullTokenId) override;
    bool IsBundleNameValid(uint32_t tokenId, const std::string &validBundleName) override;
    bool HasPermission(uint32_t tokenId, const std::string &permission) override;
    std::pair<bool, FocusedInfo> CheckBroker(Security::AccessToken::AccessTokenID tokenId) override;
    bool IsBroker(Security::AccessToken::AccessTokenID tokenId) override;
    bool IsNativeSa(Security::AccessToken::AccessTokenID tokenId) override;
    bool IsFormShell(Security::AccessToken::AccessTokenID tokenId) override;
    std::string GetBundleNameByToken(uint32_t tokenId) override;
    uint32_t GetUIExtensionWindowId(sptr<IRemoteObject> abilityToken = nullptr) override;
    bool IsFocusedUIExtension(uint32_t callingTokenId) override;
    uint64_t GetDisplayIdByWindowId(int32_t callingWindowId) override;
    uint64_t GetDisplayIdByPid(int64_t callingPid, sptr<IRemoteObject> abilityToken = nullptr) override;
    bool IsValidVirtualIme(int32_t callingUid) override;
    bool IsSpecialSaUid() override;
    bool IsUIExtension(int64_t pid) override;

private:
    std::pair<bool, FocusedInfo> IsFocusedUIAbility(
        int64_t callingPid, uint32_t windowId, const std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
    std::pair<bool, FocusedInfo> IsFocusedUIAbility(
        int64_t callingPid, uint64_t displayId, const std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
    std::pair<bool, FocusedInfo> IsFocusedUIAbility(
        int64_t callingPid, const std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
    std::pair<bool, FocusedInfo> IsFocusedUIExtension(uint32_t callingTokenId, const sptr<IRemoteObject> &abilityToken,
        const std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
    std::pair<bool, FocusedInfo> IsFocusedUIExtension(
        uint32_t windowId, uint64_t displayId, const std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
    std::pair<bool, FocusedInfo> IsFocusedUIExtension(
        uint64_t displayId, uint32_t callingTokenId, const std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
    bool IsBrokerInner(Security::AccessToken::AccessTokenID tokenId);
    std::pair<bool, FocusedInfo> IsFocusedScbNotEnable(
        int64_t callingPid, uint32_t callingTokenId, uint32_t windowId, const sptr<IRemoteObject> &abilityToken);
    bool IsFocusedUIExtension(uint32_t callingTokenId, sptr<IRemoteObject> abilityToken);
    FocusedInfo GenerateFocusInfo(
        const Rosen::FocusChangeInfo &focusWindowInfo, const std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
};
} // namespace MiscServices
} // namespace OHOS

#endif // SERVICES_INCLUDE_IDENTITY_CHECKER_IMPL_H
