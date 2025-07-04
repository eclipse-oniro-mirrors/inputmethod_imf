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

#ifndef SERVICES_INCLUDE_IDENTITY_CHECKER_H
#define SERVICES_INCLUDE_IDENTITY_CHECKER_H

#include "access_token.h"
#include "iremote_object.h"
namespace OHOS {
namespace MiscServices {
class IdentityChecker {
public:
    static constexpr uint64_t DEFAULT_DISPLAY_ID = 0;
    static constexpr int64_t INVALID_PID = -1;
    virtual ~IdentityChecker() = default;
    virtual bool IsFocused(int64_t callingPid, uint32_t callingTokenId, int64_t focusedPid = INVALID_PID,
        bool isAttach = false, sptr<IRemoteObject> abilityToken = nullptr) = 0;
    virtual bool IsSystemApp(uint64_t fullTokenId) = 0;
    virtual bool IsBundleNameValid(uint32_t tokenId, const std::string &validBundleName) = 0;
    virtual bool HasPermission(uint32_t tokenId, const std::string &permission) = 0;
    virtual bool IsBroker(Security::AccessToken::AccessTokenID tokenId) = 0;
    virtual bool IsNativeSa(Security::AccessToken::AccessTokenID tokenId) = 0;
    virtual bool IsFormShell(Security::AccessToken::AccessTokenID tokenId) = 0;
    virtual std::string GetBundleNameByToken(uint32_t tokenId);
    virtual bool IsFocusedUIExtension(uint32_t callingTokenId, sptr<IRemoteObject> abilityToken = nullptr)
    {
        return false;
    };
    virtual uint64_t GetDisplayIdByWindowId(int32_t callingWindowId)
    {
        return DEFAULT_DISPLAY_ID;
    };
    virtual uint64_t GetDisplayIdByPid(int64_t callingPid, sptr<IRemoteObject> abilityToken = nullptr)
    {
        return DEFAULT_DISPLAY_ID;
    };
    virtual bool IsValidVirtualIme(int32_t callingUid)
    {
        return false;
    };
    virtual bool IsSpecialSaUid() = 0;
};
} // namespace MiscServices
} // namespace OHOS

#endif // SERVICES_INCLUDE_IDENTITY_CHECKER_H
