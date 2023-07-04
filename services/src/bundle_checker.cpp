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
#include "bundle_checker.h"

#include <cinttypes>

#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "global.h"
#include "tokenid_kit.h"
#include "window_manager.h"

namespace OHOS {
namespace MiscServices {
using namespace Rosen;
using namespace Security::AccessToken;
bool BundleChecker::IsFocused(int64_t callingPid, uint32_t callingTokenId, int64_t focusedPid)
{
    if (focusedPid == INVALID_PID) {
        FocusChangeInfo info;
        WindowManager::GetInstance().GetFocusWindowInfo(info);
        focusedPid = info.pid_;
    }
    IMSA_HILOGD("focusedPid:%{public}" PRId64 ", pid:%{public}" PRId64 "", focusedPid, callingPid);
    if (callingPid == focusedPid) {
        IMSA_HILOGI("pid is same, focused app");
        return true;
    }
    bool isFocused = false;
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->CheckUIExtensionIsFocused(callingTokenId, isFocused);
    IMSA_HILOGI("tokenId:%{public}d check result:%{public}d, isFocused:%{public}d", callingTokenId, ret, isFocused);
    return ret == ErrorCode::NO_ERROR && isFocused;
}

bool BundleChecker::IsSystemApp(uint64_t fullTokenID)
{
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenID);
}

bool BundleChecker::IsCurrentIme(uint32_t tokenID, const std::string &currentIme)
{
    std::string bundleName = GetBundleNameByToken(tokenID);
    if (bundleName.empty()) {
        return false;
    }
    if (bundleName != currentIme) {
        IMSA_HILOGE(
            "not current ime, caller: %{public}s, current ime: %{public}s", bundleName.c_str(), currentIme.c_str());
        return false;
    }
    IMSA_HILOGD("checked ime successfully");
    return true;
}

bool BundleChecker::CheckPermission(uint32_t tokenID, const std::string &permission)
{
    if (AccessTokenKit::VerifyAccessToken(tokenID, permission) != PERMISSION_GRANTED) {
        IMSA_HILOGE("Permission [%{public}s] not granted", permission.c_str());
        return false;
    }
    IMSA_HILOGD("verify AccessToken success");
    return true;
}

std::string BundleChecker::GetBundleNameByToken(uint32_t tokenID)
{
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenID);
    if (tokenType != TOKEN_HAP) {
        IMSA_HILOGE("invalid token");
        return "";
    }
    HapTokenInfo info;
    int ret = AccessTokenKit::GetHapTokenInfo(tokenID, info);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get hap info, ret: %{public}d", ret);
        return "";
    }
    return info.bundleName;
}
} // namespace MiscServices
} // namespace OHOS
