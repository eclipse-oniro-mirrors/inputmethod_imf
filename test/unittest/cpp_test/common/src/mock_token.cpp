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

#include "mock_token.h"

#include <sstream>

#include "global.h"
#include "hap_token_info.h"
#include "token_setproc.h"

namespace {
inline void CheckSetToken(int ret)
{
    if (ret != 0) {
        IMSA_HILOGE("SetSelfTokenID failed, ret: %{public}d", ret);
    }
}
} // namespace

namespace OHOS {
namespace MiscServices {
using namespace OHOS::Security::AccessToken;

std::mutex MockToken::g_lockSetToken_;
uint64_t MockToken::g_shellTokenId_ = 0;

void MockToken::SetTestEnvironment(uint64_t shellTokenId)
{
    std::lock_guard<std::mutex> lock(g_lockSetToken_);
    g_shellTokenId_ = shellTokenId;
}

void MockToken::ResetTestEnvironment()
{
    std::lock_guard<std::mutex> lock(g_lockSetToken_);
    g_shellTokenId_ = 0;
}

uint64_t MockToken::GetShellTokenId()
{
    std::lock_guard<std::mutex> lock(g_lockSetToken_);
    return g_shellTokenId_;
}

uint64_t MockToken::GetNativeTokenIdFromProcess(const std::string &process)
{
    uint64_t selfTokenId = GetSelfTokenID();
    CheckSetToken(SetSelfTokenID(MockToken::GetShellTokenId())); // set shell token

    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = process;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        SetSelfTokenID(selfTokenId);
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }
    // restore
    CheckSetToken(SetSelfTokenID(selfTokenId));

    std::istringstream iss(numStr);
    AccessTokenID tokenID;
    iss >> tokenID;
    return tokenID;
}

uint64_t MockToken::AllocTestHapToken(
    const std::string &bundle, const std::vector<std::string> &reqPerm, bool isSystemApp)
{
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = bundle,
        .instIndex = 0,
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = MockToken::DEFAULT_API_VERSION,
        .isSystemApp = isSystemApp,
        .appDistributionType = "",
    };

    HapPolicyParams policyParams = {
        .apl = APL_NORMAL,
        .domain = "accesstoken_test_domain",
    };
    for (size_t i = 0; i < reqPerm.size(); ++i) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(reqPerm[i], permDefResult) != RET_SUCCESS) {
            continue;
        }
        PermissionStateFull permState = { .permissionName = reqPerm[i],
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 } };
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(reqPerm[i]);
        }
    }

    AccessTokenIDEx tokenIdEx = { 0 };
    uint64_t selfTokenId = GetSelfTokenID();
    if (MockToken::GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        AccessTokenKit::InitHapToken(infoParams, policyParams, tokenIdEx);
    } else {
        // set sh token for self
        MockNativeToken mock("foundation");
        AccessTokenKit::InitHapToken(infoParams, policyParams, tokenIdEx);
        // restore
        CheckSetToken(SetSelfTokenID(selfTokenId));
    }
    return tokenIdEx.tokenIDEx;
}

int32_t MockToken::DeleteTestHapToken(uint64_t tokenID)
{
    AccessTokenID accessTokenId = static_cast<AccessTokenID>(tokenID & 0xFFFFFFFF);
    uint64_t selfTokenId = GetSelfTokenID();
    if (MockToken::GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return AccessTokenKit::DeleteToken(accessTokenId);
    }

    // set sh token for self
    MockNativeToken mock("foundation");
    int32_t ret = AccessTokenKit::DeleteToken(accessTokenId);
    // restore
    CheckSetToken(SetSelfTokenID(selfTokenId));
    return ret;
}

int32_t MockToken::GrantPermissionByTest(uint64_t tokenID, const std::string &permission, uint32_t flag)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    MockHapToken mock("AccessTokenTestGrant", reqPerm);
    return AccessTokenKit::GrantPermission(static_cast<AccessTokenID>(tokenID), permission, flag);
}

int32_t MockToken::RevokePermissionByTest(uint64_t tokenID, const std::string &permission, uint32_t flag)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    MockHapToken mock("AccessTokenTestRevoke", reqPerm);
    return AccessTokenKit::RevokePermission(static_cast<AccessTokenID>(tokenID), permission, flag);
}

MockNativeToken::MockNativeToken(const std::string &process)
{
    selfToken_ = GetSelfTokenID();
    uint64_t tokenId = MockToken::GetNativeTokenIdFromProcess(process);
    SetSelfTokenID(tokenId);
}

MockNativeToken::~MockNativeToken()
{
    SetSelfTokenID(selfToken_);
}

MockHapToken::MockHapToken(const std::string &bundle, const std::vector<std::string> &reqPerm, bool isSystemApp)
{
    selfToken_ = GetSelfTokenID();
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = bundle,
        .instIndex = 0,
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = MockToken::DEFAULT_API_VERSION,
        .isSystemApp = isSystemApp,
        .appDistributionType = "",
    };

    HapPolicyParams policyParams = {
        .apl = APL_NORMAL,
        .domain = "accesstoken_test_domain",
    };
    for (size_t i = 0; i < reqPerm.size(); ++i) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(reqPerm[i], permDefResult) != RET_SUCCESS) {
            continue;
        }
        PermissionStateFull permState = { .permissionName = reqPerm[i],
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 } };
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(reqPerm[i]);
        }
    }

    AccessTokenIDEx tokenIdEx = { 0 };
    uint64_t selfTokenId = GetSelfTokenID();
    if (MockToken::GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        AccessTokenKit::InitHapToken(infoParams, policyParams, tokenIdEx);
    } else {
        MockNativeToken mock("foundation");
        AccessTokenKit::InitHapToken(infoParams, policyParams, tokenIdEx);
        CheckSetToken(SetSelfTokenID(selfTokenId));
    }
    mockToken_ = tokenIdEx.tokenIdExStruct.tokenID;
    if (mockToken_ == INVALID_TOKENID) {
        IMSA_HILOGE("AllocTestHapToken failed, mockToken_ is INVALID_TOKENID");
    }
    CheckSetToken(SetSelfTokenID(tokenIdEx.tokenIDEx));
}

MockHapToken::~MockHapToken()
{
    if (mockToken_ != INVALID_TOKENID) {
        int32_t ret = MockToken::DeleteTestHapToken(mockToken_);
        if (ret != 0) {
            IMSA_HILOGE("DeleteTestHapToken failed, ret: %{public}d", ret);
        }
    }
    CheckSetToken(SetSelfTokenID(selfToken_));
}
} // namespace MiscServices
} // namespace OHOS
