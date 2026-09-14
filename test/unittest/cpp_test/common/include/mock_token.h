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

#ifndef MOCK_TOKEN_H
#define MOCK_TOKEN_H

#include <mutex>
#include <string>
#include <vector>

#include "accesstoken_kit.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::Security::AccessToken;

class MockToken {
public:
    static constexpr int32_t DEFAULT_API_VERSION = 12;

    static void SetTestEnvironment(uint64_t shellTokenId);
    static void ResetTestEnvironment();
    static uint64_t GetShellTokenId();
    static uint64_t GetNativeTokenIdFromProcess(const std::string &process);
    static uint64_t AllocTestHapToken(
        const std::string &bundle, const std::vector<std::string> &reqPerm, bool isSystemApp = false);
    static int32_t DeleteTestHapToken(uint64_t tokenID);
    static int32_t GrantPermissionByTest(uint64_t tokenID, const std::string &permission, uint32_t flag = 1);
    static int32_t RevokePermissionByTest(uint64_t tokenID, const std::string &permission, uint32_t flag = 1);

private:
    static std::mutex g_lockSetToken_;
    static uint64_t g_shellTokenId_;
};

class MockNativeToken {
public:
    explicit MockNativeToken(const std::string &process);
    ~MockNativeToken();

private:
    uint64_t selfToken_{ 0 };
};

class MockHapToken {
public:
    MockHapToken(const std::string &bundle, const std::vector<std::string> &reqPerm, bool isSystemApp = false);
    ~MockHapToken();
    uint64_t GetTokenID() const { return mockToken_; }

private:
    uint64_t selfToken_{ 0 };
    AccessTokenID mockToken_{ 0 };
};
} // namespace MiscServices
} // namespace OHOS
#endif // MOCK_TOKEN_H
