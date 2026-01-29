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

#include "inputmethodabilitytwo_fuzzer.h"

#include <utility>

#define private public
#define protected public
#include "input_method_ability.h"
#undef private

#include "fuzzer/FuzzedDataProvider.h"
#include "input_client_service_impl.h"
#include "input_method_engine_listener_impl.h"
#include "ime_mirror_manager.h"

using namespace OHOS::MiscServices;
namespace OHOS {
constexpr int32_t MAIN_USER_ID = 100;
bool InitializeClientInfo(InputClientInfo &clientInfo) __attribute__((no_sanitize("cfi")))
{
    sptr<IInputClient> clientStub = new (std::nothrow) InputClientServiceImpl();
    if (clientStub == nullptr) {
        IMSA_HILOGE("failed to create client");
        return false;
    }
    sptr<InputDeathRecipient> deathRecipient = new (std::nothrow) InputDeathRecipient();
    if (deathRecipient == nullptr) {
        IMSA_HILOGE("failed to new deathRecipient");
        return false;
    }
    clientInfo = { .userID = MAIN_USER_ID, .client = clientStub, .deathRecipient = deathRecipient };
    return true;
}

void TestCallingDisplayIdChanged(FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    uint64_t fuzzedUint64 = provider.ConsumeIntegral<uint64_t>();
    InputMethodAbility::GetInstance().OnCallingDisplayIdChanged(fuzzedUint64);
}

void TestUnregisterProxyIme(FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    uint64_t fuzzedUint64 = provider.ConsumeIntegral<uint64_t>();
    InputMethodAbility::GetInstance().UnregisterProxyIme(fuzzedUint64);
}

void TestStartInput(FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    InputClientInfo clientInfo;
    if (!OHOS::InitializeClientInfo(clientInfo)) {
        return;
    }
    bool isBindFromClient = provider.ConsumeBool();
    InputMethodAbility::GetInstance().StartInput(clientInfo, isBindFromClient);
}

void TestIsDisplayChanged(FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    uint64_t oldDisplayId = provider.ConsumeIntegral<uint64_t>();
    uint64_t newDisplayId = provider.ConsumeIntegral<uint64_t>();
    InputMethodAbility::GetInstance().IsDisplayChanged(oldDisplayId, newDisplayId);
}

void TestOnSelectionChange(FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string text(fuzzedString.begin(), fuzzedString.end());
    int32_t oldBegin = provider.ConsumeIntegral<int32_t>();
    int32_t oldEnd = provider.ConsumeIntegral<int32_t>();
    int32_t newBegin = provider.ConsumeIntegral<int32_t>();
    int32_t newEnd = provider.ConsumeIntegral<int32_t>();
    InputMethodAbility::GetInstance().OnSelectionChange(text, oldBegin, oldEnd, newBegin, newEnd);
}

void TestOperationKeyboard(FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    int32_t cmdId = provider.ConsumeIntegral<int32_t>();
    uint32_t sessionId = provider.ConsumeIntegral<uint32_t>();
    InputMethodAbility::GetInstance().HideKeyboardImplWithoutLock(cmdId, sessionId);
    InputMethodAbility::GetInstance().ShowKeyboardImplWithLock(cmdId);
}

void TestInterfaceCoverage(FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    int32_t dataInt32 = provider.ConsumeIntegral<int32_t>();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string text(fuzzedString.begin(), fuzzedString.end());
    InputMethodAbility::GetInstance().SelectByMovement(dataInt32);
    InputMethodAbility::GetInstance().GetEnterKeyType(dataInt32);
    InputMethodAbility::GetInstance().GetSecurityMode(dataInt32);
    InputMethodAbility::GetInstance().GetTextBeforeCursor(dataInt32, text);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);

    OHOS::TestCallingDisplayIdChanged(provider);
    OHOS::TestUnregisterProxyIme(provider);
    OHOS::TestStartInput(provider);
    OHOS::TestIsDisplayChanged(provider);
    OHOS::TestOnSelectionChange(provider);
    OHOS::TestOperationKeyboard(provider);
    OHOS::TestInterfaceCoverage(provider);
    return 0;
}