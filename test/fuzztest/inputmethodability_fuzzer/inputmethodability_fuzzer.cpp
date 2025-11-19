/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "inputmethodability_fuzzer.h"

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
class KeyboardListenerImpl : public KeyboardListener {
    bool OnKeyEvent(int32_t keyCode, int32_t keyStatus, sptr<KeyEventConsumerProxy> &consumer)
    {
        return true;
    }
    bool OnKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, sptr<KeyEventConsumerProxy> &consumer)
    {
        return true;
    }
    bool OnDealKeyEvent(
        const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId, const sptr<IRemoteObject> &channelObject)
    {
        return true;
    }
    void OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height) { }
    void OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd) { }
    void OnTextChange(const std::string &text) { }
    void OnEditorAttributeChange(const InputAttribute &inputAttribute) { }
};

bool InitializeClientInfo(InputClientInfo &clientInfo)
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

void TestInsertText(FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    InputMethodAbility::GetInstance().InsertText(fuzzedString);
}

void TestDeleteForward(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    InputMethodAbility::GetInstance().DeleteForward(fuzzedInt32);
}

void TestDeleteBackward(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    InputMethodAbility::GetInstance().DeleteBackward(fuzzedInt32);
}

void TestSendExtendAction(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    InputMethodAbility::GetInstance().SendExtendAction(fuzzedInt32);
}

void TestGetTextBeforeCursor(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    std::u16string text;
    InputMethodAbility::GetInstance().GetTextBeforeCursor(fuzzedInt32, text);
}

void TestGetTextAfterCursor(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    std::u16string text;
    InputMethodAbility::GetInstance().GetTextAfterCursor(fuzzedInt32, text);
}

void TestSendFunctionKey(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    InputMethodAbility::GetInstance().SendFunctionKey(fuzzedInt32);
}

void TestMoveCursor(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    InputMethodAbility::GetInstance().MoveCursor(fuzzedInt32);
}

void TestDispatchKeyEvent(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(fuzzedInt32);
    keyEvent->SetKeyAction(fuzzedInt32);
    InputMethodAbility::GetInstance().DispatchKeyEvent(keyEvent, fuzzedInt32, nullptr);
}

void TestSetCallingWindow(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    InputMethodAbility::GetInstance().SetCallingWindow(fuzzedInt32);
}

void TestCallingDisplayIdChanged(FuzzedDataProvider &provider)
{
    uint64_t fuzzedUint64 = provider.ConsumeIntegral<uint64_t>();
    InputMethodAbility::GetInstance().OnCallingDisplayIdChanged(fuzzedUint64);
}

void TestRegisterProxyIme(FuzzedDataProvider &provider)
{
    uint64_t fuzzedUint64 = provider.ConsumeIntegral<uint64_t>();
    InputMethodAbility::GetInstance().RegisterProxyIme(fuzzedUint64);
}

void TestUnregisterProxyIme(FuzzedDataProvider &provider)
{
    uint64_t fuzzedUint64 = provider.ConsumeIntegral<uint64_t>();
    InputMethodAbility::GetInstance().UnregisterProxyIme(fuzzedUint64);
}

void TestStartInput(FuzzedDataProvider &provider)
{
    InputClientInfo clientInfo;
    if (!OHOS::InitializeClientInfo(clientInfo)) {
        return;
    }
    bool isBindFromClient = provider.ConsumeBool();
    InputMethodAbility::GetInstance().StartInput(clientInfo, isBindFromClient);
}

void TestIsDisplayChanged(FuzzedDataProvider &provider)
{
    uint64_t oldDisplayId = provider.ConsumeIntegral<uint64_t>();
    uint64_t newDisplayId = provider.ConsumeIntegral<uint64_t>();
    InputMethodAbility::GetInstance().IsDisplayChanged(oldDisplayId, newDisplayId);
}

void TestOnSelectionChange(FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string text(fuzzedString.begin(), fuzzedString.end());
    int32_t oldBegin = provider.ConsumeIntegral<int32_t>();
    int32_t oldEnd = provider.ConsumeIntegral<int32_t>();
    int32_t newBegin = provider.ConsumeIntegral<int32_t>();
    int32_t newEnd = provider.ConsumeIntegral<int32_t>();
    InputMethodAbility::GetInstance().OnSelectionChange(text, oldBegin, oldEnd, newBegin, newEnd);
}

void TestOperationKeyboard(FuzzedDataProvider &provider)
{
    int32_t cmdId = provider.ConsumeIntegral<int32_t>();
    uint32_t sessionId = provider.ConsumeIntegral<uint32_t>();
    InputMethodAbility::GetInstance().HideKeyboardImplWithoutLock(cmdId, sessionId);
    InputMethodAbility::GetInstance().ShowKeyboardImplWithLock(cmdId);
}

void TestInterfaceCoverage(FuzzedDataProvider &provider)
{
    int32_t dataInt32 = provider.ConsumeIntegral<int32_t>();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string text(fuzzedString.begin(), fuzzedString.end());
    InputMethodAbility::GetInstance().SelectByMovement(dataInt32);
    InputMethodAbility::GetInstance().GetEnterKeyType(dataInt32);
    InputMethodAbility::GetInstance().GetSecurityMode(dataInt32);
    InputMethodAbility::GetInstance().GetTextBeforeCursor(dataInt32, text);
}

void TestImeMirrorManager(FuzzedDataProvider &provider)
{
    ImeMirrorManager mgr;
    mgr.SetImeMirrorEnable(provider.ConsumeBool());
    mgr.IsImeMirrorEnable();
    mgr.SubscribeSaStart([]() { }, provider.ConsumeIntegral<int32_t>());
    mgr.UnSubscribeSaStart(provider.ConsumeIntegral<int32_t>());

    InputMethodAbility::GetInstance().BindImeMirror();
    InputMethodAbility::GetInstance().UnbindImeMirror();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TestInsertText(provider);
    OHOS::TestDeleteForward(provider);
    OHOS::TestDeleteBackward(provider);
    OHOS::TestSendExtendAction(provider);

    OHOS::TestGetTextBeforeCursor(provider);
    OHOS::TestGetTextAfterCursor(provider);

    OHOS::TestSendFunctionKey(provider);
    OHOS::TestMoveCursor(provider);

    OHOS::TestDispatchKeyEvent(provider);

    OHOS::TestSetCallingWindow(provider);

    OHOS::TestCallingDisplayIdChanged(provider);
    OHOS::TestRegisterProxyIme(provider);
    OHOS::TestUnregisterProxyIme(provider);
    OHOS::TestStartInput(provider);
    OHOS::TestIsDisplayChanged(provider);
    OHOS::TestOnSelectionChange(provider);
    OHOS::TestOperationKeyboard(provider);
    OHOS::TestInterfaceCoverage(provider);
    OHOS::TestImeMirrorManager(provider);
    return 0;
}