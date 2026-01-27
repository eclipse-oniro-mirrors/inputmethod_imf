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
    InputMethodAbility::GetInstance().SetCallingWindow(fuzzedInt32, fuzzedInt32);
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
    return 0;
}