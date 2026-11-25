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

#include "inputmethodabilityrichptt_fuzzer.h"

#include <utility>

#include "input_method_ability.h"

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

void TestGetRichBeforeCursor(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    RichTextData richText;
    InputMethodAbility::GetInstance().GetRichBeforeCursor(fuzzedInt32, richText);
}

void TestGetRichAfterCursor(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    RichTextData richText;
    InputMethodAbility::GetInstance().GetRichAfterCursor(fuzzedInt32, richText);
}

void TestOnPttLongPress(FuzzedDataProvider &provider)
{
    InputMethodAbility::GetInstance().OnPttLongPress();
}

void TestOnPttGestureCancelled(FuzzedDataProvider &provider)
{
    InputMethodAbility::GetInstance().OnPttGestureCancelled();
}

void TestDispatchKeyEventPttSpace(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    auto keyEvent = MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(MMI::KeyEvent::KEYCODE_SPACE);
    int32_t action = provider.ConsumeIntegralInRange<int32_t>(0, 1);
    keyEvent->SetKeyAction(action == 0 ? MMI::KeyEvent::KEY_ACTION_DOWN : MMI::KeyEvent::KEY_ACTION_UP);
    InputMethodAbility::GetInstance().DispatchKeyEvent(keyEvent, fuzzedInt32, nullptr);
}

void TestNotifyPanelStatusDetached(FuzzedDataProvider &provider)
{
    bool isUseParameterFlag = provider.ConsumeBool();
    bool isCheckFuncButton = provider.ConsumeBool();
    InputMethodAbility::GetInstance().NotifyPanelStatus(isUseParameterFlag, FLG_DETACHED, isCheckFuncButton);
}

void TestNotifyKeyboardHeightDetached(FuzzedDataProvider &provider)
{
    uint32_t fuzzedUint32 = provider.ConsumeIntegral<uint32_t>();
    InputMethodAbility::GetInstance().NotifyKeyboardHeight(fuzzedUint32, FLG_DETACHED);
}

void TestSendMessage(FuzzedDataProvider &provider)
{
    ArrayBuffer arrayBuffer;
    arrayBuffer.jsArgc = provider.ConsumeIntegral<size_t>();
    arrayBuffer.msgId = provider.ConsumeRandomLengthString(32);
    size_t paramLen = provider.ConsumeIntegralInRange<size_t>(0, 256);
    for (size_t i = 0; i < paramLen; i++) {
        arrayBuffer.msgParam.push_back(provider.ConsumeIntegral<uint8_t>());
    }
    InputMethodAbility::GetInstance().SendMessage(arrayBuffer);
}

void TestRecvMessage(FuzzedDataProvider &provider)
{
    ArrayBuffer arrayBuffer;
    arrayBuffer.jsArgc = provider.ConsumeIntegral<size_t>();
    arrayBuffer.msgId = provider.ConsumeRandomLengthString(32);
    size_t paramLen = provider.ConsumeIntegralInRange<size_t>(0, 256);
    for (size_t i = 0; i < paramLen; i++) {
        arrayBuffer.msgParam.push_back(provider.ConsumeIntegral<uint8_t>());
    }
    InputMethodAbility::GetInstance().RecvMessage(arrayBuffer);
}

void TestIsCapacitySupport(FuzzedDataProvider &provider)
{
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    bool isSupport = false;
    InputMethodAbility::GetInstance().IsCapacitySupport(fuzzedInt32, isSupport);
}

void TestHandleKeyEventResult(FuzzedDataProvider &provider)
{
    uint64_t fuzzedUint64 = provider.ConsumeIntegral<uint64_t>();
    bool consumeResult = provider.ConsumeBool();
    InputMethodAbility::GetInstance().HandleKeyEventResult(fuzzedUint64, consumeResult, nullptr);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TestGetRichBeforeCursor(provider);
    OHOS::TestGetRichAfterCursor(provider);
    OHOS::TestOnPttLongPress(provider);
    OHOS::TestOnPttGestureCancelled(provider);
    OHOS::TestDispatchKeyEventPttSpace(provider);
    OHOS::TestNotifyPanelStatusDetached(provider);
    OHOS::TestNotifyKeyboardHeightDetached(provider);
    OHOS::TestSendMessage(provider);
    OHOS::TestRecvMessage(provider);
    OHOS::TestIsCapacitySupport(provider);
    OHOS::TestHandleKeyEventResult(provider);
    return 0;
}
