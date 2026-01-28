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
#define private public
#define protected public
#include "input_method_controller.h"
#include "input_method_system_ability_proxy.h"
#include "input_client_service_impl.h"
#undef private

#include "inputmethodcontrollertwo_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "input_attribute.h"
#include "key_event.h"
#include "message_parcel.h"
#include "text_listener.h"

using namespace OHOS::MiscServices;
namespace OHOS {
class EventHandlerTextListenerImpl : public TextListener {
public:
    explicit EventHandlerTextListenerImpl(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
    {
        listenerEventHandler_ = handler;
    }
    std::shared_ptr<AppExecFwk::EventHandler> GetEventHandler()
    {
        return listenerEventHandler_;
    }

private:
    std::shared_ptr<AppExecFwk::EventHandler> listenerEventHandler_{ nullptr };
};
constexpr int32_t PRIVATEDATAVALUE = 100;
void TestListInputMethod(sptr<InputMethodController> imc,
    FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    sptr<OnTextChangedListener> textListener = new TextListener();
    if (textListener == nullptr || imc == nullptr) {
        return;
    }
    imc->Attach(textListener);
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string fuzzedU16String(fuzzedString.begin(), fuzzedString.end());
    auto length = provider.ConsumeIntegral<uint32_t>();
    auto start = provider.ConsumeIntegral<int32_t>();
    auto end = provider.ConsumeIntegral<int32_t>();
    auto index = provider.ConsumeIntegral<int32_t>();
    imc->OnSelectionChange(fuzzedU16String, start, end);
    imc->GetLeft(length, fuzzedU16String);
    imc->GetTextIndexAtCursor(index);
}

void FUZZOnTextChangedListener(FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string fuzzedU16String(fuzzedString.begin(), fuzzedString.end());
    auto fuzzInt32 = provider.ConsumeIntegral<int32_t>();
    auto fuzzBool = provider.ConsumeBool();
    FunctionKey key;
    KeyEvent keyEvent;
    Range range = { .start = fuzzInt32, .end = fuzzInt32};
    PanelInfo panelInfo;
    panelInfo.panelType = static_cast<PanelType>(fuzzBool);
    panelInfo.panelFlag = static_cast<PanelFlag>(fuzzBool);
    PanelStatusInfo panelStatusInfo;
    panelStatusInfo.panelInfo = panelInfo;
    panelStatusInfo.visible = fuzzBool;
    panelStatusInfo.trigger = Trigger::IME_APP;
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("eventHandlerTextListener");
    auto handler = std::make_shared<AppExecFwk::EventHandler>(runner);
    sptr<OnTextChangedListener> eventHandlerTextListener = new (std::nothrow) EventHandlerTextListenerImpl(handler);
    if (eventHandlerTextListener == nullptr) {
        return;
    }
    std::unordered_map <std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = fuzzedString;
    PrivateDataValue privateDataValue2 = static_cast<int32_t>(fuzzBool);
    PrivateDataValue privateDataValue3 = PRIVATEDATAVALUE;
    privateCommand.emplace("value1", privateDataValue1);
    privateCommand.emplace("value2", privateDataValue2);
    privateCommand.emplace("value3", privateDataValue3);
    eventHandlerTextListener->InsertTextV2(fuzzedU16String);
    eventHandlerTextListener->DeleteForwardV2(fuzzInt32);
    eventHandlerTextListener->DeleteBackwardV2(fuzzInt32);
    eventHandlerTextListener->SendKeyboardStatusV2(KeyboardStatus::SHOW);
    eventHandlerTextListener->SendFunctionKeyV2(key);
    eventHandlerTextListener->MoveCursorV2(Direction::DOWN);
    eventHandlerTextListener->HandleExtendActionV2(fuzzInt32);
    eventHandlerTextListener->GetLeftTextOfCursorV2(fuzzInt32);
    eventHandlerTextListener->GetRightTextOfCursorV2(fuzzInt32);
    eventHandlerTextListener->GetTextIndexAtCursorV2();
    eventHandlerTextListener->SendKeyEventFromInputMethodV2(keyEvent);
    eventHandlerTextListener->SetKeyboardStatusV2(fuzzBool);
    eventHandlerTextListener->HandleSetSelectionV2(fuzzInt32, fuzzInt32);
    eventHandlerTextListener->HandleSelectV2(fuzzInt32, fuzzInt32);
    eventHandlerTextListener->NotifyPanelStatusInfoV2(panelStatusInfo);
    eventHandlerTextListener->NotifyKeyboardHeightV2(fuzzInt32);
    eventHandlerTextListener->SetPreviewTextV2(fuzzedU16String, range);
}

void FUZZCovered(sptr<InputMethodController> imc, FuzzedDataProvider &provider) __attribute__((no_sanitize("cfi")))
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::vector<uint8_t> msgParam;
    auto data = provider.ConsumeIntegral<uint8_t>();
    msgParam.push_back(data);
    ArrayBuffer arrayBuffer;
    arrayBuffer.jsArgc = msgParam.size();
    arrayBuffer.msgId = fuzzedString;
    arrayBuffer.msgParam = msgParam;
    imc->SendMessage(arrayBuffer);
    imc->RecvMessage(arrayBuffer);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr || size == 0) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);

    OHOS::sptr<InputMethodController> imc = InputMethodController::GetInstance();

    OHOS::TestListInputMethod(imc, provider);
    OHOS::FUZZOnTextChangedListener(provider);
    OHOS::FUZZCovered(imc, provider);
    return 0;
}
