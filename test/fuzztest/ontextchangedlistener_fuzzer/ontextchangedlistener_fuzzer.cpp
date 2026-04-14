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

#include "input_method_controller.h"

#include "ontextchangedlistener_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "event_handler.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "input_method_utils.h"
#include "text_listener.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace {
constexpr int32_t PRIVATE_DATA_VALUE = 100;
constexpr int32_t FUZZER_SUCCESS = 0;

std::shared_ptr<AppExecFwk::EventHandler> CreateFuzzEventHandler()
{
    static std::shared_ptr<AppExecFwk::EventRunner> runner =
        AppExecFwk::EventRunner::Create("fuzzTextListenerHandler");
    if (runner == nullptr) {
        return nullptr;
    }
    return std::make_shared<AppExecFwk::EventHandler>(runner);
}
}

class FuzzTextListener : public TextListener {
public:
    explicit FuzzTextListener(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
    {
        eventHandler_ = handler;
    }

    bool IsFromTs() override
    {
        return isFromTs_;
    }

    std::shared_ptr<AppExecFwk::EventHandler> GetEventHandler() override
    {
        return eventHandler_;
    }

    void SetIsFromTs(bool isFromTs)
    {
        isFromTs_ = isFromTs;
    }

private:
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_{ nullptr };
    bool isFromTs_{ false };
};

void FuzzFinishTextPreview(sptr<FuzzTextListener> listener)
{
    listener->FinishTextPreview();
}

void FuzzOnDetach(sptr<FuzzTextListener> listener)
{
    listener->OnDetach();
}

void FuzzIsFromTs(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    auto fuzzedBool = provider.ConsumeBool();
    listener->SetIsFromTs(fuzzedBool);
    listener->IsFromTs();
}

void FuzzGetEventHandler(sptr<FuzzTextListener> listener)
{
    listener->GetEventHandler();
}

void FuzzNotifyPanelStatusInfo(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    auto fuzzedBool = provider.ConsumeBool();
    PanelInfo panelInfo;
    panelInfo.panelType = static_cast<PanelType>(fuzzedBool);
    panelInfo.panelFlag = static_cast<PanelFlag>(fuzzedBool);
    PanelStatusInfo panelStatusInfo;
    panelStatusInfo.panelInfo = panelInfo;
    panelStatusInfo.visible = fuzzedBool;
    panelStatusInfo.trigger = Trigger::IME_APP;
    listener->NotifyPanelStatusInfo(panelStatusInfo);
}

void FuzzNotifyKeyboardHeight(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    auto fuzzedHeight = provider.ConsumeIntegral<uint32_t>();
    listener->NotifyKeyboardHeight(fuzzedHeight);
}

void FuzzReceivePrivateCommand(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    auto fuzzedBool = provider.ConsumeBool();
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = fuzzedString;
    PrivateDataValue privateDataValue2 = static_cast<int32_t>(fuzzedBool);
    PrivateDataValue privateDataValue3 = PRIVATE_DATA_VALUE;
    privateCommand.emplace("value1", privateDataValue1);
    privateCommand.emplace("value2", privateDataValue2);
    privateCommand.emplace("value3", privateDataValue3);
    listener->ReceivePrivateCommand(privateCommand);
}

void FuzzSetPreviewText(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string fuzzedU16String(fuzzedString.begin(), fuzzedString.end());
    auto fuzzedStart = provider.ConsumeIntegral<int32_t>();
    auto fuzzedEnd = provider.ConsumeIntegral<int32_t>();
    Range range = { .start = fuzzedStart, .end = fuzzedEnd };
    listener->SetPreviewText(fuzzedU16String, range);
}

void FuzzInputMethodControllerWithListener(sptr<InputMethodController> imc,
    sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    if (imc == nullptr || listener == nullptr) {
        return;
    }

    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string fuzzedU16String(fuzzedString.begin(), fuzzedString.end());
    auto fuzzInt32 = provider.ConsumeIntegral<int32_t>();
    auto fuzzBool = provider.ConsumeBool();

    // Attach listener first so controller APIs can exercise listener-controller interaction paths.
    (void)imc->Attach(listener, fuzzBool);

    imc->InsertText(fuzzedU16String);
    imc->DeleteForward(fuzzInt32);
    imc->DeleteBackward(fuzzInt32);
    imc->MoveCursor(Direction::UP);
    imc->SendKeyboardStatus(KeyboardStatus::SHOW);
    imc->SendFunctionKey(fuzzInt32);
    
    PanelStatusInfo panelStatusInfo;
    panelStatusInfo.panelInfo.panelType = PanelType::SOFT_KEYBOARD;
    panelStatusInfo.panelInfo.panelFlag = PanelFlag::FLG_FIXED;
    panelStatusInfo.visible = fuzzBool;
    panelStatusInfo.trigger = Trigger::IME_APP;
    panelStatusInfo.sessionId = FUZZER_SUCCESS;
    imc->NotifyPanelStatusInfo(panelStatusInfo);
    imc->NotifyKeyboardHeight(provider.ConsumeIntegral<uint32_t>());
    
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    privateCommand.emplace("key1", fuzzedString);
    privateCommand.emplace("key2", fuzzInt32);
    imc->ReceivePrivateCommand(privateCommand);

    (void)imc->Close();
}

void FuzzOnTextChangedListenerMethods(FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string fuzzedU16String(fuzzedString.begin(), fuzzedString.end());
    auto fuzzInt32 = provider.ConsumeIntegral<int32_t>();
    auto fuzzBool = provider.ConsumeBool();
    
    auto handler = CreateFuzzEventHandler();
    if (handler == nullptr) {
        return;
    }
    sptr<FuzzTextListener> listener(new (std::nothrow) FuzzTextListener(handler));

    if (listener == nullptr) {
        return;
    }
    
    listener->InsertText(fuzzedU16String);
    listener->DeleteForward(fuzzInt32);
    listener->DeleteBackward(fuzzInt32);
    listener->SendKeyboardStatus(KeyboardStatus::SHOW);
    FunctionKey functionKey;
    listener->SendFunctionKey(functionKey);
    listener->MoveCursor(Direction::DOWN);
    listener->HandleExtendAction(fuzzInt32);
    listener->GetLeftTextOfCursor(fuzzInt32);
    listener->GetRightTextOfCursor(fuzzInt32);
    listener->GetTextIndexAtCursor();
    KeyEvent keyEvent;
    listener->SendKeyEventFromInputMethod(keyEvent);
    listener->SetKeyboardStatus(fuzzBool);
    listener->HandleSetSelection(fuzzInt32, fuzzInt32);
    listener->HandleSelect(fuzzInt32, fuzzInt32);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == OHOS::FUZZER_SUCCESS) {
        return OHOS::FUZZER_SUCCESS;
    }

    FuzzedDataProvider provider(data, size);
    auto handler = OHOS::CreateFuzzEventHandler();
    if (handler == nullptr) {
        return OHOS::FUZZER_SUCCESS;
    }
    
    OHOS::sptr<OHOS::FuzzTextListener> listener(new (std::nothrow) OHOS::FuzzTextListener(handler));

    if (listener == nullptr) {
        return OHOS::FUZZER_SUCCESS;
    }

    OHOS::sptr<OHOS::MiscServices::InputMethodController> imc =
        OHOS::MiscServices::InputMethodController::GetInstance();
    if (imc != nullptr) {
        OHOS::FuzzInputMethodControllerWithListener(imc, listener, provider);
    }

    OHOS::FuzzFinishTextPreview(listener);
    OHOS::FuzzOnDetach(listener);
    OHOS::FuzzIsFromTs(listener, provider);
    OHOS::FuzzGetEventHandler(listener);
    OHOS::FuzzNotifyPanelStatusInfo(listener, provider);
    OHOS::FuzzNotifyKeyboardHeight(listener, provider);
    OHOS::FuzzReceivePrivateCommand(listener, provider);
    OHOS::FuzzSetPreviewText(listener, provider);
    OHOS::FuzzOnTextChangedListenerMethods(provider);
    return OHOS::FUZZER_SUCCESS;
}
