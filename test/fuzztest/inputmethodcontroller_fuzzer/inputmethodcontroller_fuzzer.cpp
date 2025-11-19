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
#define private public
#define protected public
#include "input_method_controller.h"
#include "input_method_system_ability_proxy.h"
#include "input_client_service_impl.h"
#undef private

#include "inputmethodcontroller_fuzzer.h"

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
void TestListInputMethod(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    auto fuzzedBool1 = provider.ConsumeBool();
    auto fuzzedBool2 = provider.ConsumeBool();
    std::vector<Property> properties = {};
    imc->ListInputMethod(properties);
    imc->ListInputMethod(fuzzedBool1, properties);
    imc->ListInputMethod(fuzzedBool2, properties);
}

void TestListInputMethodSubtype(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::vector<SubProperty> subProperties = {};
    Property property;
    property.name = fuzzedString;
    property.id = fuzzedString;
    property.label = fuzzedString;
    property.icon = fuzzedString;
    property.iconId = provider.ConsumeIntegral<uint32_t>();
    imc->ListInputMethodSubtype(property, subProperties);
}

void TestDispatchKeyEvent(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    sptr<OnTextChangedListener> textListener = new TextListener();
    if (textListener == nullptr) {
        return;
    }
    imc->Attach(textListener);
    imc->isBound_.store(true);

    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    if (keyEvent == nullptr) {
        return;
    }
    auto fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    keyEvent->SetKeyAction(fuzzedInt32);
    keyEvent->SetKeyCode(fuzzedInt32);
    imc->DispatchKeyEvent(keyEvent, [](std::shared_ptr<MMI::KeyEvent> &keyEvent, bool isConsumed) {});
}

void TestOnSelectionChange(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    sptr<OnTextChangedListener> textListener = new TextListener();
    if (textListener == nullptr) {
        return;
    }
    imc->Attach(textListener);
    imc->isBound_.store(true);

    auto fuzzedInt32t = provider.ConsumeIntegral<int32_t>();
    auto fuzzedInt = provider.ConsumeIntegral<int>();
	std::string fuzzedString = provider.ConsumeRandomLengthString();
	std::u16string fuzzedU16String(fuzzedString.begin(), fuzzedString.end());
    CursorInfo cursorInfo;
    cursorInfo.height = fuzzedInt32t;
    cursorInfo.left = fuzzedInt32t;
    cursorInfo.top = fuzzedInt32t;
    cursorInfo.width = fuzzedInt32t;
    imc->OnCursorUpdate(cursorInfo);

    imc->OnSelectionChange(fuzzedU16String, fuzzedInt, fuzzedInt);
}

void TestOnConfigurationChange(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    sptr<OnTextChangedListener> textListener = new TextListener();
    if (textListener == nullptr) {
        return;
    }
    imc->Attach(textListener);
    imc->isBound_.store(true);

    int32_t value = provider.ConsumeIntegralInRange<int32_t>(0, 8);
    Configuration info;
    EnterKeyType keyType = static_cast<EnterKeyType>(value);
    info.SetEnterKeyType(keyType);
    TextInputType textInputType = TextInputType::DATETIME;
    info.SetTextInputType(textInputType);
    imc->OnConfigurationChange(info);
    int32_t enterKeyType;
    int32_t inputPattern;
    imc->GetEnterKeyType(enterKeyType);
    imc->GetInputPattern(inputPattern);
}

void TestSwitchInputMethod(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    int32_t value = provider.ConsumeIntegralInRange<int32_t>(0, 3);
    auto fuzzedTrigger = static_cast<SwitchTrigger>(value);
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    imc->SwitchInputMethod(fuzzedTrigger, fuzzedString, fuzzedString);
}

void TestSetCallingWindow(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    sptr<OnTextChangedListener> textListener = new TextListener();
    if (textListener == nullptr) {
        return;
    }
    imc->Attach(textListener);
    auto fuzzedUInt32 = provider.ConsumeIntegral<uint32_t>();
    imc->SetCallingWindow(fuzzedUInt32);
}

void TestUpdateListenEventFlag(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    auto fuzzedUint32 = provider.ConsumeIntegral<uint32_t>();
    imc->UpdateListenEventFlag(static_cast<uint32_t>(fuzzedUint32), static_cast<uint32_t>(fuzzedUint32), true);
    imc->UpdateListenEventFlag(static_cast<uint32_t>(fuzzedUint32), static_cast<uint32_t>(fuzzedUint32), false);
}

void TestAttach(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    sptr<OnTextChangedListener> textListener = new TextListener();
    if (textListener == nullptr) {
        return;
    }
    auto fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    InputAttribute inputAttribute;
    inputAttribute.inputPattern = fuzzedInt32;
    inputAttribute.enterKeyType = fuzzedInt32;
    inputAttribute.inputOption = fuzzedInt32;
    imc->Attach(textListener, true, inputAttribute);
    imc->Attach(textListener, false, inputAttribute);
}

void InputType(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    int32_t value = provider.ConsumeIntegralInRange<int32_t>(0, 1);
    enum InputType fuzzedInputType = static_cast<enum InputType>(value);
    imc->IsInputTypeSupported(fuzzedInputType);
    imc->StartInputType(fuzzedInputType);
}

void FUZZIsPanelShown(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    PanelInfo panelInfo;
    panelInfo.panelType = SOFT_KEYBOARD;
    panelInfo.panelFlag = FLG_FIXED;
    auto flag = provider.ConsumeBool();
    imc->IsPanelShown(panelInfo, flag);
}

void FUZZPrintLogIfAceTimeout(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    auto start = provider.ConsumeIntegral<int64_t>();
    imc->PrintLogIfAceTimeout(start);
}

void FUZZGetInputStartInfo(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    auto dataBool = provider.ConsumeBool();
    auto callingWndId = provider.ConsumeIntegral<uint32_t>();
    auto int32Value = provider.ConsumeIntegral<int32_t>();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    imc->GetInputStartInfo(dataBool, callingWndId, int32Value);
    imc->EnableIme(fuzzedString);
    imc->IsCurrentImeByPid(int32Value);
    imc->UpdateTextPreviewState(dataBool);
}

void FUZZSetControllerListener(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    sptr<OnTextChangedListener> textListener = new TextListener();
    if (textListener == nullptr) {
        return;
    }
    imc->Attach(textListener);
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    auto uint32Value = provider.ConsumeIntegral<uint32_t>();
    auto dataBool = provider.ConsumeBool();
    static std::vector<SubProperty> subProps;
    static std::shared_ptr<Property> property = std::make_shared<Property>();
    property->name = fuzzedString;
    property->id = fuzzedString;
    property->label = fuzzedString;
    property->icon = fuzzedString;
    property->iconId = uint32Value;

    OHOS::AppExecFwk::ElementName inputMethodConfig;
    inputMethodConfig.SetDeviceID(fuzzedString);
    inputMethodConfig.SetAbilityName(fuzzedString);
    inputMethodConfig.SetBundleName(fuzzedString);
    inputMethodConfig.SetModuleName(fuzzedString);
    wptr<IRemoteObject> agentObject = nullptr;
    SubProperty subProperty;
    subProperty.label = fuzzedString;
    subProperty.labelId = uint32Value;
    subProperty.name = fuzzedString;
    subProperty.id = fuzzedString;
    subProperty.mode = fuzzedString;
    subProperty.locale = fuzzedString;
    subProperty.icon = fuzzedString;
    subProps.push_back(subProperty);
    std::unordered_map <std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = fuzzedString;
    PrivateDataValue privateDataValue2 = static_cast<int32_t>(dataBool);
    PrivateDataValue privateDataValue3 = PRIVATEDATAVALUE;
    privateCommand.emplace("value1", privateDataValue1);
    privateCommand.emplace("value2", privateDataValue2);
    privateCommand.emplace("value3", privateDataValue3);
    imc->SetControllerListener(nullptr);
    imc->GetInputMethodConfig(inputMethodConfig);
    imc->OnRemoteSaDied(agentObject);
    imc->SendPrivateCommand(privateCommand);
}

void TestShowTextInputInner(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    sptr<OnTextChangedListener> textListener = new TextListener();
    if (textListener == nullptr) {
        return;
    }
    auto fuzzedBool = provider.ConsumeBool();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    auto data = provider.ConsumeIntegral<uint8_t>();
    std::vector<uint8_t> msgParam;
    msgParam.push_back(data);
    std::unordered_map <std::string, PrivateDataValue> privateCommand;
    imc->Attach(textListener);
    AttachOptions attachOptions;
    attachOptions.isShowKeyboard = fuzzedBool;
    attachOptions.requestKeyboardReason = RequestKeyboardReason::NONE;
    ClientType clientType = ClientType::INNER_KIT;
    imc->ShowTextInputInner(attachOptions, clientType);
    imc->isEditable_.store(true);
    imc->SendPrivateData(privateCommand);
}

void FUZZOnTextChangedListener(FuzzedDataProvider &provider)
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
    eventHandlerTextListener->ReceivePrivateCommandV2(privateCommand);
    eventHandlerTextListener->SetPreviewTextV2(fuzzedU16String, range);
}

void FUZZCovered(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::vector<uint8_t> msgParam;
    std::vector<uint8_t> bufferData = provider.ConsumeRemainingBytes<uint8_t>();
    msgParam.push_back(*bufferData.data());
    ArrayBuffer arrayBuffer;
    arrayBuffer.jsArgc = bufferData.size();
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
    OHOS::TestListInputMethodSubtype(imc, provider);
    OHOS::TestOnSelectionChange(imc, provider);
    OHOS::TestOnConfigurationChange(imc, provider);
    OHOS::TestSwitchInputMethod(imc, provider);
    OHOS::TestSetCallingWindow(imc, provider);
    OHOS::TestDispatchKeyEvent(imc, provider);
    OHOS::InputType(imc, provider);
    OHOS::FUZZIsPanelShown(imc, provider);
    OHOS::FUZZPrintLogIfAceTimeout(imc, provider);
    OHOS::TestUpdateListenEventFlag(imc, provider);
    OHOS::FUZZGetInputStartInfo(imc, provider);
    OHOS::FUZZSetControllerListener(imc, provider);
    OHOS::TestShowTextInputInner(imc, provider);
    OHOS::FUZZCovered(imc, provider);
    return 0;
}
