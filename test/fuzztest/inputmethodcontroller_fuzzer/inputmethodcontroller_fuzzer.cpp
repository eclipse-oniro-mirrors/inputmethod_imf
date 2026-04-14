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
void TestListInputMethod(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    auto fuzzedBool1 = provider.ConsumeBool();
    auto fuzzedBool2 = provider.ConsumeBool();
    auto fuzzedUserId = provider.ConsumeIntegral<int32_t>();
    std::vector<Property> properties = {};
    imc->ListInputMethod(properties, fuzzedUserId);
    imc->ListInputMethod(fuzzedBool1, properties, fuzzedUserId);
    imc->ListInputMethod(fuzzedBool2, properties, fuzzedUserId);
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
    auto fuzzedUserId = provider.ConsumeIntegral<int32_t>();
    imc->ListInputMethodSubtype(property, subProperties, fuzzedUserId);
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
    auto fuzzedUserId = provider.ConsumeIntegral<int32_t>();
    imc->SwitchInputMethod(fuzzedTrigger, fuzzedString, fuzzedString, fuzzedUserId);
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
    return 0;
}
