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

#include "fuzzcovered_fuzzer.h"

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

void TestCovered(sptr<InputMethodController> imc, FuzzedDataProvider &provider)
{
    sptr<OnTextChangedListener> textListener = new TextListener();
    if (textListener == nullptr || imc == nullptr) {
        return;
    }
    imc->Attach(textListener);
    auto callingWndId = provider.ConsumeIntegral<uint32_t>();
    auto isFocusTriggered = provider.ConsumeBool();
    imc->RequestHideInput(callingWndId, isFocusTriggered);

    auto isInputStart = provider.ConsumeBool();
    auto requestKeyboardReason = provider.ConsumeIntegral<int32_t>();
    imc->GetInputStartInfo(isInputStart, callingWndId, requestKeyboardReason);
    auto index = provider.ConsumeIntegral<int32_t>();
    imc->GetTextIndexAtCursor(index);
    imc->DeleteBackward(index);
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

    OHOS::TestCovered(imc, provider);
    return 0;
}
