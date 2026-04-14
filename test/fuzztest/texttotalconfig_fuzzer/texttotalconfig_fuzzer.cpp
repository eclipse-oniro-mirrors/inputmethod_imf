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

#include "texttotalconfig_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "input_attribute.h"
#include "input_method_utils.h"
#include "message_parcel.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace MiscServices {

namespace {
constexpr size_t MIN_INPUT_SIZE = 10;
constexpr size_t MAX_INPUT_SIZE = 2000;
} // namespace

void FuzzTextTotalConfigInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;

    InputAttributeInner inputAttr;
    inputAttr.inputPattern = provider.ConsumeIntegral<int32_t>();
    inputAttr.enterKeyType = provider.ConsumeIntegral<int32_t>();
    inputAttr.inputOption = provider.ConsumeIntegral<int32_t>();
    parcel.WriteParcelable(&inputAttr);

    CursorInfoInner cursorInfo;
    cursorInfo.left = provider.ConsumeFloatingPoint<double>();
    cursorInfo.top = provider.ConsumeFloatingPoint<double>();
    cursorInfo.width = provider.ConsumeFloatingPoint<double>();
    cursorInfo.height = provider.ConsumeFloatingPoint<double>();
    parcel.WriteParcelable(&cursorInfo);

    TextSelectionInner textSelection;
    textSelection.oldBegin = provider.ConsumeIntegral<int32_t>();
    textSelection.oldEnd = provider.ConsumeIntegral<int32_t>();
    textSelection.newBegin = provider.ConsumeIntegral<int32_t>();
    textSelection.newEnd = provider.ConsumeIntegral<int32_t>();
    parcel.WriteParcelable(&textSelection);

    parcel.WriteUint32(provider.ConsumeIntegral<uint32_t>());
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>());
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>());

    Value cmdValue;
    parcel.WriteParcelable(&cmdValue);

    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.WriteBool(provider.ConsumeBool());
    parcel.RewindRead(0);

    TextTotalConfigInner *result = TextTotalConfigInner::Unmarshalling(parcel);
    if (result != nullptr) {
        MessageParcel outParcel;
        result->Marshalling(outParcel);
        delete result;
    }
}

void FuzzTextTotalConfigInnerMarshalling(FuzzedDataProvider &provider)
{
    TextTotalConfigInner config;
    config.inputAttribute.inputPattern = provider.ConsumeIntegral<int32_t>();
    config.inputAttribute.enterKeyType = provider.ConsumeIntegral<int32_t>();
    config.cursorInfo.left = provider.ConsumeFloatingPoint<double>();
    config.cursorInfo.top = provider.ConsumeFloatingPoint<double>();
    config.textSelection.oldBegin = provider.ConsumeIntegral<int32_t>();
    config.textSelection.newEnd = provider.ConsumeIntegral<int32_t>();
    config.windowId = provider.ConsumeIntegral<uint32_t>();
    config.positionY = provider.ConsumeFloatingPoint<double>();
    config.height = provider.ConsumeFloatingPoint<double>();
    config.isSimpleKeyboardEnabled = provider.ConsumeBool();

    MessageParcel parcel;
    config.Marshalling(parcel);
}

void FuzzTextTotalConfigInnerRoundTrip(FuzzedDataProvider &provider)
{
    TextTotalConfigInner originalConfig;
    originalConfig.inputAttribute.inputPattern = provider.ConsumeIntegral<int32_t>();
    originalConfig.inputAttribute.enterKeyType = provider.ConsumeIntegral<int32_t>();
    originalConfig.inputAttribute.inputOption = provider.ConsumeIntegral<int32_t>();
    originalConfig.cursorInfo.left = provider.ConsumeFloatingPoint<double>();
    originalConfig.cursorInfo.top = provider.ConsumeFloatingPoint<double>();
    originalConfig.cursorInfo.width = provider.ConsumeFloatingPoint<double>();
    originalConfig.cursorInfo.height = provider.ConsumeFloatingPoint<double>();
    originalConfig.textSelection.oldBegin = provider.ConsumeIntegral<int32_t>();
    originalConfig.textSelection.oldEnd = provider.ConsumeIntegral<int32_t>();
    originalConfig.textSelection.newBegin = provider.ConsumeIntegral<int32_t>();
    originalConfig.textSelection.newEnd = provider.ConsumeIntegral<int32_t>();
    originalConfig.windowId = provider.ConsumeIntegral<uint32_t>();
    originalConfig.positionY = provider.ConsumeFloatingPoint<double>();
    originalConfig.height = provider.ConsumeFloatingPoint<double>();
    originalConfig.requestKeyboardReason = static_cast<RequestKeyboardReason>(provider.ConsumeIntegral<int32_t>());
    originalConfig.isSimpleKeyboardEnabled = provider.ConsumeBool();

    MessageParcel parcel;
    originalConfig.Marshalling(parcel);
    parcel.RewindRead(0);

    TextTotalConfigInner *result = TextTotalConfigInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzInputAttributeInnerMarshalling(FuzzedDataProvider &provider)
{
    InputAttributeInner inputAttr;
    inputAttr.inputPattern = provider.ConsumeIntegral<int32_t>();
    inputAttr.enterKeyType = provider.ConsumeIntegral<int32_t>();
    inputAttr.inputOption = provider.ConsumeIntegral<int32_t>();

    MessageParcel parcel;
    parcel.WriteParcelable(&inputAttr);
    parcel.RewindRead(0);

    InputAttributeInner *result = parcel.ReadParcelable<InputAttributeInner>();
    if (result != nullptr) {
        delete result;
    }
}

void FuzzCursorInfoInnerMarshalling(FuzzedDataProvider &provider)
{
    CursorInfoInner cursorInfo;
    cursorInfo.left = provider.ConsumeFloatingPoint<double>();
    cursorInfo.top = provider.ConsumeFloatingPoint<double>();
    cursorInfo.width = provider.ConsumeFloatingPoint<double>();
    cursorInfo.height = provider.ConsumeFloatingPoint<double>();

    MessageParcel parcel;
    cursorInfo.Marshalling(parcel);
    parcel.RewindRead(0);

    CursorInfoInner *result = CursorInfoInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzTextSelectionInnerRoundTrip(FuzzedDataProvider &provider)
{
    TextSelectionInner textSelection;
    textSelection.oldBegin = provider.ConsumeIntegral<int32_t>();
    textSelection.oldEnd = provider.ConsumeIntegral<int32_t>();
    textSelection.newBegin = provider.ConsumeIntegral<int32_t>();
    textSelection.newEnd = provider.ConsumeIntegral<int32_t>();

    MessageParcel parcel;
    textSelection.Marshalling(parcel);
    parcel.RewindRead(0);

    TextSelectionInner *result = TextSelectionInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

} // namespace MiscServices
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::MiscServices::MIN_INPUT_SIZE) {
        return 0;
    }

    if (size > OHOS::MiscServices::MAX_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);

    OHOS::MiscServices::FuzzTextTotalConfigInnerUnmarshalling(provider);
    OHOS::MiscServices::FuzzTextTotalConfigInnerMarshalling(provider);
    OHOS::MiscServices::FuzzTextTotalConfigInnerRoundTrip(provider);
    OHOS::MiscServices::FuzzInputAttributeInnerMarshalling(provider);
    OHOS::MiscServices::FuzzCursorInfoInnerMarshalling(provider);
    OHOS::MiscServices::FuzzTextSelectionInnerRoundTrip(provider);

    return 0;
}
