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

#include "panelstatusinfo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "input_method_utils.h"
#include "message_parcel.h"
#include "panel_info.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace MiscServices {

namespace {
constexpr size_t MIN_INPUT_SIZE = 10;
constexpr size_t MAX_INPUT_SIZE = 1000;
constexpr uint32_t PANEL_TYPE_MAX = 3;
constexpr uint32_t PANEL_FLAG_MAX = 3;
constexpr int32_t TRIGGER_MAX = 2;
} // namespace

void FuzzPanelStatusInfoInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;

    PanelInfo panelInfo;
    panelInfo.panelType = static_cast<PanelType>(provider.ConsumeIntegralInRange<uint32_t>(0, PANEL_TYPE_MAX));
    panelInfo.panelFlag = static_cast<PanelFlag>(provider.ConsumeIntegralInRange<uint32_t>(0, PANEL_FLAG_MAX));
    parcel.WriteParcelable(&panelInfo);

    parcel.WriteBool(provider.ConsumeBool());
    parcel.WriteInt32(provider.ConsumeIntegralInRange<int32_t>(0, TRIGGER_MAX));
    parcel.WriteUint32(provider.ConsumeIntegral<uint32_t>());
    parcel.RewindRead(0);

    PanelStatusInfoInner *result = PanelStatusInfoInner::Unmarshalling(parcel);
    if (result != nullptr) {
        MessageParcel outParcel;
        result->Marshalling(outParcel);
        delete result;
    }
}

void FuzzPanelStatusInfoInnerMarshalling(FuzzedDataProvider &provider)
{
    PanelStatusInfoInner info;
    info.panelInfo.panelType = static_cast<PanelType>(provider.ConsumeIntegralInRange<uint32_t>(0, PANEL_TYPE_MAX));
    info.panelInfo.panelFlag = static_cast<PanelFlag>(provider.ConsumeIntegralInRange<uint32_t>(0, PANEL_FLAG_MAX));
    info.visible = provider.ConsumeBool();
    info.trigger = static_cast<Trigger>(provider.ConsumeIntegralInRange<int32_t>(0, TRIGGER_MAX));
    info.sessionId = provider.ConsumeIntegral<uint32_t>();

    MessageParcel parcel;
    info.Marshalling(parcel);
}

void FuzzPanelStatusInfoInnerRoundTrip(FuzzedDataProvider &provider)
{
    PanelStatusInfoInner originalInfo;
    originalInfo.panelInfo.panelType = static_cast<PanelType>(
        provider.ConsumeIntegralInRange<uint32_t>(0, PANEL_TYPE_MAX));
    originalInfo.panelInfo.panelFlag = static_cast<PanelFlag>(
        provider.ConsumeIntegralInRange<uint32_t>(0, PANEL_FLAG_MAX));
    originalInfo.visible = provider.ConsumeBool();
    originalInfo.trigger = static_cast<Trigger>(
        provider.ConsumeIntegralInRange<int32_t>(0, TRIGGER_MAX));
    originalInfo.sessionId = provider.ConsumeIntegral<uint32_t>();

    MessageParcel parcel;
    originalInfo.Marshalling(parcel);
    parcel.RewindRead(0);

    PanelStatusInfoInner *result = PanelStatusInfoInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzPanelInfoMarshalling(FuzzedDataProvider &provider)
{
    PanelInfo panelInfo;
    panelInfo.panelType = static_cast<PanelType>(provider.ConsumeIntegralInRange<uint32_t>(0, PANEL_TYPE_MAX));
    panelInfo.panelFlag = static_cast<PanelFlag>(provider.ConsumeIntegralInRange<uint32_t>(0, PANEL_FLAG_MAX));

    MessageParcel parcel;
    parcel.WriteParcelable(&panelInfo);
    parcel.RewindRead(0);

    PanelInfo *result = parcel.ReadParcelable<PanelInfo>();
    if (result != nullptr) {
        delete result;
    }
}

void FuzzPanelStatusInfoInnerWithRandomData(FuzzedDataProvider &provider)
{
    MessageParcel parcel;

    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.WriteBool(provider.ConsumeBool());
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.WriteUint32(provider.ConsumeIntegral<uint32_t>());
    parcel.RewindRead(0);

    PanelStatusInfoInner *result = PanelStatusInfoInner::Unmarshalling(parcel);
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

    OHOS::MiscServices::FuzzPanelStatusInfoInnerUnmarshalling(provider);
    OHOS::MiscServices::FuzzPanelStatusInfoInnerMarshalling(provider);
    OHOS::MiscServices::FuzzPanelStatusInfoInnerRoundTrip(provider);
    OHOS::MiscServices::FuzzPanelInfoMarshalling(provider);
    OHOS::MiscServices::FuzzPanelStatusInfoInnerWithRandomData(provider);

    return 0;
}
