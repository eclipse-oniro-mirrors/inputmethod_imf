/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "ime_system_channel.h"
#include "input_method_system_ability_proxy.h"
#undef private

#include "imesystemchannel_fuzzer.h"
#include "system_cmd_channel_service_impl.h"
#include <cstddef>
#include <cstdint>

#include "input_method_agent_service_impl.h"
#include "message_parcel.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::MiscServices;
namespace OHOS {
constexpr size_t THRESHOLD = 10;

void FuzzPrivateCommand(FuzzedDataProvider &provider)
{
    bool fuzzedBool = provider.ConsumeBool();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    auto fuzzInt32 = provider.ConsumeIntegral<int32_t>();

    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = fuzzedString;
    PrivateDataValue privateDataValue2 = fuzzedBool;
    PrivateDataValue privateDataValue3 = fuzzInt32;
    privateCommand.emplace("value1", privateDataValue1);
    privateCommand.emplace("value2", privateDataValue2);
    privateCommand.emplace("value3", privateDataValue3);

    ImeSystemCmdChannel::GetInstance()->SendPrivateCommand(privateCommand);
    ImeSystemCmdChannel::GetInstance()->ReceivePrivateCommand(privateCommand);
}

void FuzzNotifyPanelStatus(FuzzedDataProvider &provider)
{
    int32_t value = provider.ConsumeIntegralInRange<int32_t>(-1, 4);
    InputType inputType = static_cast<InputType>(value);
    auto fuzzedUint32 = provider.ConsumeIntegral<uint32_t>();

    SysPanelStatus sysPanelStatus = { inputType, 0, fuzzedUint32, fuzzedUint32 };
    ImeSystemCmdChannel::GetInstance()->NotifyPanelStatus(sysPanelStatus);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::FuzzPrivateCommand(provider);
    OHOS::FuzzNotifyPanelStatus(provider);
    return 0;
}