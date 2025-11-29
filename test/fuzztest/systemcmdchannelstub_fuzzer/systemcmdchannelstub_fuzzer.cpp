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

#include "systemcmdchannelstub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "fuzzer/FuzzedDataProvider.h"
#include "message_parcel.h"
#include "system_cmd_channel_service_impl.h"

using namespace OHOS::MiscServices;
namespace OHOS {
constexpr size_t THRESHOLD = 10;
const std::u16string AGENTSTUB_INTERFACE_TOKEN = u"OHOS.MiscServices.ISystemCmdChannel";
bool FuzzSystemCmdChannelStub(FuzzedDataProvider &provider)
{
    InputType inputType = static_cast<InputType>(provider.ConsumeIntegral<int32_t>());
    auto fuzzedUint32 = provider.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> bufferData = provider.ConsumeRemainingBytes<uint8_t>();

    uint32_t code = provider.ConsumeIntegral<uint32_t>();

    SysPanelStatus sysPanelStatus = {inputType, 0, fuzzedUint32, fuzzedUint32};
    MessageParcel data;
    data.WriteInterfaceToken(AGENTSTUB_INTERFACE_TOKEN);
    data.WriteBuffer(static_cast<void *>(bufferData.data()), bufferData.size());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    sptr <SystemCmdChannelStub> stub = new SystemCmdChannelServiceImpl();
    stub->NotifyPanelStatus(sysPanelStatus);
    stub->OnRemoteRequest(code, data, reply, option);
    return true;
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
    OHOS::FuzzSystemCmdChannelStub(provider);
    return 0;
}