/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

#include "controlchannelstub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "global.h"
#include "input_control_channel_service_impl.h"
#include "message_parcel.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::MiscServices;
namespace OHOS {
constexpr size_t THRESHOLD = 10;
const std::u16string CONTROLCHANNEL_INTERFACE_TOKEN = u"OHOS.MiscServices.IInputControlChannel";

bool FuzzControlChannel(FuzzedDataProvider &provider)
{
    constexpr int32_t MAIN_USER_ID = 100;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();

    MessageParcel data;
    data.WriteInterfaceToken(CONTROLCHANNEL_INTERFACE_TOKEN);
    std::vector<uint8_t> bufferData = provider.ConsumeRemainingBytes<uint8_t>();
    data.WriteBuffer(static_cast<void *>(bufferData.data()), bufferData.size());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    sptr<InputControlChannelStub> controlChannel = new InputControlChannelServiceImpl(MAIN_USER_ID);
    controlChannel->OnRemoteRequest(code, data, reply, option);

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
    OHOS::FuzzControlChannel(provider);
    return 0;
}