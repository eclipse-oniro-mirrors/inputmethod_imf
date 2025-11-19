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

#include "agentstub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "input_method_agent_service_impl.h"
#include "message_parcel.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::MiscServices;
namespace OHOS {
constexpr size_t THRESHOLD = 10;
const std::u16string AGENTSTUB_INTERFACE_TOKEN = u"OHOS.MiscServices.IInputMethodAgent";
constexpr uint32_t CODE_MIN = 0;
constexpr uint32_t CODE_MAX = static_cast<uint32_t>(IInputMethodAgentIpcCode::COMMAND_SEND_MESSAGE) + 1;

+bool FuzzAgentStub(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>() % (CODE_MAX - CODE_MIN + 1) + CODE_MIN;

    std::vector<uint8_t> bufferData = provider.ConsumeRemainingBytes<uint8_t>();
    MessageParcel data;
    data.WriteInterfaceToken(AGENTSTUB_INTERFACE_TOKEN);
    data.WriteBuffer(static_cast<void *>(bufferData.data()), bufferData.size());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    sptr<InputMethodAgentStub> stub = new InputMethodAgentServiceImpl();
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
    FuzzedDataProvider provider(data, size);
    /* Run your code on data */
    OHOS::FuzzAgentStub(provider);
    return 0;
}