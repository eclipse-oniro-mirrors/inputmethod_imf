/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "inputclientstub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "input_client_service_impl.h"
#include "input_method_agent_service_impl.h"
#include "message_parcel.h"

using namespace OHOS::MiscServices;
namespace OHOS {
constexpr size_t THRESHOLD = 10;
const std::u16string INPUTCLIENTSTUB_INTERFACE_TOKEN = u"OHOS.MiscServices.IInputClient";

void FuzzInputClientStub(FuzzedDataProvider &provider)
{
    auto code = provider.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> bufferData = provider.ConsumeRemainingBytes<uint8_t>();

    MessageParcel data;
    data.WriteInterfaceToken(INPUTCLIENTSTUB_INTERFACE_TOKEN);
    data.WriteBuffer(static_cast<void *>(bufferData.data()), bufferData.size());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    sptr<InputClientStub> mClient = new InputClientServiceImpl();
    mClient->OnRemoteRequest(code, data, reply, option);
}

void TextOnInputReady(FuzzedDataProvider &provider)
{
    sptr<InputClientStub> mClient = new InputClientServiceImpl();
    sptr<InputMethodAgentStub> mInputMethodAgentStub = new InputMethodAgentServiceImpl();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    MessageParcel data;
    data.WriteRemoteObject(mInputMethodAgentStub->AsObject());
    auto remoteObject = data.ReadRemoteObject();
    BindImeInfo imeInfo;
    imeInfo.pid = 0;
    imeInfo.bundleName = fuzzedString;
    mClient->OnInputReady(remoteObject, imeInfo);
}

void TestOnSwitchInput(FuzzedDataProvider &provider)
{
    sptr<InputClientStub> mClient = new InputClientServiceImpl();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    uint32_t fuzzedUint32 = provider.ConsumeIntegral<uint32_t>();
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    Property property;
    property.name = fuzzedString;
    property.id = fuzzedString;
    property.icon = fuzzedString;
    property.iconId = fuzzedUint32;
    SubProperty subProperty = {};

    mClient->OnSwitchInput(property, subProperty, userId);
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
    OHOS::FuzzInputClientStub(provider);
    OHOS::TextOnInputReady(provider);
    OHOS::TestOnSwitchInput(provider);
    return 0;
}