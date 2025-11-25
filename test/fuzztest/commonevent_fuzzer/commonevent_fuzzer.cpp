/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "commonevent_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "input_method_agent_service_impl.h"
#include "string_utils.h"
#include "message_parcel.h"
#define private public
#define protected public
#include "on_demand_start_stop_sa.h"
#include "input_method_system_ability.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "input_method_controller.h"
#include "input_method_core_service_impl.h"
#include "inputmethod_message_handler.h"
#include "iremote_object.h"
#include "system_cmd_channel_service_impl.h"
using namespace OHOS::MiscServices;
using namespace MessageID;
namespace OHOS {

void FuzzStringUtils(FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    std::u16string txt(fuzzedString.begin(), fuzzedString.end());
    StringUtils::ToHex(fuzzedString);
    StringUtils::ToHex(txt);
    StringUtils::CountUtf16Chars(txt);
    StringUtils::TruncateUtf16String(txt, fuzzedInt32);
}

void FuzzOnDemandStartStopSa(FuzzedDataProvider &provider)
{
    auto onDemandStartStopSa = std::make_shared<OnDemandStartStopSa>();
    sptr<OnDemandStartStopSa::SaLoadCallback> callback =
        new (std::nothrow) OnDemandStartStopSa::SaLoadCallback(onDemandStartStopSa);
    sptr<IRemoteObject> object {nullptr};
    int32_t fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    callback->OnLoadSystemAbilitySuccess(fuzzedInt32, object);
    callback->OnLoadSystemAbilityFail(fuzzedInt32);
}

void FuzzSwitchOperation(FuzzedDataProvider &provider)
{
    auto fuzzedUint64 = provider.ConsumeIntegral<uint64_t>();
    auto fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    sptr<IInputMethodCore> core = new InputMethodCoreServiceImpl();
    sptr<SystemCmdChannelStub> stub = new SystemCmdChannelServiceImpl();
    auto info = std::make_shared<ImeInfo>();
 
    MessageParcel messData;
    messData.WriteRemoteObject(stub->AsObject());
    sptr<IRemoteObject> remoteObject = messData.ReadRemoteObject();
    bool fuzzedBool = provider.ConsumeBool();
    std::string fuzzedString = provider.ConsumeRandomLengthString();

    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->UpdateUserInfo(fuzzedInt32);
 
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->RegisterProxyIme(fuzzedUint64, core, remoteObject);
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->SwitchExtension(fuzzedInt32, info);
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->SwitchSubType(fuzzedInt32, info);
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->HandleFocusChanged(fuzzedBool,
        fuzzedUint64, fuzzedInt32, fuzzedInt32);
}
 
void FuzzHandleOperation(FuzzedDataProvider &provider)
{
    auto fuzzedInt32 = provider.ConsumeIntegral<int32_t>();
    int32_t value = provider.ConsumeIntegralInRange<int32_t>(0, 1);
    InputType inputType = static_cast<InputType>(value);
    InputClientInfo clientInfo {};
 
    bool fuzzedBool = provider.ConsumeBool();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
 
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->HandleScbStarted(fuzzedInt32, fuzzedInt32);
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->HandleWmsDisconnected(fuzzedInt32, fuzzedInt32);
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->NeedHideWhenSwitchInputType(fuzzedInt32, inputType,
        fuzzedBool);
}
} // namespace OHOS
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    /* Run your code on data */
    OHOS::FuzzStringUtils(provider);
    OHOS::FuzzOnDemandStartStopSa(provider);
    OHOS::FuzzSwitchOperation(provider);
    OHOS::FuzzHandleOperation(provider);
    return 0;
}