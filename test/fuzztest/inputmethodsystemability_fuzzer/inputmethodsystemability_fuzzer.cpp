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
#include "input_method_system_ability.h"
#include "input_method_system_ability_proxy.h"
#undef private

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_ex.h>

#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "ime_cfg_manager.h"
#include "input_client_service_impl.h"
#include "input_method_controller.h"
#include "inputmethodsystemability_fuzzer.h"
#include "input_method_core_service_impl.h"
#include "system_cmd_channel_service_impl.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "system_ability_definition.h"
#include "text_listener.h"
#include "token_setproc.h"
#include "input_method_tools.h"

using namespace OHOS::MiscServices;
namespace OHOS {
constexpr int32_t MAIN_USER_ID = 100;

bool InitializeClientInfo(InputClientInfo &clientInfo)
{
    sptr<IInputClient> clientStub = new (std::nothrow) InputClientServiceImpl();
    if (clientStub == nullptr) {
        IMSA_HILOGE("failed to create client");
        return false;
    }
    sptr<InputDeathRecipient> deathRecipient = new (std::nothrow) InputDeathRecipient();
    if (deathRecipient == nullptr) {
        IMSA_HILOGE("failed to new deathRecipient");
        return false;
    }
    clientInfo = { .userID = MAIN_USER_ID, .client = clientStub, .deathRecipient = deathRecipient };
    return true;
}
void SystemAbility(FuzzedDataProvider &provider)
{
    auto fuzzedUint32 = provider.ConsumeIntegral<uint32_t>();
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->ReleaseInput(nullptr, fuzzedUint32);
    InputClientInfo inputClientInfo;
    if (!OHOS::InitializeClientInfo(inputClientInfo)) {
        return;
    }
    InputClientInfoInner inner = InputMethodTools::GetInstance().InputClientInfoToInner(inputClientInfo);
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->UpdateListenEventFlag(inner, fuzzedUint32);

    const std::string bundleName = provider.ConsumeRandomLengthString();
    const std::string subName = provider.ConsumeRandomLengthString();
    uint32_t trigger = provider.ConsumeIntegral<uint32_t>();
    auto fuzzedUserId = provider.ConsumeIntegral<int32_t>();
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->SwitchInputMethod(bundleName, subName,
        trigger, fuzzedUserId);
}
void FuzzInputType(FuzzedDataProvider &provider)
{
    const int32_t type = provider.ConsumeIntegral<int32_t>();
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->StartInputType(type, true);
    bool resultValue = provider.ConsumeBool();
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->IsInputTypeSupported(type, resultValue);
    sptr<IInputMethodCore> core = new InputMethodCoreServiceImpl();

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        IMSA_HILOGE("systemAbilityManager is nullptr!");
        return;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        IMSA_HILOGE("remoteObject is nullptr!");
        return;
    }
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->SetCoreAndAgent(core, remoteObject);
}

void FuzzInterfaceCovage(FuzzedDataProvider &provider)
{
    const uint32_t status = provider.ConsumeIntegralInRange<uint32_t>(0, 2);
    ImeWindowInfo info {};
    PanelInfo panelInfo {};
    panelInfo.panelType = static_cast<PanelType>(provider.ConsumeIntegralInRange<int32_t>(0, 1));
    panelInfo.panelFlag = static_cast<PanelFlag>(provider.ConsumeIntegralInRange<int32_t>(0, 2));
    InputWindowInfo windowInfo;
    windowInfo.name = provider.ConsumeRandomLengthString();
    windowInfo.left = provider.ConsumeIntegral<int32_t>();
    windowInfo.top = provider.ConsumeIntegral<int32_t>();
    windowInfo.width = provider.ConsumeIntegral<uint32_t>();
    windowInfo.height = provider.ConsumeIntegral<uint32_t>();
    info.panelInfo = panelInfo;
    info.windowInfo = windowInfo;
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->PanelStatusChange(status, info);

    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    uint32_t type = provider.ConsumeIntegral<uint32_t>();
    int32_t requestKeyboardReason = provider.ConsumeIntegral<int32_t>();
    bool isShown = provider.ConsumeBool();
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->ShowInput(client, type, requestKeyboardReason);
    uint64_t displayId = provider.ConsumeIntegral<uint64_t>();
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->IsPanelShown(displayId, panelInfo, isShown);
    uint32_t windowId = provider.ConsumeIntegral<uint32_t>();
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->HideInput(client, windowId);
}
} // namespace OHOS
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SystemAbility(provider);
    OHOS::FuzzInputType(provider);
    OHOS::FuzzInterfaceCovage(provider);
    return 0;
}
