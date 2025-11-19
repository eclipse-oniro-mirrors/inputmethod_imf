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

using namespace OHOS::MiscServices;
namespace OHOS {
void SystemAbility(FuzzedDataProvider &provider)
{
    auto fuzzedUint32 = provider.ConsumeIntegral<uint32_t>();
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->ReleaseInput(nullptr, fuzzedUint32);
}
} // namespace OHOS
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SystemAbility(provider);
    return 0;
}
