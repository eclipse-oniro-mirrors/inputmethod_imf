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
#include "global.h"
#include "input_method_controller.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "system_ability_definition.h"
#include "systemabilitystub_fuzzer.h"
#include "text_listener.h"
#include "token_setproc.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::Security::AccessToken;
using namespace OHOS::MiscServices;
namespace OHOS {
std::atomic_bool g_isInitialize = false;
constexpr uint32_t TARGET_REMOTE_CODE_NUMS = 21;
void GrantNativePermission()
{
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.CONNECT_IME_ABILITY";
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "inputmethod_imf",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    int res = SetSelfTokenID(tokenId);
    if (res == 0) {
        IMSA_HILOGI("SetSelfTokenID success!");
    } else {
        IMSA_HILOGE("SetSelfTokenID fail!");
    }
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}
constexpr size_t THRESHOLD = 10;
const std::u16string SYSTEMABILITY_INTERFACE_TOKEN = u"OHOS.MiscServices.IInputMethodSystemAbility";

bool FuzzInputMethodSystemAbility(FuzzedDataProvider &provider)
{
    GrantNativePermission();
    uint32_t code = provider.ConsumeIntegral<uint32_t>() % TARGET_REMOTE_CODE_NUMS;
    std::vector<uint8_t> bufferData = provider.ConsumeRemainingBytes<uint8_t>();

    if (!g_isInitialize.load()) {
        DelayedSingleton<InputMethodSystemAbility>::GetInstance()->Initialize();
        g_isInitialize.store(true);
    }

    sptr<InputMethodController> imc = InputMethodController::GetInstance();
    sptr<OnTextChangedListener> textListener = new TextListener();
    imc->Attach(textListener);

    MessageParcel datas;
    datas.WriteInterfaceToken(SYSTEMABILITY_INTERFACE_TOKEN);
    datas.WriteBuffer(static_cast<void *>(bufferData.data()), bufferData.size());
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    return true;
}

bool TestDump(FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string u16Str(fuzzedString.begin(), fuzzedString.end());
    std::vector<std::u16string> args;
    args.push_back(u16Str);
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->Dump(provider.ConsumeIntegral<int32_t>(), args);
    DelayedSingleton<InputMethodSystemAbility>::GetInstance()->DumpAllMethod(provider.ConsumeIntegral<int32_t>());
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
    OHOS::FuzzInputMethodSystemAbility(provider);
    OHOS::TestDump(provider);
    return 0;
}
