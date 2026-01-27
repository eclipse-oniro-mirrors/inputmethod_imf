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

#include "imesetmode_fuzzer.h"

#define private public
#define protected public
#include "ime_enabled_info_manager.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::MiscServices;
namespace OHOS {
void FuzzIsDefaultFullMode(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    auto fuzzedString = provider.ConsumeRandomLengthString();
    ImeEnabledInfoManager::GetInstance().IsDefaultFullMode(userId, fuzzedString);
}

void FuzzSetCurrentIme(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    auto fuzzedString = provider.ConsumeRandomLengthString();
    std::string imeId = fuzzedString;
    bool fuzzedBool = provider.ConsumeBool();
    if (fuzzedBool) {
        imeId = fuzzedString + "/" + "ext";
    }
    bool isSetByUser = fuzzedBool;
    ImeEnabledInfoManager::GetInstance().SetCurrentIme(userId, imeId, fuzzedString, isSetByUser);
}

void FuzzSetTmpIme(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    auto fuzzedString = provider.ConsumeRandomLengthString();
    std::string imeId = fuzzedString;
    bool fuzzedBool = provider.ConsumeBool();
    if (fuzzedBool) {
        imeId = fuzzedString + "/" + "ext";
    }
    ImeEnabledInfoManager::GetInstance().SetTmpIme(userId, imeId);
}

void FuzzGetCurrentImeCfg(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    ImeEnabledInfoManager::GetInstance().GetCurrentImeCfg(userId);
}

void FuzzIsDefaultImeSet(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    ImeEnabledInfoManager::GetInstance().IsDefaultImeSet(userId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    OHOS::FuzzIsDefaultFullMode(provider);
    OHOS::FuzzSetCurrentIme(provider);
    OHOS::FuzzSetTmpIme(provider);
    OHOS::FuzzGetCurrentImeCfg(provider);
    OHOS::FuzzIsDefaultImeSet(provider);

    return 0;
}