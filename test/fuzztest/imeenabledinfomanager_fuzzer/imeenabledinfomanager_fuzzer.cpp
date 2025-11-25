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

#include "imeenabledinfomanager_fuzzer.h"

#define private public
#define protected public
#include "ime_enabled_info_manager.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::MiscServices;
namespace OHOS {

void FuzzInit(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::map<int32_t, std::vector<FullImeInfo>> fullImeInfos;
    std::vector<FullImeInfo> imeInfos;
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < size; i++) {
        FullImeInfo imeInfo;
        imeInfo.prop.name = fuzzedString + std::to_string(i);
        imeInfo.prop.id = std::to_string(i) + fuzzedString;
        imeInfos.push_back(imeInfo);
    }
    fullImeInfos.insert({ userId, imeInfos });
    ImeEnabledInfoManager::GetInstance().Init(fullImeInfos);
}

void FuzzSwitch(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::vector<FullImeInfo> imeInfos;
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < size; i++) {
        FullImeInfo imeInfo;
        imeInfo.prop.name = fuzzedString + std::to_string(i);
        imeInfo.prop.id = std::to_string(i) + fuzzedString;
        imeInfos.push_back(imeInfo);
    }
    ImeEnabledInfoManager::GetInstance().Switch(userId, imeInfos);
}

void FuzzDelete(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    ImeEnabledInfoManager::GetInstance().Delete(userId);
}

void FuzzAddPackage(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    FullImeInfo imeInfo;
    imeInfo.prop.name = fuzzedString;
    imeInfo.prop.id = fuzzedString + "ext";
    ImeEnabledInfoManager::GetInstance().Add(userId, imeInfo);
}

void FuzzDeletePackage(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    ImeEnabledInfoManager::GetInstance().Delete(userId, fuzzedString);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    OHOS::FuzzInit(provider);
    OHOS::FuzzSwitch(provider);
    OHOS::FuzzDelete(provider);
    OHOS::FuzzAddPackage(provider);
    OHOS::FuzzDeletePackage(provider);

    return 0;
}