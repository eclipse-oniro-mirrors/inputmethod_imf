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

#include "imeenablestatus_fuzzer.h"

#define private public
#define protected public
#include "ime_enabled_info_manager.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::MiscServices;
namespace OHOS {

void FuzzUpdateEnabledStatus(FuzzedDataProvider &provider)
{
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, 10);
    auto userId = provider.ConsumeIntegral<int32_t>();
    auto enabledStatus = static_cast<EnabledStatus>(size);
    auto fuzzedString = provider.ConsumeRandomLengthString();
    ImeEnabledInfoManager::GetInstance().Update(userId, fuzzedString, fuzzedString + "ext", enabledStatus);
}

void FuzzGetEnabledState(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    auto fuzzedString = provider.ConsumeRandomLengthString();
    auto enabledStatus = EnabledStatus::DISABLED;
    ImeEnabledInfoManager::GetInstance().GetEnabledState(userId, fuzzedString, enabledStatus);
}

void FuzzGetEnabledStates(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, 10);
    auto fuzzedString = provider.ConsumeRandomLengthString();
    std::vector<Property> props;
    for (size_t i = 0; i < size; i++) {
        Property prop;
        prop.name = fuzzedString + std::to_string(i);
        prop.id = std::to_string(i) + fuzzedString;
        props.push_back(prop);
    }
    ImeEnabledInfoManager::GetInstance().GetEnabledStates(userId, props);
}

void FuzzOnFullExperienceTableChanged(FuzzedDataProvider &provider)
{
    auto userId = provider.ConsumeIntegral<int32_t>();
    ImeEnabledInfoManager::GetInstance().OnFullExperienceTableChanged(userId);
}

void FuzzGetEnabledStateInner(FuzzedDataProvider &provider)
{
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, 10);
    static std::vector<Property> props;
    static std::vector<FullImeInfo> imeInfos;
    static std::vector<ImeEnabledInfo> enabledInfos;
    auto fuzzedString = provider.ConsumeRandomLengthString();
    for (size_t i = 0; i < size; i++) {
        Property prop;
        prop.name = fuzzedString + std::to_string(i);
        prop.id = std::to_string(i) + fuzzedString;
        props.push_back(prop);
    }
    auto userId = provider.ConsumeIntegral<int32_t>();
    bool fuzzedBool = provider.ConsumeBool();
    auto fuzzUint32 = provider.ConsumeIntegral<uint32_t>();
    auto fuzzInt32 = provider.ConsumeIntegral<int32_t>();
    EnabledStatus status = static_cast<EnabledStatus>(fuzzInt32);
    FullImeInfo imeInfo = { .isNewIme = fuzzedBool, .tokenId = fuzzUint32, .appId = fuzzedString,
        .versionCode = fuzzUint32 };
    ImeEnabledInfo imeEnabeleInfo;
    imeEnabeleInfo.bundleName = fuzzedString;
    imeEnabeleInfo.extensionName = fuzzedString;
    imeEnabeleInfo.enabledStatus = static_cast<EnabledStatus>(fuzzInt32);
    imeEnabeleInfo.stateUpdateTime = fuzzedString;
    enabledInfos.push_back(imeEnabeleInfo);
    ImeEnabledCfg newEnabledCfg;
    newEnabledCfg.version = fuzzedString;
    newEnabledCfg.enabledInfos = enabledInfos;
    ImeEnabledInfoManager::GetInstance().GetEnabledStateInner(userId, fuzzedString, status);
    ImeEnabledInfoManager::GetInstance().GetEnabledStatesInner(userId, props);
    ImeEnabledInfoManager::GetInstance().IsInEnabledCache(userId, fuzzedString, fuzzedString);
    ImeEnabledInfoManager::GetInstance().CorrectByBundleMgr(userId, imeInfos, enabledInfos);
    ImeEnabledInfoManager::GetInstance().UpdateEnabledCfgCache(userId, newEnabledCfg);
    ImeEnabledInfoManager::GetInstance().NotifyCurrentImeStatusChanged(userId, fuzzedString, status);
    ImeEnabledInfoManager::GetInstance().IsExpired(fuzzedString);
    ImeEnabledInfoManager::GetInstance().UpdateGlobalEnabledTable(userId, newEnabledCfg);
    ImeEnabledInfoManager::GetInstance().ModCurrentIme(enabledInfos);
    ImeEnabledInfoManager::GetInstance().IsCurrentIme(fuzzedString, enabledInfos);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    OHOS::FuzzUpdateEnabledStatus(provider);
    OHOS::FuzzGetEnabledState(provider);
    OHOS::FuzzGetEnabledStates(provider);
    OHOS::FuzzOnFullExperienceTableChanged(provider);
    OHOS::FuzzGetEnabledStateInner(provider);
    return 0;
}