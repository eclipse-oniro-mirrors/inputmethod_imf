/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "settings_data_utils.h"
#undef private

#include "settingsdatautils_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::MiscServices;
namespace OHOS {

void FuzzCreateAndRegisterObserver(FuzzedDataProvider &provider, SettingsDataObserver::CallbackFunc func)
{
    std::string uriProxy = provider.ConsumeRandomLengthString();
    std::string key = provider.ConsumeRandomLengthString();
    SettingsDataUtils::GetInstance().CreateAndRegisterObserver(uriProxy, key, func);
}

void FuzzRegisterObserver(FuzzedDataProvider &provider, SettingsDataObserver::CallbackFunc &func)
{
    std::string uriProxy = provider.ConsumeRandomLengthString();
    std::string key = provider.ConsumeRandomLengthString();
    sptr<SettingsDataObserver> observer = new SettingsDataObserver(uriProxy, key, func);
    SettingsDataUtils::GetInstance().RegisterObserver(observer);
}

void FuzzUnregisterObserver(FuzzedDataProvider &provider, SettingsDataObserver::CallbackFunc &func)
{
    std::string uriProxy = provider.ConsumeRandomLengthString();
    std::string key = provider.ConsumeRandomLengthString();
    sptr<SettingsDataObserver> observer = new SettingsDataObserver(uriProxy, key, func);
    SettingsDataUtils::GetInstance().UnregisterObserver(observer);
}

void FuzzGenerateTargetUri(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    SettingsDataUtils::GetInstance().GenerateTargetUri(SETTING_URI_PROXY, key);
}


void FuzzSetStringValue(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    SettingsDataUtils::GetInstance().SetStringValue(SETTING_URI_PROXY, key, key);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    SettingsDataObserver::CallbackFunc func;

    OHOS::FuzzCreateAndRegisterObserver(provider, func);
    OHOS::FuzzRegisterObserver(provider, func);
    OHOS::FuzzUnregisterObserver(provider, func);
    OHOS::FuzzGenerateTargetUri(provider);
    return 0;
}