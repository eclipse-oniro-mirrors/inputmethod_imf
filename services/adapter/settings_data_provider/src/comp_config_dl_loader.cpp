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

#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE

#include "comp_config_dl_loader.h"

#include <dlfcn.h>

namespace OHOS {
namespace MiscServices {

static constexpr const char *LIB_PATH = "/system/lib64/platformsdk/libcompconfigclient.z.so";

CompConfigDlLoader::CompConfigDlLoader() {}

CompConfigDlLoader::~CompConfigDlLoader()
{
    if (reader_ != nullptr && fnDestroy_ != nullptr) {
        fnDestroy_(reader_);
        reader_ = nullptr;
    }
    if (handle_ != nullptr) {
        dlclose(handle_);
        handle_ = nullptr;
    }
    loaded_.store(false);
}

bool CompConfigDlLoader::Load()
{
    if (loaded_.load()) {
        return true;
    }
    handle_ = dlopen(LIB_PATH, RTLD_NOW);
    if (handle_ == nullptr) {
        IMSA_HILOGE("dlopen failed: %{public}s", dlerror());
        return false;
    }
    fnCreate_ = reinterpret_cast<FnCreate>(dlsym(handle_, "SystemCompConfigReader_Create"));
    fnDestroy_ = reinterpret_cast<FnDestroy>(dlsym(handle_, "SystemCompConfigReader_Destroy"));
    fnInit_ = reinterpret_cast<FnInit>(dlsym(handle_, "SystemCompConfigReader_Init"));
    fnGetConfig_ = reinterpret_cast<FnGetConfig>(dlsym(handle_, "SystemCompConfigReader_GetConfig"));
    fnFreeResult_ = reinterpret_cast<FnFreeResult>(dlsym(handle_, "CompConfigFreePropertyValueMapResult"));
    if (fnCreate_ == nullptr || fnDestroy_ == nullptr || fnInit_ == nullptr || fnGetConfig_ == nullptr ||
        fnFreeResult_ == nullptr) {
        IMSA_HILOGE("dlsym failed, one or more symbols not found");
        dlclose(handle_);
        handle_ = nullptr;
        return false;
    }

    reader_ = fnCreate_();
    if (reader_ == nullptr) {
        IMSA_HILOGE("SystemCompConfigReader_Create failed");
        dlclose(handle_);
        handle_ = nullptr;
        return false;
    }

    loaded_.store(true);
    IMSA_HILOGI("dlopen and dlsym success");
    return true;
}

bool CompConfigDlLoader::IsLoaded() const
{
    return loaded_.load();
}

int32_t CompConfigDlLoader::Init(const std::vector<std::string> &keys)
{
    if (!loaded_.load() || fnInit_ == nullptr) {
        IMSA_HILOGE("not loaded");
        return -1;
    }
    std::vector<const char *> keyPtrs;
    keyPtrs.reserve(keys.size());
    for (const auto &key : keys) {
        keyPtrs.push_back(key.c_str());
    }
    int32_t ret = fnInit_(reader_, keyPtrs.data(), static_cast<int32_t>(keyPtrs.size()));
    IMSA_HILOGD("Init ret: %{public}d", ret);
    return ret;
}

std::pair<int32_t, std::unordered_map<std::string, std::string>> CompConfigDlLoader::GetConfig(
    const std::string &bundleName, const std::vector<std::string> &keys)
{
    if (!loaded_.load() || fnGetConfig_ == nullptr) {
        IMSA_HILOGE("not loaded");
        return {-1, {}};
    }
    std::vector<const char *> keyPtrs;
    keyPtrs.reserve(keys.size());
    for (const auto &key : keys) {
        keyPtrs.push_back(key.c_str());
    }
    CompConfigPropertyValueMapResult result =
        fnGetConfig_(reader_, bundleName.c_str(), keyPtrs.data(), static_cast<int32_t>(keyPtrs.size()));
    IMSA_HILOGD("GetConfig ret: %{public}d, entryCount: %{public}d", result.ret, result.entryCount);
    if (result.ret != 0) {
        IMSA_HILOGD("GetConfig failed, ret: %{public}d", result.ret);
        fnFreeResult_(&result);
        return {result.ret, {}};
    }
    std::unordered_map<std::string, std::string> valMap;
    for (int32_t i = 0; i < result.entryCount; ++i) {
        if (result.entries[i].key != nullptr) {
            valMap[result.entries[i].key] = result.entries[i].value ? result.entries[i].value : "";
        }
    }
    fnFreeResult_(&result);
    IMSA_HILOGD("GetConfig valMap size: %{public}zu", valMap.size());
    return {0, valMap};
}
} // namespace MiscServices
} // namespace OHOS

#endif // COMPATIBILITY_CONFIG_CENTER_ENABLE
