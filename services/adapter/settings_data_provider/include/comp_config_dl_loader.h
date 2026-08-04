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

#ifndef INPUTMETHOD_IMF_COMP_CONFIG_DL_LOADER_H
#define INPUTMETHOD_IMF_COMP_CONFIG_DL_LOADER_H

#include <atomic>
#include <string>
#include <unordered_map>
#include <vector>
#include "global.h"

#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE

// C API types from libcompconfigclient.z.so (mirrored from comp_config_read_util.h)
typedef struct {
    const char *key;
    const char *value;
} CompConfigKvEntry;

typedef struct {
    int32_t ret;
    CompConfigKvEntry *entries;
    int32_t entryCount;
} CompConfigPropertyValueMapResult;

// Opaque handle from libcompconfigclient.z.so
typedef struct SystemCompConfigReaderHandle SystemCompConfigReaderHandle;

namespace OHOS {
namespace MiscServices {

class CompConfigDlLoader {
public:
    CompConfigDlLoader();
    ~CompConfigDlLoader();

    // dlopen + dlsym all required symbols, returns true on success
    bool Load();
    bool IsLoaded() const;

    // Initialize the reader with the specified keys
    int32_t Init(const std::vector<std::string> &keys);

    // Get config for bundleName. Returns (retCode, map[key->value]).
    // Same semantics as original C++ API: SystemCompConfigReader::GetConfig
    std::pair<int32_t, std::unordered_map<std::string, std::string>> GetConfig(
        const std::string &bundleName, const std::vector<std::string> &keys = {});

private:
    void *handle_ = nullptr;
    SystemCompConfigReaderHandle *reader_ = nullptr;
    std::atomic<bool> loaded_{false};

    // Function pointer types
    using FnCreate = SystemCompConfigReaderHandle *(*)(void);
    using FnDestroy = void (*)(SystemCompConfigReaderHandle *);
    using FnInit = int32_t (*)(SystemCompConfigReaderHandle *, const char **, int32_t);
    using FnGetConfig = CompConfigPropertyValueMapResult (*)(
        SystemCompConfigReaderHandle *, const char *, const char **, int32_t);
    using FnFreeResult = void (*)(CompConfigPropertyValueMapResult *);

    FnCreate fnCreate_ = nullptr;
    FnDestroy fnDestroy_ = nullptr;
    FnInit fnInit_ = nullptr;
    FnGetConfig fnGetConfig_ = nullptr;
    FnFreeResult fnFreeResult_ = nullptr;
};
} // namespace MiscServices
} // namespace OHOS

#endif // COMPATIBILITY_CONFIG_CENTER_ENABLE
#endif // INPUTMETHOD_IMF_COMP_CONFIG_DL_LOADER_H
