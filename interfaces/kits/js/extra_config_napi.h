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

#ifndef INTERFACE_JS_EXTRA_CONFIG
#define INTERFACE_JS_EXTRA_CONFIG

#include "extra_config.h"
#include "napi/native_api.h"

namespace OHOS {
namespace MiscServices {
constexpr uint32_t DEFAULT_MAX_EXTRA_CONFIG_SIZE = 128 * 1024; // 128K
constexpr uint32_t MAX_EXTRA_CONFIG_SIZE = 1024 * 1024; // 1M

class JsExtraConfig {
public:
    JsExtraConfig() = default;
    ~JsExtraConfig() = default;
    static napi_status GetValue(napi_env env, napi_value in, ExtraConfig &out, uint32_t maxLen = MAX_EXTRA_CONFIG_SIZE);
    static napi_status GetValue(napi_env env, napi_value in, CustomSettings &out,
        uint32_t maxLen = MAX_EXTRA_CONFIG_SIZE);
    static napi_status GetValue(napi_env env, napi_value in, CustomValueType &out, uint32_t &valueSize);
    static napi_status GetJsExtraConfig(napi_env env, const ExtraConfig &in, napi_value &out);
    static napi_status CreateExtraConfig(napi_env env, const ExtraConfig &in, napi_value &out);
    static napi_status GetExtraConfig(napi_env env, napi_value in, ExtraConfig &out,
        uint32_t maxLen = DEFAULT_MAX_EXTRA_CONFIG_SIZE);
};
} // namespace MiscServices
} // namespace OHOS
#endif // INTERFACE_JS_EXTRA_CONFIG