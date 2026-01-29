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

#ifndef INTERFACE_ANI_EXTRA_CONFIG
#define INTERFACE_ANI_EXTRA_CONFIG

#include "extra_config.h"
#include "ani.h"

namespace OHOS {
namespace MiscServices {
constexpr uint32_t DEFAULT_MAX_EXTRA_CONFIG_SIZE = 32 * 1024; // 32K
class AniExtraConfig {
public:
    AniExtraConfig() = default;
    ~AniExtraConfig() = default;
    static bool GetExtraConfig([[maybe_unused]]ani_env* env, ani_object in, ExtraConfig &out,
        uint32_t maxLen = DEFAULT_MAX_EXTRA_CONFIG_SIZE);
private:
    static std::string ConvertString(ani_env* env, ani_object in);
    static ani_field AniFindClassField(ani_env* env, ani_class cls, const char* name);
    static ani_class AniGetClass(ani_env* env, const char* className);
    static ani_method AniGetClassMethod(ani_env* env, const char* className,
        const char* methodName, const char* signature);
    static bool ParseValue(ani_env* env, ani_object aniValue, CustomValueType &valueObj, uint32_t& valueSize);
    static bool ParseRecordItem(ani_env* env, ani_object entryIterator,
        ani_method iterNextMethod, ani_class iterResultClass, CustomSettings& out);
    static bool ParseRecord(ani_env *env, ani_object recordObj,
        CustomSettings& out, uint32_t maxLen = DEFAULT_MAX_EXTRA_CONFIG_SIZE);
    static bool GetRecordOrUndefined(ani_env* env, ani_object in,
        const char* name, CustomSettings& out, uint32_t maxLen = DEFAULT_MAX_EXTRA_CONFIG_SIZE);
};
} // namespace MiscServices
} // namespace OHOS
#endif // INTERFACE_ANI_EXTRA_CONFIG