/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef INPUTMETHOD_EXTRA_CONFIG_H
#define INPUTMETHOD_EXTRA_CONFIG_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <variant>

namespace OHOS {
namespace MiscServices {

enum CustomValueTypeValue : int32_t {
    CUSTOM_VALUE_TYPE_STRING = 0,
    CUSTOM_VALUE_TYPE_NUMBER,
    CUSTOM_VALUE_TYPE_BOOL
};
using CustomValueType = std::variant<std::string, int32_t, bool>;
using CustomSettings = std::unordered_map<std::string, CustomValueType>;
struct ExtraConfig {
    CustomSettings customSettings = {};
    bool operator==(const ExtraConfig &info) const
    {
        return customSettings == info.customSettings;
    }
};
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_EXTRA_CONFIG_H