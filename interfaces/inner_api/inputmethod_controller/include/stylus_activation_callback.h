/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef INPUTMETHOD_CONTROLLER_STYLUS_ACTIVATION_CALLBACK_H
#define INPUTMETHOD_CONTROLLER_STYLUS_ACTIVATION_CALLBACK_H

#include <cstdint>

namespace OHOS {
namespace MiscServices {
/**
 * @brief Stylus activation type enum.
 *
 * This enum defines the activation type returned by the stylus service clinet
 * when the input method framework queries whether to activate the stylus input method.
 */
enum class StylusActivationType :int32_t {
    NONE = 0,
    STYLUS = 1,
};
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_CONTROLLER_STYLUS_ACTIVATION_CALLBACK_H