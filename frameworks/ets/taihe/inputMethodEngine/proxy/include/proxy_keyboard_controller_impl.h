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
#ifndef TAIHE_PROXY_KEYBOARD_CONTROLLER_IMPL_H
#define TAIHE_PROXY_KEYBOARD_CONTROLLER_IMPL_H

#include "ani_common_engine.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "input_method_ability.h"
#include "input_method_utils.h"

namespace OHOS {
namespace MiscServices {
class IMFProxyKeyboardControllerImpl {
public:
    IMFProxyKeyboardControllerImpl() = default;
    ~IMFProxyKeyboardControllerImpl() = default;

    void HideSelfAsync();
};
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_PROXY_KEYBOARD_CONTROLLER_IMPL_H
