/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_INPUT_METHOD_ABILITY_INTERFACE_H
#define FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_INPUT_METHOD_ABILITY_INTERFACE_H

#include <cstdint>
#include <memory>
#include <mutex>

#include "input_method_engine_listener.h"
#include "keyboard_listener.h"
#include "unRegistered_type.h"

namespace OHOS {
namespace MiscServices {
class InputMethodAbilityInterface {
public:
    static InputMethodAbilityInterface &GetInstance();
    int32_t RegisteredProxy();
    int32_t UnRegisteredProxy(UnRegisteredType type);
    int32_t InsertText(const std::string &text);
    int32_t DeleteForward(int32_t length);
    int32_t DeleteBackward(int32_t length);
    int32_t MoveCursor(int32_t keyCode);
    void SetImeListener(std::shared_ptr<InputMethodEngineListener> imeListener);
    void SetKdListener(std::shared_ptr<KeyboardListener> kdListener);

private:
    InputMethodAbilityInterface() = default;
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_INPUT_METHOD_ABILITY_INTERFACE_H
