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
#include "input_method_types.h"

namespace OHOS {
namespace MiscServices {
class InputMethodAbilityInterface {
public:
    static InputMethodAbilityInterface &GetInstance();
    int32_t RegisteredProxy();
    int32_t UnRegisteredProxy(UnRegisteredType type);
    /**
     * @brief Register the proxy input method to input method service with displayId.
     *
     * This function can be successfully invoked only when the related feature is enabled.
     *
     * @param displayId Indicates the ID of the display where the proxy input method is located.
     * @return Returns 0 for success, others for failure.
     * @since 18
     */
    int32_t RegisterProxyIme(uint64_t displayId);
    /**
     * @brief Unregister proxy input method.
     *
     * This function can be successfully invoked only when the related feature is enabled.
     *
     * @param displayId Indicates the ID of the display where the proxy input method is located.
     * @return Returns 0 for success, others for failure.
     * @since 18
     */
    int32_t UnregisterProxyIme(uint64_t displayId);
    /**
     * @brief Bind the input method mirror to the current input session.
     *
     * After binding the input method mirror (ime mirror), it can perceive content changes in the current edit box,
     * but **cannot actively input content into the edit box**.
     * Once bound successfully, the mirror function will start receiving status information such as text updates
     * and cursor position changes from the edit box.
     * This interface can only be called successfully when the relevant feature is enabled.
     *
     * @return Returns 0 for success, other values for failure.
     * @note The input method mirror only has content perception capability and does not support active input operations
     * such as inserting or deleting text.
     */
    int32_t BindImeMirror();

    /**
     * @brief Unbind the input method mirror from the current input session.
     *
     * After unbinding, the input method mirror will stop perceiving content changes in the edit box and
     * will no longer receive any status information from the edit box.
     * This interface can only be called successfully when the relevant feature is enabled.
     *
     * @return Returns 0 for success, other values for failure.
     * @note If you need to re-perceive the edit box content after unbinding, you must call {@link BindImeMirror} again.
     */
    int32_t UnbindImeMirror();
    int32_t InsertText(const std::string &text);
    int32_t DeleteForward(int32_t length);
    int32_t DeleteBackward(int32_t length);
    int32_t MoveCursor(int32_t keyCode);
    int32_t GetInputAttribute(InputAttribute &attribute);
    int32_t SendFunctionKey(int32_t funcKey);
    void SetImeListener(std::shared_ptr<InputMethodEngineListener> imeListener);
    void SetKdListener(std::shared_ptr<KeyboardListener> kdListener);
    int32_t SelectByRange(int32_t start, int32_t end);

private:
    InputMethodAbilityInterface() = default;
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_INPUT_METHOD_ABILITY_INTERFACE_H
