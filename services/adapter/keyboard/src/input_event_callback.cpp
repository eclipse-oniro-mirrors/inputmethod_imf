/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "input_event_callback.h"

#include "global.h"

namespace OHOS {
namespace MiscServices {
uint32_t InputEventCallback::keyState_ = static_cast<uint32_t>(0);
int32_t InputEventCallback::lastPressedKey_ = MMI::KeyEvent::KEYCODE_UNKNOWN;
const std::map<int32_t, uint8_t> MASK_MAP{
    { MMI::KeyEvent::KEYCODE_SHIFT_LEFT, KeyboardEvent::SHIFT_LEFT_MASK },
    { MMI::KeyEvent::KEYCODE_SHIFT_RIGHT, KeyboardEvent::SHIFT_RIGHT_MASK },
    { MMI::KeyEvent::KEYCODE_CTRL_LEFT, KeyboardEvent::CTRL_LEFT_MASK },
    { MMI::KeyEvent::KEYCODE_CTRL_RIGHT, KeyboardEvent::CTRL_RIGHT_MASK },
    { MMI::KeyEvent::KEYCODE_CAPS_LOCK, KeyboardEvent::CAPS_MASK },
};

void InputEventCallback::OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
    auto keyCode = keyEvent->GetKeyCode();
    auto keyAction = keyEvent->GetKeyAction();
    auto currKey = MASK_MAP.find(keyCode);
    if (currKey == MASK_MAP.end()) {
        IMSA_HILOGD("key code unknown");
        if (keyAction == MMI::KeyEvent::KEY_ACTION_DOWN) {
            lastPressedKey_ = MMI::KeyEvent::KEYCODE_UNKNOWN;
        }
        return;
    }
    IMSA_HILOGD("keyCode: %{public}d, keyAction: %{public}d", keyCode, keyAction);

    if (keyAction == MMI::KeyEvent::KEY_ACTION_DOWN) {
        IMSA_HILOGD("key %{public}d pressed down", keyCode);
        keyState_ = static_cast<uint32_t>(keyState_ | currKey->second);
        lastPressedKey_ = keyCode;
        if (keyCode == MMI::KeyEvent::KEYCODE_CAPS_LOCK) {
            if (keyHandler_ != nullptr) {
                int32_t ret = keyHandler_(keyState_, KeyboardEvent::CAPS_MASK);
                IMSA_HILOGI("handle key event ret: %{public}d", ret);
            }
        }
        return;
    }

    if (keyAction == MMI::KeyEvent::KEY_ACTION_UP) {
        auto lastPressedKey = MASK_MAP.find(lastPressedKey_);
        if (keyHandler_ != nullptr && lastPressedKey != MASK_MAP.end()) {
            int32_t ret = keyHandler_(keyState_, lastPressedKey->second);
            IMSA_HILOGI("handle key event ret: %{public}d", ret);
        }
        keyState_ = static_cast<uint32_t>(keyState_ & ~currKey->second);
    }
}

void InputEventCallback::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
}

void InputEventCallback::OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const
{
}

void InputEventCallback::SetKeyHandle(KeyHandle handle)
{
    keyHandler_ = std::move(handle);
}
} // namespace MiscServices
} // namespace OHOS