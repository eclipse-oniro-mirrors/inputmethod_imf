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

namespace OHOS {
namespace MiscServices {
uint32_t InputEventCallback::keyState_ = static_cast<uint32_t>(0);
bool InputEventCallback::isKeyHandled_ = false;
const std::map<int32_t, uint8_t> MASK_MAP{
    { MMI::KeyEvent::KEYCODE_CAPS_LOCK, KeyboardEvent::CAPS_MASK },
};

void InputEventCallback::OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
    if (keyEvent == nullptr) {
        IMSA_HILOGE("keyEvent is nullptr!");
        return;
    }
    auto keyCode = keyEvent->GetKeyCode();
    auto keyAction = keyEvent->GetKeyAction();
    if (keyEventHandler_ != nullptr && ShouldForwardPttKeyEvent(keyEvent)) {
        KeyboardEventInfo eventInfo {
            keyCode,
            keyAction,
            {},
        };
        if (keyCode == MMI::KeyEvent::KEYCODE_SPACE && keyAction == MMI::KeyEvent::KEY_ACTION_DOWN) {
            eventInfo.pressedKeys = keyEvent->GetPressedKeys();
        }
        keyEventHandler_(eventInfo);
    }
    auto currKey = MASK_MAP.find(keyCode);
    if (currKey == MASK_MAP.end()) {
        IMSA_HILOGD("key code is unknown.");
        keyState_ = 0;
        return;
    }

    if (keyAction == MMI::KeyEvent::KEY_ACTION_DOWN) {
        IMSA_HILOGD("key pressed down.");
        keyState_ = static_cast<uint32_t>(keyState_ | currKey->second);
        if (keyCode == MMI::KeyEvent::KEYCODE_CAPS_LOCK) {
            if (keyHandler_ != nullptr) {
                int32_t ret = keyHandler_(keyState_);
                IMSA_HILOGI("handle key event ret: %{public}d.", ret);
            }
            isKeyHandled_ = true;
            return;
        }
        isKeyHandled_ = false;
        return;
    }

    if (keyAction == MMI::KeyEvent::KEY_ACTION_UP) {
        if (keyHandler_ != nullptr && !isKeyHandled_) {
            int32_t ret = keyHandler_(keyState_);
            IMSA_HILOGI("handle key event ret: %{public}d.", ret);
        }
        isKeyHandled_ = true;
        keyState_ = static_cast<uint32_t>(keyState_ & ~currKey->second);
    }
}

bool InputEventCallback::ShouldForwardPttKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent) const
{
    if (keyEvent == nullptr) {
        return false;
    }
    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t keyAction = keyEvent->GetKeyAction();
    bool isKeyAction = keyAction == MMI::KeyEvent::KEY_ACTION_DOWN ||
        keyAction == MMI::KeyEvent::KEY_ACTION_UP;
    if (!isKeyAction) {
        return false;
    }

    std::lock_guard<std::mutex> lock(pttRoutingMutex_);
    if (keyCode == MMI::KeyEvent::KEYCODE_SPACE) {
        if (keyAction == MMI::KeyEvent::KEY_ACTION_UP) {
            bool shouldForward = pttRoutingState_ != PttRoutingState::IDLE;
            pttRoutingState_ = PttRoutingState::IDLE;
            return shouldForward;
        }
        if (pttRoutingState_ != PttRoutingState::IDLE) {
            return false;
        }
        const auto &pressedKeys = keyEvent->GetPressedKeys();
        bool isOnlySpacePressed = pressedKeys.size() == 1 &&
            pressedKeys[0] == MMI::KeyEvent::KEYCODE_SPACE;
        pttRoutingState_ = isOnlySpacePressed ? PttRoutingState::TRACKING : PttRoutingState::SUPPRESSED;
        return isOnlySpacePressed;
    }

    if (pttRoutingState_ != PttRoutingState::TRACKING) {
        return false;
    }
    pttRoutingState_ = PttRoutingState::SUPPRESSED;
    return true;
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

void InputEventCallback::SetKeyEventMonitorHandler(KeyEventMonitorHandler keyEventHandler)
{
    if (keyEventHandler != nullptr) {
        IMSA_HILOGI("PTT: set key event monitor handler, valid=%{public}d.", true);
    }
    keyEventHandler_ = std::move(keyEventHandler);
}

void InputEventCallback::TriggerSwitch()
{
    auto state = KeyboardEvent::META_MASK | KeyboardEvent::SPACE_MASK;
    if (keyHandler_ == nullptr) {
        IMSA_HILOGI("keyHandler_ is nullptr.");
        return;
    }
    int32_t ret = keyHandler_(state);
    IMSA_HILOGI("handle combinationkey ret: %{public}d.", ret);
}
} // namespace MiscServices
} // namespace OHOS
