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

#include "ptt_controller.h"

namespace OHOS {
namespace MiscServices {
PttAction PttController::HandleKeyEvent(const KeyboardEventInfo &eventInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool isKeyAction = eventInfo.keyAction == MMI::KeyEvent::KEY_ACTION_DOWN ||
        eventInfo.keyAction == MMI::KeyEvent::KEY_ACTION_UP;
    bool isSpace = eventInfo.keyCode == MMI::KeyEvent::KEYCODE_SPACE;
    if (!isSpace && (!isKeyAction || (state_ != PttState::PENDING && state_ != PttState::ACTIVE))) {
        return PttAction::NONE;
    }

    PttState previousState = state_;
    PttAction action = PttAction::NONE;
    if (isSpace) {
        if (eventInfo.keyAction == MMI::KeyEvent::KEY_ACTION_DOWN) {
            action = HandleSpaceDownLocked(eventInfo);
        } else if (eventInfo.keyAction == MMI::KeyEvent::KEY_ACTION_UP) {
            action = HandleSpaceUpLocked();
        }
    } else {
        action = HandleOtherKeyLocked();
    }
    if (action != PttAction::NONE || previousState != state_) {
        IMSA_HILOGD("PTT: handle key event, isSpace=%{public}d, keyAction=%{public}d, "
            "pressedKeyCount=%{public}zu, state=%{public}s->%{public}s, action=%{public}s.",
            isSpace, eventInfo.keyAction, eventInfo.pressedKeys.size(), StateToString(previousState),
            StateToString(state_), ActionToString(action));
    }
    return action;
}

PttAction PttController::HandleTimeout()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != PttState::PENDING) {
        IMSA_HILOGD("PTT: ignore timeout, state=%{public}s.", StateToString(state_));
        return PttAction::NONE;
    }
    state_ = PttState::ACTIVE;
    IMSA_HILOGI("PTT: long press timeout, state=PENDING->ACTIVE, action=START_VOICE.");
    return PttAction::START_VOICE;
}

PttAction PttController::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    PttAction action = PttAction::NONE;
    if (state_ == PttState::PENDING) {
        action = PttAction::CANCEL_TIMER;
    } else if (state_ == PttState::ACTIVE) {
        action = PttAction::STOP_VOICE;
    }
    PttState previousState = state_;
    state_ = PttState::IDLE;
    IMSA_HILOGI("PTT: reset controller, state=%{public}s->IDLE, cleanupAction=%{public}s.",
        StateToString(previousState), ActionToString(action));
    return action;
}

PttState PttController::SuppressUntilSpaceUp()
{
    std::lock_guard<std::mutex> lock(mutex_);
    PttState previousState = state_;
    if (state_ != PttState::IDLE) {
        state_ = PttState::SUPPRESSED;
    }
    IMSA_HILOGI("PTT: suppress failed gesture until space up, state=%{public}s->%{public}s.",
        StateToString(previousState), StateToString(state_));
    return state_;
}

PttState PttController::GetState() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

const char *PttController::StateToString(PttState state)
{
    switch (state) {
        case PttState::IDLE:
            return "IDLE";
        case PttState::PENDING:
            return "PENDING";
        case PttState::ACTIVE:
            return "ACTIVE";
        case PttState::SUPPRESSED:
            return "SUPPRESSED";
        default:
            return "UNKNOWN";
    }
}

const char *PttController::ActionToString(PttAction action)
{
    switch (action) {
        case PttAction::NONE:
            return "NONE";
        case PttAction::START_TIMER:
            return "START_TIMER";
        case PttAction::CANCEL_TIMER:
            return "CANCEL_TIMER";
        case PttAction::START_VOICE:
            return "START_VOICE";
        case PttAction::STOP_VOICE:
            return "STOP_VOICE";
        default:
            return "UNKNOWN";
    }
}

PttAction PttController::HandleSpaceDownLocked(const KeyboardEventInfo &eventInfo)
{
    if (state_ != PttState::IDLE) {
        return PttAction::NONE;
    }
    if (HasOtherPressedKey(eventInfo)) {
        state_ = PttState::SUPPRESSED;
        return PttAction::NONE;
    }

    state_ = PttState::PENDING;
    return PttAction::START_TIMER;
}

PttAction PttController::HandleSpaceUpLocked()
{
    PttAction action = PttAction::NONE;
    if (state_ == PttState::PENDING) {
        action = PttAction::CANCEL_TIMER;
    } else if (state_ == PttState::ACTIVE) {
        action = PttAction::STOP_VOICE;
    }
    state_ = PttState::IDLE;
    return action;
}

PttAction PttController::HandleOtherKeyLocked()
{
    if (state_ == PttState::PENDING) {
        state_ = PttState::SUPPRESSED;
        return PttAction::CANCEL_TIMER;
    }

    if (state_ == PttState::ACTIVE) {
        state_ = PttState::SUPPRESSED;
        return PttAction::STOP_VOICE;
    }

    return PttAction::NONE;
}

bool PttController::HasOtherPressedKey(const KeyboardEventInfo &eventInfo)
{
    for (const auto keyCode : eventInfo.pressedKeys) {
        if (keyCode != MMI::KeyEvent::KEYCODE_SPACE) {
            return true;
        }
    }
    return false;
}
} // namespace MiscServices
} // namespace OHOS
