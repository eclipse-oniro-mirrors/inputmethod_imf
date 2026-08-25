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

#include "input_method_ability.h"

#include <cinttypes>

namespace OHOS {
namespace MiscServices {
bool InputMethodAbility::IsOnlySpacePressed(const std::shared_ptr<MMI::KeyEvent> &keyEvent)
{
    if (keyEvent == nullptr) {
        IMSA_HILOGW("PTT: cannot check pressed keys because key event is nullptr.");
        return false;
    }

    const auto &pressedKeys = keyEvent->GetPressedKeys();
    bool isOnlySpacePressed = pressedKeys.size() == 1 && pressedKeys[0] == MMI::KeyEvent::KEYCODE_SPACE;
    IMSA_HILOGD("PTT: check pressed keys, pressedKeyCount=%{public}zu, isOnlySpacePressed=%{public}d.",
        pressedKeys.size(), isOnlySpacePressed);
    return isOnlySpacePressed;
}

bool InputMethodAbility::HandlePttKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t callbackId,
    const sptr<IRemoteObject> &channel, int32_t &result)
{
    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t keyAction = keyEvent->GetKeyAction();
    if (keyCode != MMI::KeyEvent::KEYCODE_SPACE) {
        if (keyAction == MMI::KeyEvent::KEY_ACTION_DOWN || keyAction == MMI::KeyEvent::KEY_ACTION_UP) {
            SuppressPttKeyEventTracking();
        }
        return false;
    }
    if (keyAction == MMI::KeyEvent::KEY_ACTION_UP) {
        auto previousState = pttSpaceTrackingState_.load();
        IMSA_HILOGI("PTT: IMA received space up, previousState=%{public}d, callbackId=%{public}" PRIu64 ".",
            static_cast<int32_t>(previousState), callbackId);
        ResetPttKeyEventTracking();
        return false;
    }
    if (keyAction != MMI::KeyEvent::KEY_ACTION_DOWN) {
        return false;
    }

    auto trackingState = pttSpaceTrackingState_.load();
    IMSA_HILOGD("PTT: IMA received space down, trackingState=%{public}d, pressedKeyCount=%{public}zu.",
        static_cast<int32_t>(trackingState), keyEvent->GetPressedKeys().size());
    if (trackingState == PttSpaceTrackingState::TRACKING) {
        result = HandleKeyEventResult(callbackId, true, channel);
        IMSA_HILOGD("PTT: consumed repeated space down, callbackId=%{public}" PRIu64 ", ret=%{public}d.",
            callbackId, result);
        return true;
    }
    // The service query also checks the PTT setting, monitor readiness, current IME, and exact client channel.
    if (trackingState == PttSpaceTrackingState::IDLE && IsOnlySpacePressed(keyEvent) &&
        IsPttGestureAvailable(channel)) {
        pttSpaceTrackingState_.store(PttSpaceTrackingState::TRACKING);
        IMSA_HILOGI("PTT: started tracking the initial space down, callbackId=%{public}" PRIu64 ".", callbackId);
    } else if (trackingState == PttSpaceTrackingState::IDLE) {
        pttSpaceTrackingState_.store(PttSpaceTrackingState::SUPPRESSED);
        IMSA_HILOGI("PTT: space gesture is unavailable; keep normal key reporting until space up, "
            "callbackId=%{public}" PRIu64 ".", callbackId);
    }
    return false;
}

bool InputMethodAbility::IsPttGestureAvailable(const sptr<IRemoteObject> &channel)
{
    if (channel == nullptr) {
        IMSA_HILOGW("PTT: cannot query gesture availability because input channel is nullptr.");
        return false;
    }
    auto proxy = GetImsaProxy();
    if (proxy == nullptr) {
        IMSA_HILOGE("PTT: cannot query gesture availability because IMSA proxy is nullptr.");
        return false;
    }

    bool isAvailable = false;
    int32_t ret = proxy->IsPttGestureAvailable(channel, isAvailable);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGW("PTT: query gesture availability failed, ret=%{public}d.", ret);
        return false;
    }
    IMSA_HILOGD("PTT: gesture availability=%{public}d.", isAvailable);
    return isAvailable;
}

void InputMethodAbility::ResetPttKeyEventTracking()
{
    auto previousState = pttSpaceTrackingState_.exchange(PttSpaceTrackingState::IDLE);
    if (previousState != PttSpaceTrackingState::IDLE) {
        IMSA_HILOGI("PTT: reset space key tracking, previousState=%{public}d.",
            static_cast<int32_t>(previousState));
    }
}

void InputMethodAbility::SuppressPttKeyEventTracking()
{
    auto expected = PttSpaceTrackingState::TRACKING;
    if (pttSpaceTrackingState_.compare_exchange_strong(expected, PttSpaceTrackingState::SUPPRESSED)) {
        IMSA_HILOGI("PTT: suppress space key tracking until space up.");
    }
}

void InputMethodAbility::OnPttGestureCancelled()
{
    IMSA_HILOGI("PTT: received gesture cancellation from IMSA.");
    SuppressPttKeyEventTracking();
}

int32_t InputMethodAbility::OnPttLongPress()
{
    IMSA_HILOGI("PTT: begin rolling back the space before the cursor.");
    std::u16string text;
    int32_t ret = GetTextBeforeCursor(1, text);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("PTT: get text before cursor failed, ret=%{public}d.", ret);
        return ret;
    }
    if (text.empty()) {
        IMSA_HILOGW("PTT: skip rolling back space because there is no text before the cursor.");
        return ErrorCode::NO_ERROR;
    }

    if (text.back() != u' ') {
        IMSA_HILOGW("PTT: skip rolling back space because the character before the cursor is not a space.");
        return ErrorCode::NO_ERROR;
    }
    // By IMF API definition, DeleteForward removes text on the left of the cursor.
    ret = DeleteForward(1);
    IMSA_HILOGI("PTT: roll back space finished, ret=%{public}d.", ret);
    return ret;
}
} // namespace MiscServices
} // namespace OHOS
