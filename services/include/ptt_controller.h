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

#ifndef INPUTMETHOD_IMF_PTT_CONTROLLER_H
#define INPUTMETHOD_IMF_PTT_CONTROLLER_H

#include <cstdint>
#include <mutex>

#include "keyboard_event.h"

namespace OHOS {
namespace MiscServices {
enum class PttState : uint8_t {
    IDLE = 0,
    PENDING,
    ACTIVE,
    SUPPRESSED,
};

enum class PttAction : uint8_t {
    NONE = 0,
    START_TIMER,
    CANCEL_TIMER,
    START_VOICE,
    STOP_VOICE,
};

class PttController {
public:
    PttController() = default;
    ~PttController() = default;

    PttController(const PttController &) = delete;
    PttController &operator=(const PttController &) = delete;
    PttController(PttController &&) = delete;
    PttController &operator=(PttController &&) = delete;

    PttAction HandleKeyEvent(const KeyboardEventInfo &eventInfo);
    PttAction HandleTimeout();
    PttAction Reset();
    PttState SuppressUntilSpaceUp();
    PttState GetState() const;
    static const char *StateToString(PttState state);
    static const char *ActionToString(PttAction action);

private:
    PttAction HandleSpaceDownLocked(const KeyboardEventInfo &eventInfo);
    PttAction HandleSpaceUpLocked();
    PttAction HandleOtherKeyLocked();
    static bool HasOtherPressedKey(const KeyboardEventInfo &eventInfo);
    mutable std::mutex mutex_;
    PttState state_ { PttState::IDLE };
};
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_IMF_PTT_CONTROLLER_H
