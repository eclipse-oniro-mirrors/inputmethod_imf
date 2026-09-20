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

#include <gtest/gtest.h>

#include <utility>
#include <vector>

#include "ptt_controller.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
namespace {
KeyboardEventInfo MakeKeyboardEvent(
    int32_t keyCode, int32_t keyAction, std::vector<int32_t> pressedKeys = {})
{
    return { keyCode, keyAction, std::move(pressedKeys) };
}
} // namespace

class PttControllerTest : public testing::Test {
public:
    void SetUp() override
    {
        controller_.Reset();
    }

    PttController controller_;
};

/**
 * @tc.name: PttController_IdleAndStringConversion_001
 * @tc.desc: Verify idle filtering and enum string conversion.
 * @tc.type: FUNC
 */
HWTEST_F(PttControllerTest, PttController_IdleAndStringConversion_001, TestSize.Level0)
{
    EXPECT_EQ(controller_.GetState(), PttState::IDLE);
    EXPECT_EQ(controller_.HandleTimeout(), PttAction::NONE);
    EXPECT_EQ(controller_.HandleKeyEvent(
        MakeKeyboardEvent(MMI::KeyEvent::KEYCODE_A, MMI::KeyEvent::KEY_ACTION_DOWN)), PttAction::NONE);
    EXPECT_EQ(controller_.HandleKeyEvent(
        MakeKeyboardEvent(MMI::KeyEvent::KEYCODE_A, -1)), PttAction::NONE);
    EXPECT_EQ(controller_.HandleKeyEvent(
        MakeKeyboardEvent(MMI::KeyEvent::KEYCODE_SPACE, -1)), PttAction::NONE);

    EXPECT_STREQ(PttController::StateToString(PttState::IDLE), "IDLE");
    EXPECT_STREQ(PttController::StateToString(PttState::PENDING), "PENDING");
    EXPECT_STREQ(PttController::StateToString(PttState::ACTIVE), "ACTIVE");
    EXPECT_STREQ(PttController::StateToString(PttState::SUPPRESSED), "SUPPRESSED");
    EXPECT_STREQ(PttController::StateToString(static_cast<PttState>(255)), "UNKNOWN");

    EXPECT_STREQ(PttController::ActionToString(PttAction::NONE), "NONE");
    EXPECT_STREQ(PttController::ActionToString(PttAction::START_TIMER), "START_TIMER");
    EXPECT_STREQ(PttController::ActionToString(PttAction::CANCEL_TIMER), "CANCEL_TIMER");
    EXPECT_STREQ(PttController::ActionToString(PttAction::START_VOICE), "START_VOICE");
    EXPECT_STREQ(PttController::ActionToString(PttAction::STOP_VOICE), "STOP_VOICE");
    EXPECT_STREQ(PttController::ActionToString(static_cast<PttAction>(255)), "UNKNOWN");
}

/**
 * @tc.name: PttController_ShortPress_001
 * @tc.desc: Verify a short space press starts and then cancels the timer.
 * @tc.type: FUNC
 */
HWTEST_F(PttControllerTest, PttController_ShortPress_001, TestSize.Level0)
{
    auto spaceDown = MakeKeyboardEvent(
        MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN, { MMI::KeyEvent::KEYCODE_SPACE });
    auto spaceUp = MakeKeyboardEvent(MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_UP);

    EXPECT_EQ(controller_.HandleKeyEvent(spaceDown), PttAction::START_TIMER);
    EXPECT_EQ(controller_.GetState(), PttState::PENDING);
    EXPECT_EQ(controller_.HandleKeyEvent(spaceDown), PttAction::NONE);
    EXPECT_EQ(controller_.HandleKeyEvent(spaceUp), PttAction::CANCEL_TIMER);
    EXPECT_EQ(controller_.GetState(), PttState::IDLE);
    EXPECT_EQ(controller_.HandleKeyEvent(spaceUp), PttAction::NONE);
}

/**
 * @tc.name: PttController_LongPress_001
 * @tc.desc: Verify timeout activation and release stop actions.
 * @tc.type: FUNC
 */
HWTEST_F(PttControllerTest, PttController_LongPress_001, TestSize.Level0)
{
    auto spaceDown = MakeKeyboardEvent(
        MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN, { MMI::KeyEvent::KEYCODE_SPACE });
    auto spaceUp = MakeKeyboardEvent(MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_UP);

    EXPECT_EQ(controller_.HandleKeyEvent(spaceDown), PttAction::START_TIMER);
    EXPECT_EQ(controller_.HandleTimeout(), PttAction::START_VOICE);
    EXPECT_EQ(controller_.GetState(), PttState::ACTIVE);
    EXPECT_EQ(controller_.HandleTimeout(), PttAction::NONE);
    EXPECT_EQ(controller_.HandleKeyEvent(spaceDown), PttAction::NONE);
    EXPECT_EQ(controller_.HandleKeyEvent(spaceUp), PttAction::STOP_VOICE);
    EXPECT_EQ(controller_.GetState(), PttState::IDLE);
}

/**
 * @tc.name: PttController_Suppression_001
 * @tc.desc: Verify chords and another key suppress a pending or active gesture.
 * @tc.type: FUNC
 */
HWTEST_F(PttControllerTest, PttController_Suppression_001, TestSize.Level0)
{
    auto chordedSpaceDown = MakeKeyboardEvent(MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN,
        { MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEYCODE_A });
    auto spaceDown = MakeKeyboardEvent(
        MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN, { MMI::KeyEvent::KEYCODE_SPACE });
    auto spaceUp = MakeKeyboardEvent(MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_UP);
    auto otherDown = MakeKeyboardEvent(MMI::KeyEvent::KEYCODE_A, MMI::KeyEvent::KEY_ACTION_DOWN);
    auto otherUp = MakeKeyboardEvent(MMI::KeyEvent::KEYCODE_A, MMI::KeyEvent::KEY_ACTION_UP);

    EXPECT_EQ(controller_.HandleKeyEvent(chordedSpaceDown), PttAction::NONE);
    EXPECT_EQ(controller_.GetState(), PttState::SUPPRESSED);
    EXPECT_EQ(controller_.HandleKeyEvent(otherDown), PttAction::NONE);
    EXPECT_EQ(controller_.HandleKeyEvent(spaceUp), PttAction::NONE);
    EXPECT_EQ(controller_.GetState(), PttState::IDLE);

    EXPECT_EQ(controller_.HandleKeyEvent(spaceDown), PttAction::START_TIMER);
    EXPECT_EQ(controller_.HandleKeyEvent(otherDown), PttAction::CANCEL_TIMER);
    EXPECT_EQ(controller_.GetState(), PttState::SUPPRESSED);
    EXPECT_EQ(controller_.HandleKeyEvent(spaceUp), PttAction::NONE);

    EXPECT_EQ(controller_.HandleKeyEvent(spaceDown), PttAction::START_TIMER);
    EXPECT_EQ(controller_.HandleTimeout(), PttAction::START_VOICE);
    EXPECT_EQ(controller_.HandleKeyEvent(otherUp), PttAction::STOP_VOICE);
    EXPECT_EQ(controller_.GetState(), PttState::SUPPRESSED);
    EXPECT_EQ(controller_.HandleKeyEvent(spaceUp), PttAction::NONE);
    EXPECT_EQ(controller_.GetState(), PttState::IDLE);
}

/**
 * @tc.name: PttController_ResetAndExplicitSuppress_001
 * @tc.desc: Verify cleanup actions for every controller state.
 * @tc.type: FUNC
 */
HWTEST_F(PttControllerTest, PttController_ResetAndExplicitSuppress_001, TestSize.Level0)
{
    auto spaceDown = MakeKeyboardEvent(
        MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN, { MMI::KeyEvent::KEYCODE_SPACE });

    EXPECT_EQ(controller_.Reset(), PttAction::NONE);
    EXPECT_EQ(controller_.SuppressUntilSpaceUp(), PttState::IDLE);

    EXPECT_EQ(controller_.HandleKeyEvent(spaceDown), PttAction::START_TIMER);
    EXPECT_EQ(controller_.Reset(), PttAction::CANCEL_TIMER);
    EXPECT_EQ(controller_.GetState(), PttState::IDLE);

    EXPECT_EQ(controller_.HandleKeyEvent(spaceDown), PttAction::START_TIMER);
    EXPECT_EQ(controller_.HandleTimeout(), PttAction::START_VOICE);
    EXPECT_EQ(controller_.Reset(), PttAction::STOP_VOICE);
    EXPECT_EQ(controller_.GetState(), PttState::IDLE);

    EXPECT_EQ(controller_.HandleKeyEvent(spaceDown), PttAction::START_TIMER);
    EXPECT_EQ(controller_.SuppressUntilSpaceUp(), PttState::SUPPRESSED);
    EXPECT_EQ(controller_.Reset(), PttAction::NONE);
    EXPECT_EQ(controller_.GetState(), PttState::IDLE);
}
} // namespace MiscServices
} // namespace OHOS
