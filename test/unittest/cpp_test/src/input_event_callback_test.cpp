/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "input_event_callback.h"
#include "keyboard_event.h"

#include <gtest/gtest.h>

#include <vector>

#include "global.h"
#include "key_event.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;

std::shared_ptr<MMI::KeyEvent> MakePttRoutingEvent(
    int32_t keyCode, int32_t keyAction, const std::vector<int32_t> &pressedKeys = {})
{
    auto keyEvent = MMI::KeyEvent::Create();
    if (keyEvent == nullptr) {
        return nullptr;
    }
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(keyAction);
    for (int32_t pressedKey : pressedKeys) {
        MMI::KeyEvent::KeyItem keyItem;
        keyItem.SetKeyCode(pressedKey);
        keyItem.SetPressed(true);
        keyEvent->AddKeyItem(keyItem);
    }
    return keyEvent;
}
} // namespace

class InputEventCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {}
    void SetUp();
    void TearDown();
};

void InputEventCallbackTest::SetUpTestCase(void)
{
    IMSA_HILOGI("InputEventCallbackTest::SetUpTestCase");
}

void InputEventCallbackTest::SetUp()
{
    IMSA_HILOGI("InputEventCallbackTest::SetUp");
    InputEventCallback::keyState_ = 0;
    InputEventCallback::isKeyHandled_ = false;
}

void InputEventCallbackTest::TearDown()
{
    IMSA_HILOGI("InputEventCallbackTest::TearDown");
}

/**
 * @tc.name: InputEventCallback_SetKeyHandle_001
 * @tc.desc: Test SetKeyHandle with valid handler
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, SetKeyHandle_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest SetKeyHandle_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    bool handlerInvoked = false;
    KeyHandle handle = [&handlerInvoked](uint32_t state) -> int32_t {
        handlerInvoked = true;
        return ErrorCode::NO_ERROR;
    };
    callback->SetKeyHandle(handle);
    EXPECT_TRUE(callback->keyHandler_ != nullptr);
}

/**
 * @tc.name: InputEventCallback_SetKeyHandle_002
 * @tc.desc: Test SetKeyHandle with nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, SetKeyHandle_002, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest SetKeyHandle_002 START");
    auto callback = std::make_shared<InputEventCallback>();
    callback->SetKeyHandle(nullptr);
    EXPECT_TRUE(callback->keyHandler_ == nullptr);
}

/**
 * @tc.name: InputEventCallback_OnInputEvent_NullKeyEvent_001
 * @tc.desc: Test OnInputEvent with null keyEvent
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, OnInputEvent_NullKeyEvent_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest OnInputEvent_NullKeyEvent_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    bool handlerInvoked = false;
    callback->SetKeyHandle([&handlerInvoked](uint32_t state) -> int32_t {
        handlerInvoked = true;
        return ErrorCode::NO_ERROR;
    });
    callback->OnInputEvent(std::shared_ptr<MMI::KeyEvent>(nullptr));
    EXPECT_FALSE(handlerInvoked);
}

/**
 * @tc.name: InputEventCallback_OnInputEvent_CapsLockDown_001
 * @tc.desc: Test OnInputEvent with caps lock key down
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, OnInputEvent_CapsLockDown_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest OnInputEvent_CapsLockDown_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    uint32_t capturedState = 0;
    bool handlerInvoked = false;
    callback->SetKeyHandle([&capturedState, &handlerInvoked](uint32_t state) -> int32_t {
        capturedState = state;
        handlerInvoked = true;
        return ErrorCode::NO_ERROR;
    });
    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    MMI::KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyItem.SetPressed(true);
    keyEvent->SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddKeyItem(keyItem);
    callback->OnInputEvent(keyEvent);
    EXPECT_TRUE(handlerInvoked);
    EXPECT_TRUE((capturedState & KeyboardEvent::CAPS_MASK) != 0);
    EXPECT_TRUE(InputEventCallback::isKeyHandled_);
}

/**
 * @tc.name: InputEventCallback_OnInputEvent_CapsLockUp_001
 * @tc.desc: Test OnInputEvent with caps lock key up
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, OnInputEvent_CapsLockUp_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest OnInputEvent_CapsLockUp_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    InputEventCallback::keyState_ = KeyboardEvent::CAPS_MASK;
    InputEventCallback::isKeyHandled_ = true;
    uint32_t capturedState = 0;
    bool handlerInvoked = false;
    callback->SetKeyHandle([&capturedState, &handlerInvoked](uint32_t state) -> int32_t {
        capturedState = state;
        handlerInvoked = true;
        return ErrorCode::NO_ERROR;
    });
    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    MMI::KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyItem.SetPressed(false);
    keyEvent->SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_UP);
    keyEvent->AddKeyItem(keyItem);
    callback->OnInputEvent(keyEvent);
    EXPECT_FALSE(handlerInvoked);
    EXPECT_EQ(InputEventCallback::keyState_ & KeyboardEvent::CAPS_MASK, 0);
}

/**
 * @tc.name: InputEventCallback_OnInputEvent_UnknownKey_001
 * @tc.desc: Test OnInputEvent with unknown key code
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, OnInputEvent_UnknownKey_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest OnInputEvent_UnknownKey_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    bool handlerInvoked = false;
    callback->SetKeyHandle([&handlerInvoked](uint32_t state) -> int32_t {
        handlerInvoked = true;
        return ErrorCode::NO_ERROR;
    });
    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    MMI::KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(MMI::KeyEvent::KEYCODE_A);
    keyItem.SetPressed(true);
    keyEvent->SetKeyCode(MMI::KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddKeyItem(keyItem);
    callback->OnInputEvent(keyEvent);
    EXPECT_FALSE(handlerInvoked);
    EXPECT_EQ(InputEventCallback::keyState_, 0);
}

/**
 * @tc.name: InputEventCallback_OnInputEvent_CapsLockUp_NotHandled_001
 * @tc.desc: Test OnInputEvent with caps lock key up when not previously handled
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, OnInputEvent_CapsLockUp_NotHandled_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest OnInputEvent_CapsLockUp_NotHandled_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    InputEventCallback::keyState_ = KeyboardEvent::CAPS_MASK;
    InputEventCallback::isKeyHandled_ = false;
    uint32_t capturedState = 0;
    bool handlerInvoked = false;
    callback->SetKeyHandle([&capturedState, &handlerInvoked](uint32_t state) -> int32_t {
        capturedState = state;
        handlerInvoked = true;
        return ErrorCode::NO_ERROR;
    });
    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    MMI::KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyItem.SetPressed(false);
    keyEvent->SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_UP);
    keyEvent->AddKeyItem(keyItem);
    callback->OnInputEvent(keyEvent);
    EXPECT_TRUE(handlerInvoked);
    EXPECT_TRUE((capturedState & KeyboardEvent::CAPS_MASK) != 0);
    EXPECT_EQ(InputEventCallback::keyState_ & KeyboardEvent::CAPS_MASK, 0);
}

/**
 * @tc.name: InputEventCallback_OnInputEvent_CapsLockUp_NoHandler_001
 * @tc.desc: Test OnInputEvent with caps lock key up and no keyHandler set
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, OnInputEvent_CapsLockUp_NoHandler_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest OnInputEvent_CapsLockUp_NoHandler_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    InputEventCallback::keyState_ = KeyboardEvent::CAPS_MASK;
    InputEventCallback::isKeyHandled_ = false;
    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    MMI::KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyItem.SetPressed(false);
    keyEvent->SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_UP);
    keyEvent->AddKeyItem(keyItem);
    callback->OnInputEvent(keyEvent);
    EXPECT_EQ(InputEventCallback::keyState_ & KeyboardEvent::CAPS_MASK, 0);
}

/**
 * @tc.name: InputEventCallback_TriggerSwitch_001
 * @tc.desc: Test TriggerSwitch with keyHandler set
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, TriggerSwitch_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest TriggerSwitch_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    uint32_t capturedState = 0;
    bool handlerInvoked = false;
    callback->SetKeyHandle([&capturedState, &handlerInvoked](uint32_t state) -> int32_t {
        capturedState = state;
        handlerInvoked = true;
        return ErrorCode::NO_ERROR;
    });
    callback->TriggerSwitch();
    EXPECT_TRUE(handlerInvoked);
    EXPECT_EQ(capturedState, KeyboardEvent::META_MASK | KeyboardEvent::SPACE_MASK);
}

/**
 * @tc.name: InputEventCallback_TriggerSwitch_002
 * @tc.desc: Test TriggerSwitch with no keyHandler set
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, TriggerSwitch_002, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest TriggerSwitch_002 START");
    auto callback = std::make_shared<InputEventCallback>();
    callback->SetKeyHandle(nullptr);
    callback->TriggerSwitch();
    EXPECT_TRUE(callback->keyHandler_ == nullptr);
}

/**
 * @tc.name: InputEventCallback_OnInputEvent_PointerEvent_001
 * @tc.desc: Test OnInputEvent with pointer event (should not crash)
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, OnInputEvent_PointerEvent_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest OnInputEvent_PointerEvent_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    callback->OnInputEvent(pointerEvent);
}

/**
 * @tc.name: InputEventCallback_OnInputEvent_AxisEvent_001
 * @tc.desc: Test OnInputEvent with axis event (should not crash)
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, OnInputEvent_AxisEvent_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest OnInputEvent_AxisEvent_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    auto axisEvent = MMI::AxisEvent::Create();
    ASSERT_TRUE(axisEvent != nullptr);
    callback->OnInputEvent(axisEvent);
}

/**
 * @tc.name: InputEventCallback_OnInputEvent_CapsLockDown_NoHandler_001
 * @tc.desc: Test OnInputEvent with caps lock key down and no handler
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, OnInputEvent_CapsLockDown_NoHandler_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest OnInputEvent_CapsLockDown_NoHandler_001 START");
    auto callback = std::make_shared<InputEventCallback>();
    callback->SetKeyHandle(nullptr);
    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    MMI::KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyItem.SetPressed(true);
    keyEvent->SetKeyCode(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    keyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddKeyItem(keyItem);
    callback->OnInputEvent(keyEvent);
    EXPECT_TRUE((InputEventCallback::keyState_ & KeyboardEvent::CAPS_MASK) != 0);
    EXPECT_TRUE(InputEventCallback::isKeyHandled_);
}

/**
 * @tc.name: InputEventCallback_StaticState_001
 * @tc.desc: Test keyState_ and isKeyHandled_ static members initial state
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, StaticState_001, TestSize.Level0)
{
    IMSA_HILOGI("InputEventCallbackTest StaticState_001 START");
    InputEventCallback::keyState_ = 0;
    InputEventCallback::isKeyHandled_ = false;
    EXPECT_EQ(InputEventCallback::keyState_, 0);
    EXPECT_FALSE(InputEventCallback::isKeyHandled_);
}

/**
 * @tc.name: InputEventCallback_PttHandlerConfiguration_001
 * @tc.desc: Test PTT handler assignment and null event filtering.
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, PttHandlerConfiguration_001, TestSize.Level0)
{
    auto callback = std::make_shared<InputEventCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_FALSE(callback->ShouldForwardPttKeyEvent(nullptr));

    callback->SetKeyEventMonitorHandler([](const KeyboardEventInfo &eventInfo) {});
    EXPECT_NE(callback->keyEventHandler_, nullptr);
    callback->SetKeyEventMonitorHandler(nullptr);
    EXPECT_EQ(callback->keyEventHandler_, nullptr);
}

/**
 * @tc.name: InputEventCallback_PttSpaceSequence_001
 * @tc.desc: Test initial space down, repeat suppression, and release forwarding.
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, PttSpaceSequence_001, TestSize.Level0)
{
    auto callback = std::make_shared<InputEventCallback>();
    ASSERT_NE(callback, nullptr);
    std::vector<KeyboardEventInfo> events;
    callback->SetKeyEventMonitorHandler([&events](const KeyboardEventInfo &eventInfo) {
        events.push_back(eventInfo);
    });
    auto spaceDown = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN,
        { MMI::KeyEvent::KEYCODE_SPACE });
    auto spaceUp = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_UP);
    ASSERT_NE(spaceDown, nullptr);
    ASSERT_NE(spaceUp, nullptr);

    callback->OnInputEvent(spaceDown);
    ASSERT_EQ(events.size(), 1);
    EXPECT_EQ(events[0].keyCode, MMI::KeyEvent::KEYCODE_SPACE);
    EXPECT_EQ(events[0].keyAction, MMI::KeyEvent::KEY_ACTION_DOWN);
    EXPECT_EQ(events[0].pressedKeys, std::vector<int32_t>({ MMI::KeyEvent::KEYCODE_SPACE }));
    EXPECT_EQ(callback->pttRoutingState_, InputEventCallback::PttRoutingState::TRACKING);

    callback->OnInputEvent(spaceDown);
    EXPECT_EQ(events.size(), 1);
    callback->OnInputEvent(spaceUp);
    ASSERT_EQ(events.size(), 2);
    EXPECT_EQ(events[1].keyAction, MMI::KeyEvent::KEY_ACTION_UP);
    EXPECT_TRUE(events[1].pressedKeys.empty());
    EXPECT_EQ(callback->pttRoutingState_, InputEventCallback::PttRoutingState::IDLE);

    callback->OnInputEvent(spaceUp);
    EXPECT_EQ(events.size(), 2);
}

/**
 * @tc.name: InputEventCallback_PttSuppression_001
 * @tc.desc: Test chord suppression and cancellation by another key.
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, PttSuppression_001, TestSize.Level0)
{
    auto callback = std::make_shared<InputEventCallback>();
    ASSERT_NE(callback, nullptr);
    std::vector<KeyboardEventInfo> events;
    callback->SetKeyEventMonitorHandler([&events](const KeyboardEventInfo &eventInfo) {
        events.push_back(eventInfo);
    });
    auto chordedSpaceDown = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN,
        { MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEYCODE_A });
    auto spaceDown = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN,
        { MMI::KeyEvent::KEYCODE_SPACE });
    auto spaceUp = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_UP);
    auto otherDown = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_A, MMI::KeyEvent::KEY_ACTION_DOWN);
    auto otherUp = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_A, MMI::KeyEvent::KEY_ACTION_UP);
    ASSERT_NE(chordedSpaceDown, nullptr);
    ASSERT_NE(spaceDown, nullptr);
    ASSERT_NE(spaceUp, nullptr);
    ASSERT_NE(otherDown, nullptr);
    ASSERT_NE(otherUp, nullptr);

    callback->OnInputEvent(chordedSpaceDown);
    EXPECT_TRUE(events.empty());
    EXPECT_EQ(callback->pttRoutingState_, InputEventCallback::PttRoutingState::SUPPRESSED);
    callback->OnInputEvent(otherDown);
    EXPECT_TRUE(events.empty());
    callback->OnInputEvent(spaceUp);
    ASSERT_EQ(events.size(), 1);
    EXPECT_EQ(callback->pttRoutingState_, InputEventCallback::PttRoutingState::IDLE);

    callback->OnInputEvent(spaceDown);
    callback->OnInputEvent(otherDown);
    ASSERT_EQ(events.size(), 3);
    EXPECT_EQ(events[2].keyCode, MMI::KeyEvent::KEYCODE_A);
    EXPECT_EQ(callback->pttRoutingState_, InputEventCallback::PttRoutingState::SUPPRESSED);
    callback->OnInputEvent(otherUp);
    EXPECT_EQ(events.size(), 3);
    callback->OnInputEvent(spaceUp);
    EXPECT_EQ(events.size(), 4);
    EXPECT_EQ(callback->pttRoutingState_, InputEventCallback::PttRoutingState::IDLE);
}

/**
 * @tc.name: InputEventCallback_PttInvalidActions_001
 * @tc.desc: Test idle non-space events and unsupported key actions are ignored.
 * @tc.type: FUNC
 */
HWTEST_F(InputEventCallbackTest, PttInvalidActions_001, TestSize.Level0)
{
    auto callback = std::make_shared<InputEventCallback>();
    ASSERT_NE(callback, nullptr);
    int32_t callCount = 0;
    callback->SetKeyEventMonitorHandler([&callCount](const KeyboardEventInfo &eventInfo) {
        ++callCount;
    });
    auto otherDown = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_A, MMI::KeyEvent::KEY_ACTION_DOWN);
    auto invalidOther = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_A, -1);
    auto invalidSpace = MakePttRoutingEvent(MMI::KeyEvent::KEYCODE_SPACE, -1);
    ASSERT_NE(otherDown, nullptr);
    ASSERT_NE(invalidOther, nullptr);
    ASSERT_NE(invalidSpace, nullptr);

    callback->OnInputEvent(otherDown);
    callback->OnInputEvent(invalidOther);
    callback->OnInputEvent(invalidSpace);
    EXPECT_EQ(callCount, 0);
    EXPECT_EQ(callback->pttRoutingState_, InputEventCallback::PttRoutingState::IDLE);
}
} // namespace MiscServices
} // namespace OHOS
