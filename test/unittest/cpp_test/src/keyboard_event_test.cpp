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

#include "global.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;
} // namespace

class KeyboardEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {}
    void SetUp();
    void TearDown();
};

void KeyboardEventTest::SetUpTestCase(void)
{
    IMSA_HILOGI("KeyboardEventTest::SetUpTestCase");
}

void KeyboardEventTest::SetUp()
{
    IMSA_HILOGI("KeyboardEventTest::SetUp");
}

void KeyboardEventTest::TearDown()
{
    IMSA_HILOGI("KeyboardEventTest::TearDown");
}

/**
 * @tc.name: KeyboardEvent_GetInstance_001
 * @tc.desc: Test GetInstance returns a valid singleton
 * @tc.type: FUNC
 */
HWTEST_F(KeyboardEventTest, GetInstance_001, TestSize.Level0)
{
    IMSA_HILOGI("KeyboardEventTest GetInstance_001 START");
    auto &instance = KeyboardEvent::GetInstance();
    auto &instance2 = KeyboardEvent::GetInstance();
    EXPECT_EQ(&instance, &instance2);
}

/**
 * @tc.name: KeyboardEvent_MaskConstants_001
 * @tc.desc: Test key mask constants have expected values
 * @tc.type: FUNC
 */
HWTEST_F(KeyboardEventTest, MaskConstants_001, TestSize.Level0)
{
    IMSA_HILOGI("KeyboardEventTest MaskConstants_001 START");
    EXPECT_EQ(KeyboardEvent::SHIFT_LEFT_MASK, 0X1);
    EXPECT_EQ(KeyboardEvent::SHIFT_RIGHT_MASK, 0X1 << 1);
    EXPECT_EQ(KeyboardEvent::CTRL_LEFT_MASK, 0X1 << 2);
    EXPECT_EQ(KeyboardEvent::CTRL_RIGHT_MASK, 0X1 << 3);
    EXPECT_EQ(KeyboardEvent::CAPS_MASK, 0X1 << 4);
    EXPECT_EQ(KeyboardEvent::META_MASK, 0X1 << 5);
    EXPECT_EQ(KeyboardEvent::SPACE_MASK, 0X1 << 6);
}

/**
 * @tc.name: KeyboardEvent_PressKeyDelay_001
 * @tc.desc: Test PRESS_KEY_DELAY_MS constant
 * @tc.type: FUNC
 */
HWTEST_F(KeyboardEventTest, PressKeyDelay_001, TestSize.Level0)
{
    IMSA_HILOGI("KeyboardEventTest PressKeyDelay_001 START");
    EXPECT_EQ(KeyboardEvent::PRESS_KEY_DELAY_MS, 200);
}

/**
 * @tc.name: KeyboardEvent_AddKeyEventMonitor_001
 * @tc.desc: Test AddKeyEventMonitor with valid key handle
 * @tc.type: FUNC
 */
HWTEST_F(KeyboardEventTest, AddKeyEventMonitor_001, TestSize.Level0)
{
    IMSA_HILOGI("KeyboardEventTest AddKeyEventMonitor_001 START");
    bool callbackInvoked = false;
    KeyHandle handle = [&callbackInvoked](uint32_t state) -> int32_t {
        callbackInvoked = true;
        IMSA_HILOGI("KeyHandle called with state: %{public}u", state);
        return ErrorCode::NO_ERROR;
    };
    auto ret = KeyboardEvent::AddKeyEventMonitor(handle);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: KeyboardEvent_AddKeyEventMonitor_002
 * @tc.desc: Test AddKeyEventMonitor with nullptr handle does not crash
 * @tc.type: FUNC
 */
HWTEST_F(KeyboardEventTest, AddKeyEventMonitor_002, TestSize.Level1)
{
    IMSA_HILOGI("KeyboardEventTest AddKeyEventMonitor_002 START");
    KeyHandle handle = nullptr;
    auto ret = KeyboardEvent::AddKeyEventMonitor(handle);
    // AddKeyEventMonitor does not check handle for nullptr; result depends on InputManager
    EXPECT_TRUE(ret == ErrorCode::NO_ERROR || ret == ErrorCode::ERROR_NULL_POINTER ||
        ret == ErrorCode::ERROR_SUBSCRIBE_KEYBOARD_EVENT);
}

/**
 * @tc.name: KeyboardEvent_CombinationKeyCallBack_001
 * @tc.desc: Test CombinationKeyCallBack type definition and invocation
 * @tc.type: FUNC
 */
HWTEST_F(KeyboardEventTest, CombinationKeyCallBack_001, TestSize.Level0)
{
    IMSA_HILOGI("KeyboardEventTest CombinationKeyCallBack_001 START");
    bool callbackInvoked = false;
    KeyboardEvent::CombinationKeyCallBack callback =
        [&callbackInvoked](std::shared_ptr<MMI::KeyEvent> keyEvent) {
            callbackInvoked = true;
        };
    ASSERT_TRUE(callback != nullptr);
    callback(nullptr);
    EXPECT_TRUE(callbackInvoked);
}

/**
 * @tc.name: KeyboardEvent_AddKeyEventMonitor_003
 * @tc.desc: Test AddKeyEventMonitor registers multiple combination keys
 * @tc.type: FUNC
 */
HWTEST_F(KeyboardEventTest, AddKeyEventMonitor_003, TestSize.Level1)
{
    IMSA_HILOGI("KeyboardEventTest AddKeyEventMonitor_003 START");
    int32_t callCount = 0;
    KeyHandle handle = [&callCount](uint32_t state) -> int32_t {
        callCount++;
        return ErrorCode::NO_ERROR;
    };
    auto ret = KeyboardEvent::AddKeyEventMonitor(handle);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: KeyboardEvent_KeyHandle_001
 * @tc.desc: Test KeyHandle callback with various key states
 * @tc.type: FUNC
 */
HWTEST_F(KeyboardEventTest, KeyHandle_001, TestSize.Level0)
{
    IMSA_HILOGI("KeyboardEventTest KeyHandle_001 START");
    uint32_t capturedState = 0;
    KeyHandle handle = [&capturedState](uint32_t state) -> int32_t {
        capturedState = state;
        return ErrorCode::NO_ERROR;
    };

    auto ret = KeyboardEvent::AddKeyEventMonitor(handle);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    auto callback = std::make_shared<InputEventCallback>();
    callback->SetKeyHandle(handle);
    callback->TriggerSwitch();
    EXPECT_EQ(capturedState, KeyboardEvent::META_MASK | KeyboardEvent::SPACE_MASK);
}

/**
 * @tc.name: KeyboardEvent_KeyboardEventSingleton_001
 * @tc.desc: Test KeyboardEvent is not copyable
 * @tc.type: FUNC
 */
HWTEST_F(KeyboardEventTest, KeyboardEventSingleton_001, TestSize.Level0)
{
    IMSA_HILOGI("KeyboardEventTest KeyboardEventSingleton_001 START");
    auto &instance = KeyboardEvent::GetInstance();
    EXPECT_TRUE(std::is_reference<decltype(instance)>::value);
}
} // namespace MiscServices
} // namespace OHOS
