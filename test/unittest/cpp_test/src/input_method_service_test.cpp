/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <sys/time.h>

#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#define private public
#include "global.h"
#include "im_common_event_manager.h"
#include "input_manager.h"
#include "input_method_controller.h"
#include "key_event.h"
#include "key_event_util.h"
#include "pointer_event.h"
#include "full_ime_info_manager.h"
#include "ime_info_inquirer.h"
#undef private

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace MMI;
namespace {
constexpr int32_t TIME_WAIT_FOR_HANDLE_KEY_EVENT = 10000;
constexpr int32_t MAIN_USER_ID = 100;
} // namespace

class InputMethodServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void InputMethodServiceTest::SetUpTestCase(void)
{
    IMSA_HILOGI("InputMethodServiceTest::SetUpTestCase");
}

void InputMethodServiceTest::TearDownTestCase(void)
{
    IMSA_HILOGI("InputMethodServiceTest::TearDownTestCase");
}

void InputMethodServiceTest::SetUp(void)
{
    IMSA_HILOGI("InputMethodServiceTest::SetUp");
}

void InputMethodServiceTest::TearDown(void)
{
    IMSA_HILOGI("InputMethodServiceTest::TearDown");
}

/**
 * @tc.name: test_KeyEvent_UNKNOWN_001
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_UNKNOWN_001, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_UNKNOWN_001 TEST START");
    bool result = KeyEventUtil::SimulateKeyEvent(MMI::KeyEvent::KEYCODE_0);
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_UNKNOWN_002
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_UNKNOWN_002, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_UNKNOWN_002 TEST START");
    bool result = KeyEventUtil::SimulateKeyEvents({ MMI::KeyEvent::KEYCODE_0, MMI::KeyEvent::KEYCODE_1 });
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_CAPS_001
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_CAPS_001, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_CAPS_001 TEST START");
    bool result = KeyEventUtil::SimulateKeyEvent(MMI::KeyEvent::KEYCODE_CAPS_LOCK);
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_CTRL_001
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_CTRL_001, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_CTRL_001 TEST START");
    bool result = KeyEventUtil::SimulateKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_LEFT);
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_CTRL_002
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_CTRL_002, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_CTRL_002 TEST START");
    bool result = KeyEventUtil::SimulateKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_RIGHT);
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_SHIFT_001
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_SHIFT_001, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_SHIFT_001 TEST START");
    bool result = KeyEventUtil::SimulateKeyEvent(MMI::KeyEvent::KEYCODE_SHIFT_LEFT);
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_SHIFT_002
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_SHIFT_002, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_SHIFT_002 TEST START");
    bool result = KeyEventUtil::SimulateKeyEvent(MMI::KeyEvent::KEYCODE_SHIFT_RIGHT);
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_CTRL_SHIFT_001
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_CTRL_SHIFT_001, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_CTRL_SHIFT_001 TEST START");
    bool result =
        KeyEventUtil::SimulateKeyEvents({ MMI::KeyEvent::KEYCODE_CTRL_LEFT, MMI::KeyEvent::KEYCODE_SHIFT_LEFT });
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_CTRL_SHIFT_002
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_CTRL_SHIFT_002, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_CTRL_SHIFT_002 TEST START");
    bool result =
        KeyEventUtil::SimulateKeyEvents({ MMI::KeyEvent::KEYCODE_CTRL_LEFT, MMI::KeyEvent::KEYCODE_SHIFT_RIGHT });
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_CTRL_SHIFT_003
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_CTRL_SHIFT_003, TestSize.Level1)
{
    IMSA_HILOGI("test_KeyEvent_CTRL_SHIFT_003 TEST START");
    bool result =
        KeyEventUtil::SimulateKeyEvents({ MMI::KeyEvent::KEYCODE_CTRL_RIGHT, MMI::KeyEvent::KEYCODE_SHIFT_LEFT });
    EXPECT_TRUE(result);
    usleep(TIME_WAIT_FOR_HANDLE_KEY_EVENT);
}

/**
 * @tc.name: test_KeyEvent_CTRL_SHIFT_004
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, test_KeyEvent_CTRL_SHIFT_004, TestSize.Level1)
{
    IMSA_HILOGI("SubscribeKeyboardEvent007 TEST START");
    bool result =
        KeyEventUtil::SimulateKeyEvents({ MMI::KeyEvent::KEYCODE_CTRL_RIGHT, MMI::KeyEvent::KEYCODE_SHIFT_RIGHT });
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventSubscriber_IfNeedToBeProcessed_PackageRemoved_Exists_001
 * @tc.desc: Test IfNeedToBeProcessed with MSG_ID_PACKAGE_REMOVED when bundle exists
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, EventSubscriber_IfNeedToBeProcessed_PackageRemoved_Exists_001, TestSize.Level1)
{
    IMSA_HILOGI("EventSubscriber_IfNeedToBeProcessed_PackageRemoved_Exists_001 TEST START");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("test_event");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ImCommonEventManager::EventSubscriber>(subscriberInfo);

    int32_t userId = MAIN_USER_ID;
    std::string bundleName = "test.input.method";

    FullImeInfo info;
    info.prop.name = bundleName;
    FullImeInfoManager::GetInstance().fullImeInfos_[userId].push_back(info);

    auto result = subscriber->IfNeedToBeProcessed(MessageID::MSG_ID_PACKAGE_REMOVED, userId, bundleName);

    EXPECT_EQ(result.first, true);
    EXPECT_EQ(result.second, MessageID::MSG_ID_PACKAGE_REMOVED);

    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
}

/**
 * @tc.name: EventSubscriber_IfNeedToBeProcessed_PackageRemoved_NotExists_002
 * @tc.desc: Test IfNeedToBeProcessed with MSG_ID_PACKAGE_REMOVED when bundle does not exist
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, EventSubscriber_IfNeedToBeProcessed_PackageRemoved_NotExists_002, TestSize.Level1)
{
    IMSA_HILOGI("EventSubscriber_IfNeedToBeProcessed_PackageRemoved_NotExists_002 TEST START");

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("test_event");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ImCommonEventManager::EventSubscriber>(subscriberInfo);

    int32_t userId = MAIN_USER_ID;
    std::string bundleName = "nonexistent.input.method";

    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);

    auto result = subscriber->IfNeedToBeProcessed(MessageID::MSG_ID_PACKAGE_REMOVED, userId, bundleName);

    EXPECT_EQ(result.first, false); // 不需要处理
    EXPECT_EQ(result.second, MessageID::MSG_ID_PACKAGE_REMOVED);
}

/**
 * @tc.name: EventSubscriber_IfNeedToBeProcessed_PackageChanged_InputMethod_003
 * @tc.desc: Test IfNeedToBeProcessed with MSG_ID_PACKAGE_CHANGED when bundle is input method
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, EventSubscriber_IfNeedToBeProcessed_PackageChanged_InputMethod_003, TestSize.Level1)
{
    IMSA_HILOGI("EventSubscriber_IfNeedToBeProcessed_PackageChanged_InputMethod_003 TEST START");

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("test_event");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ImCommonEventManager::EventSubscriber>(subscriberInfo);

    int32_t userId = MAIN_USER_ID;
    std::string bundleName = "test.input.method";

    FullImeInfo info;
    info.prop.name = bundleName;
    FullImeInfoManager::GetInstance().fullImeInfos_[userId].push_back(info);

    auto result = subscriber->IfNeedToBeProcessed(MessageID::MSG_ID_PACKAGE_CHANGED, userId, bundleName);

    EXPECT_EQ(result.first, true);
    EXPECT_EQ(result.second, MessageID::MSG_ID_PACKAGE_REMOVED);

    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
}

/**
 * @tc.name: EventSubscriber_IfNeedToBeProcessed_PackageChanged_NoLongerInputMethod_004
 * @tc.desc: Test IfNeedToBeProcessed with MSG_ID_PACKAGE_CHANGED when bundle was input method but no longer is
 * @tc.type: FUNC
 */
HWTEST_F(
    InputMethodServiceTest, EventSubscriber_IfNeedToBeProcessed_PackageChanged_NoLongerInputMethod_004, TestSize.Level1)
{
    IMSA_HILOGI("EventSubscriber_IfNeedToBeProcessed_PackageChanged_NoLongerInputMethod_004 TEST START");

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("test_event");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ImCommonEventManager::EventSubscriber>(subscriberInfo);

    int32_t userId = MAIN_USER_ID;
    std::string bundleName = "test.input.method.changed";

    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);

    auto result = subscriber->IfNeedToBeProcessed(MessageID::MSG_ID_PACKAGE_CHANGED, userId, bundleName);

    EXPECT_EQ(result.first, false);
    EXPECT_EQ(result.second, MessageID::MSG_ID_PACKAGE_CHANGED);
}

/**
 * @tc.name: ImCommonEventManager_HandlePackageEvent_Processed_001
 * @tc.desc: Test HandlePackageEvent when IfNeedToBeProcessed returns true (condition inside if is true)
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, ImCommonEventManager_HandlePackageEvent_Processed_001, TestSize.Level1)
{
    IMSA_HILOGI("ImCommonEventManager_HandlePackageEvent_Processed_001 TEST START");

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("test.event");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ImCommonEventManager::EventSubscriber>(subscriberInfo);

    int32_t userId = MAIN_USER_ID;
    std::string bundleName = "com.example.testinputmethod";

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    want.SetElementName("device_id", bundleName, "ability_name");
    want.SetParam("userId", userId);

    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);

    subscriber->AddPackage(eventData);

    EXPECT_TRUE(FullImeInfoManager::GetInstance().fullImeInfos_[userId].empty());
}
} // namespace MiscServices
} // namespace OHOS