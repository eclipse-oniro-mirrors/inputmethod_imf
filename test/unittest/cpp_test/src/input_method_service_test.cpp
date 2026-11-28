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

#if !defined(target_cpu_x86_64) // x86_64_virt emulator: suite unstable/fails, isolated

#include <gtest/gtest.h>
#include <sys/time.h>

#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "global.h"
#include "im_common_event_manager.h"
#include "input_manager.h"
#include "input_method_controller.h"
#include "key_event.h"
#include "key_event_util.h"
#include "pointer_event.h"
#include "full_ime_info_manager.h"
#include "ime_info_inquirer.h"
#include "input_method_system_ability.h"
#include "identity_checker_impl.h"
#include "identity_checker_mock.h"
#include "user_session_manager.h"
#include "peruser_session.h"
#include "input_method_core_service_impl.h"
#include "input_method_agent_service_impl.h"
#include "input_client_service_impl.h"
#include "input_type_manager.h"
#include "ipc_skeleton.h"
#include "window_adapter.h"
#include "tdd_util.h"
#include "scene_board_judgement.h"
#include "ime_enabled_info_manager.h"
#include "exam_mode_manager.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace MMI;
using namespace OHOS::Rosen;
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
    static bool isScbEnable_;
};

bool InputMethodServiceTest::isScbEnable_ { false };

void InputMethodServiceTest::SetUpTestCase(void)
{
    IMSA_HILOGI("InputMethodServiceTest::SetUpTestCase");
    isScbEnable_ = SceneBoardJudgement::IsSceneBoardEnabled();
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

/**
 * @tc.name: testConnectSystemCmd001
 * @tc.desc: Test ConnectSystemCmd when identityChecker_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, testConnectSystemCmd001, TestSize.Level1)
{
    IMSA_HILOGI("testConnectSystemCmd001 TEST START");
    sptr<IRemoteObject> channel = nullptr;
    sptr<IRemoteObject> agent = nullptr;
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    if (imsa != nullptr) {
        imsa->identityChecker_ = nullptr;
        int32_t result = imsa->ConnectSystemCmd(channel, agent);
        EXPECT_EQ(result, ErrorCode::ERROR_NULL_POINTER);
    }
}

/**
 * @tc.name: testConnectSystemCmd003
 * @tc.desc: Test ConnectSystemCmd when caller lacks PERMISSION_CONNECT_IME_ABILITY
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, testConnectSystemCmd003, TestSize.Level1)
{
    IMSA_HILOGI("testConnectSystemCmd003 TEST START");
    sptr<IRemoteObject> channel = nullptr;
    sptr<IRemoteObject> agent = nullptr;
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    if (imsa != nullptr) {
        IdentityCheckerMock::ResetParam();
        IdentityCheckerMock::SetSystemApp(true);
        IdentityCheckerMock::SetPermission(false);
        imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
        int32_t result = imsa->ConnectSystemCmd(channel, agent);
        EXPECT_EQ(result, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    }
}

/**
 * @tc.name: testConnectSystemCmd004
 * @tc.desc: Test ConnectSystemCmd when session is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, testConnectSystemCmd004, TestSize.Level1)
{
    IMSA_HILOGI("testConnectSystemCmd004 TEST START");
    sptr<IRemoteObject> channel = nullptr;
    sptr<IRemoteObject> agent = nullptr;
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    if (imsa != nullptr) {
        IdentityCheckerMock::ResetParam();
        IdentityCheckerMock::SetSystemApp(true);
        IdentityCheckerMock::SetPermission(true);
        imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
        int32_t result = imsa->ConnectSystemCmd(channel, agent);
        EXPECT_EQ(result, ErrorCode::ERROR_NULL_POINTER);
    }
}

/**
 * @tc.name: testConnectSystemCmd005
 * @tc.desc: Test ConnectSystemCmd with appIdentifier = "123" (feature app)
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, testConnectSystemCmd005, TestSize.Level1)
{
    IMSA_HILOGI("testConnectSystemCmd005 TEST START");
    sptr<IRemoteObject> channel = nullptr;
    sptr<IRemoteObject> agent = nullptr;
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    if (imsa != nullptr) {
        IdentityCheckerMock::ResetParam();
        IdentityCheckerMock::SetSystemApp(true);
        IdentityCheckerMock::SetPermission(true);
        IdentityCheckerMock::bundleName_ = "test.app";
        imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
        int32_t userId = TddUtil::GetCurrentUserId();
        auto session = std::make_shared<PerUserSession>(userId, nullptr);
        sptr<IInputMethodCore> mockCore = new (std::nothrow) InputMethodCoreServiceImpl();
        sptr<IRemoteObject> mockAgent = new (std::nothrow) InputMethodAgentServiceImpl();
        auto imeData = std::make_shared<ImeData>(mockCore, mockAgent, nullptr, 100);
        imeData->imeStatus = ImeStatus::READY;
        session->realImeData_ = imeData;
        UserSessionManager::GetInstance().userSessions_[userId] = session;
        int32_t result = imsa->ConnectSystemCmd(channel, agent);
        EXPECT_NE(result, ErrorCode::ERROR_SYSTEM_PANEL_ERROR);
        UserSessionManager::GetInstance().userSessions_.clear();
    }
}

/**
 * @tc.name: PerUserSession_SetInputType_ImeNotStarted
 * @tc.desc: Test SetInputType when real IME data is not started
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, PerUserSession_SetInputType_ImeNotStarted, TestSize.Level1)
{
    IMSA_HILOGI("PerUserSession_SetInputType_ImeNotStarted TEST START");
 
    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
 
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->config.inputAttribute.callingDisplayId = 100;
 
    int32_t result = session->SetInputType(clientInfo);
 
    EXPECT_EQ(result, ErrorCode::ERROR_IME_NOT_STARTED);
    UserSessionManager::GetInstance().userSessions_.clear();
}
 
/**
 * @tc.name: PerUserSession_SetInputType_NullClientInfo
 * @tc.desc: Test SetInputType with nullptr clientInfo
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, PerUserSession_SetInputType_NullClientInfo, TestSize.Level1)
{
    IMSA_HILOGI("PerUserSession_SetInputType_NullClientInfo TEST START");
 
    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
 
    sptr<IInputMethodCore> mockCore = new (std::nothrow) InputMethodCoreServiceImpl();
    sptr<IRemoteObject> mockAgent = new (std::nothrow) InputMethodAgentServiceImpl();
    auto imeData = std::make_shared<ImeData>(mockCore, mockAgent, nullptr, 100);
    imeData->imeStatus = ImeStatus::READY;
    session->realImeData_ = imeData;
 
    UserSessionManager::GetInstance().userSessions_[userId] = session;
 
    int32_t result = session->SetInputType(nullptr);
 
    EXPECT_EQ(result, ErrorCode::NO_ERROR);
    UserSessionManager::GetInstance().userSessions_.clear();
}
 
/**
 * @tc.name: PerUserSession_SetInputType_NormalCase
 * @tc.desc: Test SetInputType with valid clientInfo
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, PerUserSession_SetInputType_NormalCase, TestSize.Level1)
{
    IMSA_HILOGI("PerUserSession_SetInputType_NormalCase TEST START");
 
    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
 
    sptr<IInputMethodCore> mockCore = new (std::nothrow) InputMethodCoreServiceImpl();
    sptr<IRemoteObject> mockAgent = new (std::nothrow) InputMethodAgentServiceImpl();
    auto imeData = std::make_shared<ImeData>(mockCore, mockAgent, nullptr, 100);
    imeData->imeStatus = ImeStatus::READY;
    session->realImeData_ = imeData;
 
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->config.inputAttribute.callingDisplayId = 100;
 
    UserSessionManager::GetInstance().userSessions_[userId] = session;
 
    int32_t result = session->SetInputType(clientInfo);
 
    EXPECT_EQ(result, ErrorCode::NO_ERROR);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: PerUserSession_OnRequestHideInput_GetDisplayGroupIdFailed
 * @tc.desc: Test OnRequestHideInput when GetDisplayGroupIdWithRetry fails
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, PerUserSession_OnRequestHideInput_GetDisplayGroupIdFailed, TestSize.Level1)
{
    IMSA_HILOGI("PerUserSession_OnRequestHideInput_GetDisplayGroupIdFailed TEST START");

    // Clear displayGroupIds to simulate failure scenario
    WindowAdapter::GetInstance().displayGroupIds_.clear();

    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;

    // Call with invalid displayId that should fail
    uint64_t invalidDisplayId = 999;
    std::string callerBundleName = "";

    int32_t result = session->OnRequestHideInput(invalidDisplayId, callerBundleName);

    // Should return error when GetDisplayGroupIdWithRetry fails
    if (isScbEnable_) {
        EXPECT_EQ(result, ErrorCode::ERROR_INVALID_DISPLAYID);
    } else {
        EXPECT_EQ(result, ErrorCode::ERROR_USER_NOT_EXIST);
    }

    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: PerUserSession_GetClientGroup_GetDisplayGroupIdFailed
 * @tc.desc: Test GetClientGroup when GetDisplayGroupIdWithRetry fails
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, PerUserSession_GetClientGroup_GetDisplayGroupIdFailed, TestSize.Level1)
{
    IMSA_HILOGI("PerUserSession_GetClientGroup_GetDisplayGroupIdFailed TEST START");

    // Clear displayGroupIds to simulate failure scenario
    WindowAdapter::GetInstance().displayGroupIds_.clear();

    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;

    // Call with invalid displayId that should fail
    uint64_t invalidDisplayId = 888;

    auto clientGroup = session->GetClientGroup(invalidDisplayId);

    // Should return nullptr when GetDisplayGroupIdWithRetry fails
    EXPECT_EQ(clientGroup, nullptr);

    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: PerUserSession_OnWindowDisplayIdChanged_GetDisplayGroupIdFailed
 * @tc.desc: Test OnWindowDisplayIdChanged when GetDisplayGroupIdWithRetry fails
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, PerUserSession_OnWindowDisplayIdChanged_GetDisplayGroupIdFailed, TestSize.Level1)
{
    IMSA_HILOGI("PerUserSession_OnWindowDisplayIdChanged_GetDisplayGroupIdFailed TEST START");

    // Clear displayGroupIds to simulate failure scenario
    WindowAdapter::GetInstance().displayGroupIds_.clear();

    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);

    // Setup a mock client with bindImeData
    uint64_t displayGroupId = 200;
    auto clientGroup = std::make_shared<ClientGroup>(displayGroupId, nullptr);
    session->clientGroupMap_[displayGroupId] = clientGroup;

    // Create a clientInfo with necessary fields
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->clientGroupId = displayGroupId;
    clientInfo->pid = 1000;
    clientInfo->uid = 1000;
    clientInfo->userID = userId;
    clientInfo->state = ClientState::ACTIVE;
    session->clientGroupMap_[displayGroupId]->mapClients_[nullptr] = clientInfo;

    UserSessionManager::GetInstance().userSessions_[userId] = session;

    // Call with invalid displayId that should fail in GetDisplayGroupIdWithRetry
    int32_t windowId = 1;
    uint64_t invalidDisplayId = 777;

    // Verify session is properly set up
    EXPECT_NE(session, nullptr);
    EXPECT_EQ(session->clientGroupMap_.size(), 1);

    // This should return early due to GetDisplayGroupIdWithRetry failure
    session->OnWindowDisplayIdChanged(windowId, invalidDisplayId);

    // Verify session state remains consistent after error handling
    EXPECT_NE(session, nullptr);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: PerUserSession_MultipleGetDisplayGroupIdWithRetryFailures
 * @tc.desc: Test multiple GetDisplayGroupIdWithRetry calls in OnWindowDisplayIdChanged
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, PerUserSession_MultipleGetDisplayGroupIdWithRetryFailures, TestSize.Level1)
{
    IMSA_HILOGI("PerUserSession_MultipleGetDisplayGroupIdWithRetryFailures TEST START");

    // Clear displayGroupIds to simulate failure scenario
    WindowAdapter::GetInstance().displayGroupIds_.clear();

    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);

    // Setup a mock client with bindImeData and multiple displayIds
    uint64_t validDisplayGroupId = 200;
    auto clientGroup = std::make_shared<ClientGroup>(validDisplayGroupId, nullptr);
    session->clientGroupMap_[validDisplayGroupId] = clientGroup;

    // Create a clientInfo with necessary fields
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->clientGroupId = validDisplayGroupId;
    clientInfo->pid = 1000;
    clientInfo->uid = 1000;
    clientInfo->userID = userId;
    clientInfo->state = ClientState::ACTIVE;
    clientInfo->config.inputAttribute.editorDisplayId = 100;
    clientInfo->config.inputAttribute.displayGroupId = validDisplayGroupId;
    session->clientGroupMap_[validDisplayGroupId]->mapClients_[nullptr] = clientInfo;

    UserSessionManager::GetInstance().userSessions_[userId] = session;

    // Call with invalid displayId that should fail in multiple GetDisplayGroupIdWithRetry calls
    int32_t windowId = 1;
    uint64_t invalidDisplayId = 999;

    // Verify session and client are properly set up
    EXPECT_NE(session, nullptr);
    EXPECT_EQ(session->clientGroupMap_.size(), 1);
    EXPECT_NE(session->clientGroupMap_[validDisplayGroupId], nullptr);

    // This should test both GetDisplayGroupIdWithRetry calls in OnWindowDisplayIdChanged
    session->OnWindowDisplayIdChanged(windowId, invalidDisplayId);

    // Verify session state remains consistent after handling multiple errors
    EXPECT_NE(session, nullptr);
    EXPECT_EQ(session->clientGroupMap_.size(), 1);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: ShowInputInner_StylusActivation_ClientInfoNull_001
 * @tc.desc: ShowInputInner with stylus activation but no matching client info, cover 915 false branch
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, ShowInputInner_StylusActivation_ClientInfoNull_001, TestSize.Level1)
{
    IMSA_HILOGI("ShowInputInner_StylusActivation_ClientInfoNull_001 TEST START");
    InputMethodSystemAbility imsa;
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetFocused(true);
    imsa.identityChecker_ = std::make_shared<IdentityCheckerMock>();

    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;

    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);

    InputTypeManager::GetInstance().Set(false);
    auto ret = imsa.ShowInputInner(client, 0, 0, true);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);

    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: ShowInputInner_StylusActivation_StartSuccess_002
 * @tc.desc: ShowInputInner with stylus activation and stylus ime already started, cover 918 false branch
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, ShowInputInner_StylusActivation_StartSuccess_002, TestSize.Level1)
{
    IMSA_HILOGI("ShowInputInner_StylusActivation_StartSuccess_002 TEST START");
    InputMethodSystemAbility imsa;
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetFocused(true);
    imsa.identityChecker_ = std::make_shared<IdentityCheckerMock>();

    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;

    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);

    auto clientGroup = std::make_shared<ClientGroup>(0, nullptr);
    session->clientGroupMap_[0] = clientGroup;
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->pid = IPCSkeleton::GetCallingPid();
    clientInfo->isNotifyInputStart = false;
    clientGroup->mapClients_[nullptr] = clientInfo;

    ImeIdentification stylusIme{ "stylusBundle", "stylusSub" };
    InputTypeManager::GetInstance().inputTypes_.insert_or_assign(InputType::STYLUS_INPUT, stylusIme);
    InputTypeManager::GetInstance().Set(true, stylusIme);

    auto ret = imsa.ShowInputInner(client, 0, 0, true);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);

    InputTypeManager::GetInstance().inputTypes_.erase(InputType::STYLUS_INPUT);
    InputTypeManager::GetInstance().Set(false);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: ShowInputInner_StylusActivation_StartFailed_003
 * @tc.desc: ShowInputInner with stylus activation but start stylus ime failed, cover 918 true branch
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, ShowInputInner_StylusActivation_StartFailed_003, TestSize.Level1)
{
    IMSA_HILOGI("ShowInputInner_StylusActivation_StartFailed_003 TEST START");
    InputMethodSystemAbility imsa;
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetFocused(true);
    imsa.identityChecker_ = std::make_shared<IdentityCheckerMock>();

    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;

    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);

    auto clientGroup = std::make_shared<ClientGroup>(0, nullptr);
    session->clientGroupMap_[0] = clientGroup;
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->pid = IPCSkeleton::GetCallingPid();
    clientInfo->isNotifyInputStart = true;
    clientGroup->mapClients_[nullptr] = clientInfo;

    InputTypeManager::GetInstance().inputTypes_.erase(InputType::STYLUS_INPUT);
    InputTypeManager::GetInstance().Set(false);
    session->imeStartLock_.lock();
    auto ret = imsa.ShowInputInner(client, 0, 0, true);
    session->imeStartLock_.unlock();
    EXPECT_EQ(ret, ErrorCode::ERROR_TRY_IME_START_FAILED);

    InputTypeManager::GetInstance().Set(false);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: ShowInputInner_NotStylus_ExitStylusIme_004
 * @tc.desc: ShowInputInner without stylus activation while stylus ime is started, cover 923 to 927 branch
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, ShowInputInner_NotStylus_ExitStylusIme_004, TestSize.Level1)
{
    IMSA_HILOGI("ShowInputInner_NotStylus_ExitStylusIme_004 TEST START");
    InputMethodSystemAbility imsa;
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetFocused(true);
    imsa.identityChecker_ = std::make_shared<IdentityCheckerMock>();

    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;

    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);

    ImeIdentification stylusIme{ "stylusBundle", "stylusSub" };
    InputTypeManager::GetInstance().inputTypes_.insert_or_assign(InputType::STYLUS_INPUT, stylusIme);
    InputTypeManager::GetInstance().Set(true, stylusIme);

    session->imeStartLock_.lock();
    auto ret = imsa.ShowInputInner(client, 0, 0, false);
    session->imeStartLock_.unlock();
    EXPECT_FALSE(InputTypeManager::GetInstance().IsStylusImeStarted());
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);

    InputTypeManager::GetInstance().inputTypes_.erase(InputType::STYLUS_INPUT);
    InputTypeManager::GetInstance().Set(false);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: ShowInputInner_NotStylus_NoStylusIme_005
 * @tc.desc: ShowInputInner without stylus activation and stylus ime not started, cover 923 false branch
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, ShowInputInner_NotStylus_NoStylusIme_005, TestSize.Level1)
{
    IMSA_HILOGI("ShowInputInner_NotStylus_NoStylusIme_005 TEST START");
    InputMethodSystemAbility imsa;
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetFocused(true);
    imsa.identityChecker_ = std::make_shared<IdentityCheckerMock>();

    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;

    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);

    InputTypeManager::GetInstance().inputTypes_.erase(InputType::STYLUS_INPUT);
    InputTypeManager::GetInstance().Set(false);
    auto ret = imsa.ShowInputInner(client, 0, 0, false);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);

    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: RequestSystemInputCapability_InvalidType
 * @tc.desc: AC-1.6: invalid type returns ERROR_PARAMETER_CHECK_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, RequestSystemInputCapability_InvalidType, TestSize.Level1)
{
    IMSA_HILOGI("RequestSystemInputCapability_InvalidType TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    auto ret = imsa->RequestSystemInputCapability(99);
    EXPECT_EQ(ret, ErrorCode::ERROR_PARAMETER_CHECK_FAILED);
}

/**
 * @tc.name: RequestSystemInputCapability_Translation_NotDefaultIme
 * @tc.desc: AC-1.2: current ime is not default ime, returns ERROR_NOT_DEFAULT_IME
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, RequestSystemInputCapability_Translation_NotDefaultIme, TestSize.Level1)
{
    IMSA_HILOGI("RequestSystemInputCapability_Translation_NotDefaultIme TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    // setup user session with attached client
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    auto clientGroup = std::make_shared<ClientGroup>(0, nullptr);
    session->clientGroupMap_[0] = clientGroup;
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->pid = IPCSkeleton::GetCallingPid();
    clientGroup->mapClients_[nullptr] = clientInfo;
    ImeEnabledInfo enabledInfo;
    enabledInfo.bundleName = "com.other.ime";
    enabledInfo.extensionName = "ServiceExtAbility";
    enabledInfo.extraInfo.isDefaultIme = true;
    ImeEnabledCfg enabledCfg;
    enabledCfg.enabledInfos.push_back(enabledInfo);
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.insert_or_assign(userId, enabledCfg);
    FullImeInfo fullImeInfo;
    fullImeInfo.prop.name = "com.other.ime";
    FullImeInfoManager::GetInstance().fullImeInfos_[userId].push_back(fullImeInfo);
    ImeInfoInquirer::GetInstance().systemConfig_.defaultInputMethod = "com.default.ime/ServiceExtAbility";
    auto ret = imsa->RequestSystemInputCapability(static_cast<int32_t>(InputCapabilityType::TRANSLATION));
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_DEFAULT_IME);
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.erase(userId);
    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: RequestSystemInputCapability_Translation_NullCurrentIme
 * @tc.desc: AC-1.2 boundary: current ime is nullptr, returns ERROR_NOT_DEFAULT_IME
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, RequestSystemInputCapability_Translation_NullCurrentIme, TestSize.Level1)
{
    IMSA_HILOGI("RequestSystemInputCapability_Translation_NullCurrentIme TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    // setup user session with attached client
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    auto clientGroup = std::make_shared<ClientGroup>(0, nullptr);
    session->clientGroupMap_[0] = clientGroup;
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->pid = IPCSkeleton::GetCallingPid();
    clientGroup->mapClients_[nullptr] = clientInfo;
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.erase(userId);
    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
    ImeInfoInquirer::GetInstance().systemConfig_.defaultInputMethod = "com.default.ime/ServiceExtAbility";
    auto ret = imsa->RequestSystemInputCapability(static_cast<int32_t>(InputCapabilityType::TRANSLATION));
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_DEFAULT_IME);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: RequestSystemInputCapability_Translation_EmptyDefaultIme
 * @tc.desc: AC-1.2 boundary: default ime config is empty, returns ERROR_NOT_DEFAULT_IME
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, RequestSystemInputCapability_Translation_EmptyDefaultIme, TestSize.Level1)
{
    IMSA_HILOGI("RequestSystemInputCapability_Translation_EmptyDefaultIme TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    // setup user session with attached client
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    auto clientGroup = std::make_shared<ClientGroup>(0, nullptr);
    session->clientGroupMap_[0] = clientGroup;
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->pid = IPCSkeleton::GetCallingPid();
    clientGroup->mapClients_[nullptr] = clientInfo;
    ImeEnabledInfo enabledInfo;
    enabledInfo.bundleName = "com.default.ime";
    enabledInfo.extensionName = "ServiceExtAbility";
    enabledInfo.extraInfo.isDefaultIme = true;
    ImeEnabledCfg enabledCfg;
    enabledCfg.enabledInfos.push_back(enabledInfo);
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.insert_or_assign(userId, enabledCfg);
    FullImeInfo fullImeInfo;
    fullImeInfo.prop.name = "com.default.ime";
    FullImeInfoManager::GetInstance().fullImeInfos_[userId].push_back(fullImeInfo);
    ImeInfoInquirer::GetInstance().systemConfig_.defaultInputMethod = "";
    auto ret = imsa->RequestSystemInputCapability(static_cast<int32_t>(InputCapabilityType::TRANSLATION));
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_DEFAULT_IME);
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.erase(userId);
    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: RequestSystemInputCapability_Translation_TypeNotConfigured
 * @tc.desc: AC-1.4: translation type not configured in config file, returns ERROR_IMSA_INPUT_TYPE_NOT_SUPPORTED
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, RequestSystemInputCapability_Translation_TypeNotConfigured, TestSize.Level1)
{
    IMSA_HILOGI("RequestSystemInputCapability_Translation_TypeNotConfigured TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    // setup current ime == default ime
    ImeEnabledInfo enabledInfo;
    enabledInfo.bundleName = "com.default.ime";
    enabledInfo.extensionName = "ServiceExtAbility";
    enabledInfo.extraInfo.isDefaultIme = true;
    ImeEnabledCfg enabledCfg;
    enabledCfg.enabledInfos.push_back(enabledInfo);
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.insert_or_assign(userId, enabledCfg);
    FullImeInfo fullImeInfo;
    fullImeInfo.prop.name = "com.default.ime";
    FullImeInfoManager::GetInstance().fullImeInfos_[userId].push_back(fullImeInfo);
    ImeInfoInquirer::GetInstance().systemConfig_.defaultInputMethod = "com.default.ime/ServiceExtAbility";
    // setup user session with attached client
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    auto clientGroup = std::make_shared<ClientGroup>(0, nullptr);
    session->clientGroupMap_[0] = clientGroup;
    auto clientInfo = std::make_shared<InputClientInfo>();
    clientInfo->pid = IPCSkeleton::GetCallingPid();
    clientGroup->mapClients_[nullptr] = clientInfo;
    // ensure TRANSLATION_INPUT is not in inputTypes_
    InputTypeManager::GetInstance().isTypeCfgReady_ = true;
    InputTypeManager::GetInstance().inputTypes_.erase(InputType::TRANSLATION_INPUT);
    auto ret = imsa->RequestSystemInputCapability(static_cast<int32_t>(InputCapabilityType::TRANSLATION));
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_INPUT_TYPE_NOT_SUPPORTED);
    // cleanup
    InputTypeManager::GetInstance().inputTypes_.erase(InputType::TRANSLATION_INPUT);
    InputTypeManager::GetInstance().isTypeCfgReady_ = false;
    UserSessionManager::GetInstance().userSessions_.clear();
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.erase(userId);
    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
}

/**
 * @tc.name: RequestSystemInputCapability_Translation_NotAttached
 * @tc.desc: AC-1.5: caller not attached, returns ERROR_CLIENT_NOT_BOUND
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, RequestSystemInputCapability_Translation_NotAttached, TestSize.Level1)
{
    IMSA_HILOGI("RequestSystemInputCapability_Translation_NotAttached TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    // setup user session without any attached client
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    auto ret = imsa->RequestSystemInputCapability(static_cast<int32_t>(InputCapabilityType::TRANSLATION));
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: testNotifyImeModalWindowStateChanged_001
 * @tc.desc: NotifyImeModalWindowStateChanged null session / non-current ime / normal path
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, testNotifyImeModalWindowStateChanged_001, TestSize.Level1)
{
    IMSA_HILOGI("testNotifyImeModalWindowStateChanged_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    UserSessionManager::GetInstance().userSessions_.clear();

    // session is nullptr
    EXPECT_EQ(imsa->NotifyImeModalWindowStateChanged("com.test.modal", 0), ErrorCode::ERROR_NULL_POINTER);

    // session exists but real ime pid differs from calling pid
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    sptr<IInputMethodCore> mockCore = new (std::nothrow) InputMethodCoreServiceImpl();
    sptr<IRemoteObject> mockAgent = new (std::nothrow) InputMethodAgentServiceImpl();
    auto imeData = std::make_shared<ImeData>(mockCore, mockAgent, nullptr, IPCSkeleton::GetCallingPid() + 1);
    imeData->imeStatus = ImeStatus::READY;
    session->realImeData_ = imeData;
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    EXPECT_EQ(imsa->NotifyImeModalWindowStateChanged("com.test.modal", 0), ErrorCode::ERROR_NOT_IME);

    // real ime pid matches calling pid, enters OnNotifyImeModalWindowStateChanged
    imeData->pid = IPCSkeleton::GetCallingPid();
    EXPECT_EQ(imsa->NotifyImeModalWindowStateChanged("com.test.modal", 0), ErrorCode::NO_ERROR);

    UserSessionManager::GetInstance().userSessions_.clear();
}

/**
 * @tc.name: testRequestHideInput_ModalAppSkipHide_001
 * @tc.desc: RequestHideInput skips hide when caller is an ime modal app and real ime is bound
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, testRequestHideInput_ModalAppSkipHide_001, TestSize.Level1)
{
    IMSA_HILOGI("testRequestHideInput_ModalAppSkipHide_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetFocused(false);
    IdentityCheckerMock::SetPermission(true);
    IdentityCheckerMock::SetBundleName("com.test.modal");
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();

    int32_t userId = TddUtil::GetCurrentUserId();
    UserSessionManager::GetInstance().userSessions_.clear();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;

    // register modal app + bind a current client to real ime
    session->OnNotifyImeModalWindowStateChanged(IPCSkeleton::GetCallingPid(), "com.test.modal", 0);
    auto group = std::make_shared<ClientGroup>(0, nullptr);
    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    group->currentClient_ = client;
    auto info = std::make_shared<InputClientInfo>();
    info->bindImeData = std::make_shared<BindImeData>(IPCSkeleton::GetCallingPid(), ImeType::IME);
    group->mapClients_.insert_or_assign(client->AsObject(), info);
    session->clientGroupMap_.insert_or_assign(0, group);

    EXPECT_EQ(imsa->RequestHideInput(0, 0, false, -1), ErrorCode::NO_ERROR);

    UserSessionManager::GetInstance().userSessions_.clear();
    IdentityCheckerMock::ResetParam();
}

/**
 * @tc.name: testRequestHideInput_ModalAppNotRegistered_001
 * @tc.desc: RequestHideInput proceeds hide when caller is not an ime modal app
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodServiceTest, testRequestHideInput_ModalAppNotRegistered_001, TestSize.Level1)
{
    IMSA_HILOGI("testRequestHideInput_ModalAppNotRegistered_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetFocused(false);
    IdentityCheckerMock::SetPermission(true);
    IdentityCheckerMock::SetBundleName("com.test.modal");
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();

    int32_t userId = TddUtil::GetCurrentUserId();
    UserSessionManager::GetInstance().userSessions_.clear();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;

    // no modal app registered, IsImeModalApp returns false, hide proceeds
    EXPECT_EQ(imsa->RequestHideInput(0, 0, false, -1), ErrorCode::NO_ERROR);

    UserSessionManager::GetInstance().userSessions_.clear();
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testIsCapacitySupport_001, TestSize.Level1)
{
    IMSA_HILOGI("testIsCapacitySupport_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    bool isSupport = false;
    EXPECT_EQ(imsa->IsCapacitySupport(-1, isSupport), ErrorCode::ERROR_PARAMETER_CHECK_FAILED);
    EXPECT_EQ(imsa->IsCapacitySupport(static_cast<int32_t>(CapacityType::END), isSupport),
        ErrorCode::ERROR_PARAMETER_CHECK_FAILED);
}

HWTEST_F(InputMethodServiceTest, testIsCapacitySupport_002, TestSize.Level1)
{
    IMSA_HILOGI("testIsCapacitySupport_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    bool isSupport = false;
    EXPECT_EQ(imsa->IsCapacitySupport(static_cast<int32_t>(CapacityType::IMMERSIVE_EFFECT), isSupport), ERR_OK);
    EXPECT_EQ(imsa->IsCapacitySupport(static_cast<int32_t>(CapacityType::SYSTEM_PANEL), isSupport), ERR_OK);
    EXPECT_EQ(imsa->IsCapacitySupport(static_cast<int32_t>(CapacityType::DISABLE_IMMERSIVE_MODE), isSupport), ERR_OK);
    EXPECT_EQ(imsa->IsCapacitySupport(static_cast<int32_t>(CapacityType::SUPPORT_PC_MODE), isSupport), ERR_OK);
    EXPECT_EQ(imsa->IsCapacitySupport(static_cast<int32_t>(CapacityType::DISABLE_PC_MODE_IMMERSIVE_MODE), isSupport),
        ERR_OK);
    EXPECT_EQ(imsa->IsCapacitySupport(static_cast<int32_t>(CapacityType::IS_PC_MODE), isSupport), ERR_OK);
}

HWTEST_F(InputMethodServiceTest, testIsCurrentIme_001, TestSize.Level1)
{
    IMSA_HILOGI("testIsCurrentIme_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    UserSessionManager::GetInstance().userSessions_.clear();
    bool resultValue = true;
    EXPECT_EQ(imsa->IsCurrentIme(resultValue), ERR_OK);
    EXPECT_FALSE(resultValue);
}

HWTEST_F(InputMethodServiceTest, testIsInputMethodExtension_001, TestSize.Level1)
{
    IMSA_HILOGI("testIsInputMethodExtension_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    bool resultValue = false;
    EXPECT_EQ(imsa->IsInputMethodExtension(resultValue), ERR_OK);
}

HWTEST_F(InputMethodServiceTest, testIsInputTypeSupported_001, TestSize.Level1)
{
    IMSA_HILOGI("testIsInputTypeSupported_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    bool resultValue = false;
    EXPECT_EQ(imsa->IsInputTypeSupported(static_cast<int32_t>(InputType::SECURITY_INPUT), resultValue), ERR_OK);
}

HWTEST_F(InputMethodServiceTest, testGetSecurityMode_001, TestSize.Level1)
{
    IMSA_HILOGI("testGetSecurityMode_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetBundleName("com.test.ime");
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    UserSessionManager::GetInstance().userSessions_.clear();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
    int32_t security = -1;
    EXPECT_EQ(imsa->GetSecurityMode(security), ErrorCode::ERROR_NOT_IME);
    UserSessionManager::GetInstance().userSessions_.clear();
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testGetSecurityMode_002, TestSize.Level1)
{
    IMSA_HILOGI("testGetSecurityMode_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetBundleName("com.test.ime");
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    FullImeInfo fullImeInfo;
    fullImeInfo.prop.name = "com.test.ime";
    fullImeInfo.tokenId = IPCSkeleton::GetCallingTokenID();
    FullImeInfoManager::GetInstance().fullImeInfos_[userId].push_back(fullImeInfo);
    int32_t security = -1;
    EXPECT_EQ(imsa->GetSecurityMode(security), ErrorCode::NO_ERROR);
    EXPECT_EQ(security, static_cast<int32_t>(SecurityMode::BASIC));
    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testSetEDCDefaultInputMethod_001, TestSize.Level1)
{
    IMSA_HILOGI("testSetEDCDefaultInputMethod_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    EXPECT_EQ(imsa->SetEDCDefaultInputMethod(""), ErrorCode::ERROR_PARAMETER_CHECK_FAILED);
}

HWTEST_F(InputMethodServiceTest, testSetEDCDefaultInputMethod_002, TestSize.Level1)
{
    IMSA_HILOGI("testSetEDCDefaultInputMethod_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    imsa->identityChecker_ = nullptr;
    EXPECT_EQ(imsa->SetEDCDefaultInputMethod("com.test.edc.ime"), ErrorCode::ERROR_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testSetEDCDefaultInputMethod_003, TestSize.Level1)
{
    IMSA_HILOGI("testSetEDCDefaultInputMethod_003 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetNativeSa(false);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    EXPECT_EQ(imsa->SetEDCDefaultInputMethod("com.test.edc.ime"), ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testExecTextInteraction_001, TestSize.Level1)
{
    IMSA_HILOGI("testExecTextInteraction_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    imsa->identityChecker_ = nullptr;
    EXPECT_EQ(imsa->ExecTextInteraction("test"), ErrorCode::ERROR_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testExecTextInteraction_002, TestSize.Level1)
{
    IMSA_HILOGI("testExecTextInteraction_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetPermission(false);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    EXPECT_EQ(imsa->ExecTextInteraction("test"), ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testExecTextInteraction_003, TestSize.Level1)
{
    IMSA_HILOGI("testExecTextInteraction_003 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetPermission(true);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    UserSessionManager::GetInstance().userSessions_.clear();
    EXPECT_EQ(imsa->ExecTextInteraction("test"), ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testIsPttGestureAvailable_001, TestSize.Level1)
{
    IMSA_HILOGI("testIsPttGestureAvailable_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    sptr<IRemoteObject> channel = nullptr;
    bool resultValue = false;
    EXPECT_EQ(imsa->IsPttGestureAvailable(channel, resultValue), ErrorCode::ERROR_BAD_PARAMETERS);
}

HWTEST_F(InputMethodServiceTest, testIsPttGestureAvailable_002, TestSize.Level1)
{
    IMSA_HILOGI("testIsPttGestureAvailable_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    sptr<IRemoteObject> channel = new (std::nothrow) InputMethodAgentServiceImpl();
    ASSERT_NE(channel, nullptr);
    bool resultValue = true;
    EXPECT_EQ(imsa->IsPttGestureAvailable(channel, resultValue), ERR_OK);
    EXPECT_FALSE(resultValue);
}

HWTEST_F(InputMethodServiceTest, testGetSoftKeyboardInfo_001, TestSize.Level1)
{
    IMSA_HILOGI("testGetSoftKeyboardInfo_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    imsa->identityChecker_ = nullptr;
    BoundImeInfo imeInfo;
    EXPECT_EQ(imsa->GetSoftKeyboardInfo(0, imeInfo), ErrorCode::ERROR_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testGetSoftKeyboardInfo_002, TestSize.Level1)
{
    IMSA_HILOGI("testGetSoftKeyboardInfo_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetSystemApp(false);
    IdentityCheckerMock::SetNativeSa(false);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    BoundImeInfo imeInfo;
    EXPECT_EQ(imsa->GetSoftKeyboardInfo(0, imeInfo), ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testNotifyInputStart_001, TestSize.Level1)
{
    IMSA_HILOGI("testNotifyInputStart_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    UserSessionManager::GetInstance().userSessions_.clear();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    InputStartInfo inputStartInfo;
    EXPECT_EQ(imsa->NotifyInputStart(inputStartInfo), ErrorCode::ERROR_NOT_CURRENT_IME);
    UserSessionManager::GetInstance().userSessions_.clear();
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testNotifyInputStop_001, TestSize.Level1)
{
    IMSA_HILOGI("testNotifyInputStop_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    UserSessionManager::GetInstance().userSessions_.clear();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    InputStopInfo inputStopInfo;
    EXPECT_EQ(imsa->NotifyInputStop(inputStopInfo), ErrorCode::ERROR_NOT_CURRENT_IME);
    UserSessionManager::GetInstance().userSessions_.clear();
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testNotifySoftKeyBoardInfoChanged_001, TestSize.Level1)
{
    IMSA_HILOGI("testNotifySoftKeyBoardInfoChanged_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    UserSessionManager::GetInstance().userSessions_.clear();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    BoundImeInfo oldImeInfo;
    BoundImeInfo newImeInfo;
    EXPECT_EQ(imsa->NotifySoftKeyBoardInfoChanged(oldImeInfo, newImeInfo), ErrorCode::ERROR_NOT_CURRENT_IME);
    UserSessionManager::GetInstance().userSessions_.clear();
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testReleaseInput_001, TestSize.Level1)
{
    IMSA_HILOGI("testReleaseInput_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    EXPECT_EQ(imsa->ReleaseInput(nullptr, 0, 0), ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testReleaseInput_002, TestSize.Level1)
{
    IMSA_HILOGI("testReleaseInput_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    UserSessionManager::GetInstance().userSessions_.clear();
    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(imsa->ReleaseInput(client, 0, 0), ErrorCode::ERROR_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testIncreaseAttachCount_001, TestSize.Level1)
{
    IMSA_HILOGI("testIncreaseAttachCount_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    UserSessionManager::GetInstance().userSessions_.clear();
    imsa->IncreaseAttachCount();
    SUCCEED();
}

HWTEST_F(InputMethodServiceTest, testDecreaseAttachCount_001, TestSize.Level1)
{
    IMSA_HILOGI("testDecreaseAttachCount_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    UserSessionManager::GetInstance().userSessions_.clear();
    imsa->DecreaseAttachCount();
    SUCCEED();
}

HWTEST_F(InputMethodServiceTest, testPostPttDialogTask_001, TestSize.Level1)
{
    IMSA_HILOGI("testPostPttDialogTask_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    auto savedHandler = InputMethodSystemAbility::serviceHandler_;
    InputMethodSystemAbility::serviceHandler_ = nullptr;
    imsa->PostPttDialogTask(0);
    InputMethodSystemAbility::serviceHandler_ = savedHandler;
    SUCCEED();
}

HWTEST_F(InputMethodServiceTest, testInitConnect_001, TestSize.Level1)
{
    IMSA_HILOGI("testInitConnect_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    UserSessionManager::GetInstance().userSessions_.clear();
    EXPECT_EQ(imsa->InitConnect(), ErrorCode::ERROR_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testInitConnect_002, TestSize.Level1)
{
    IMSA_HILOGI("testInitConnect_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    UserSessionManager::GetInstance().userSessions_.clear();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    EXPECT_EQ(imsa->InitConnect(), ErrorCode::ERROR_NOT_CURRENT_IME);
    UserSessionManager::GetInstance().userSessions_.clear();
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testGetCurrentInputMethod_001, TestSize.Level1)
{
    IMSA_HILOGI("testGetCurrentInputMethod_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    int32_t userId = TddUtil::GetCurrentUserId();
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.erase(userId);
    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
    Property prop;
    EXPECT_EQ(imsa->GetCurrentInputMethod(userId, prop), ErrorCode::ERROR_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testGetCurrentInputMethodSubtype_001, TestSize.Level1)
{
    IMSA_HILOGI("testGetCurrentInputMethodSubtype_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    int32_t userId = TddUtil::GetCurrentUserId();
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.erase(userId);
    FullImeInfoManager::GetInstance().fullImeInfos_.erase(userId);
    SubProperty subProp;
    EXPECT_EQ(imsa->GetCurrentInputMethodSubtype(subProp, userId), ErrorCode::ERROR_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testCheckEnableAndSwitchPermission_001, TestSize.Level1)
{
    IMSA_HILOGI("testCheckEnableAndSwitchPermission_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetNativeSa(false);
    IdentityCheckerMock::SetSystemApp(false);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    EXPECT_EQ(imsa->CheckEnableAndSwitchPermission(), ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testCheckEnableAndSwitchPermission_002, TestSize.Level1)
{
    IMSA_HILOGI("testCheckEnableAndSwitchPermission_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetSystemApp(true);
    IdentityCheckerMock::SetPermission(false);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    EXPECT_EQ(imsa->CheckEnableAndSwitchPermission(), ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testCheckEnableAndSwitchPermission_003, TestSize.Level1)
{
    IMSA_HILOGI("testCheckEnableAndSwitchPermission_003 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetSystemApp(true);
    IdentityCheckerMock::SetPermission(true);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    EXPECT_EQ(imsa->CheckEnableAndSwitchPermission(), ErrorCode::NO_ERROR);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testCheckSwitchPermission_001, TestSize.Level1)
{
    IMSA_HILOGI("testCheckSwitchPermission_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    SwitchInfo switchInfo = { std::chrono::system_clock::now(), "com.test.ime", "" };
    EXPECT_EQ(imsa->CheckSwitchPermission(userId, switchInfo, SwitchTrigger::IMSA), ErrorCode::NO_ERROR);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testCheckSwitchPermission_002, TestSize.Level1)
{
    IMSA_HILOGI("testCheckSwitchPermission_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetNativeSa(true);
    IdentityCheckerMock::SetSystemApp(true);
    IdentityCheckerMock::SetPermission(true);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    SwitchInfo switchInfo = { std::chrono::system_clock::now(), "com.test.ime", "" };
    EXPECT_EQ(imsa->CheckSwitchPermission(userId, switchInfo, SwitchTrigger::NATIVE_SA), ErrorCode::NO_ERROR);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testCheckSwitchPermission_003, TestSize.Level1)
{
    IMSA_HILOGI("testCheckSwitchPermission_003 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetSystemApp(false);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    SwitchInfo switchInfo = { std::chrono::system_clock::now(), "com.test.ime", "" };
    EXPECT_EQ(imsa->CheckSwitchPermission(userId, switchInfo, SwitchTrigger::SYSTEM_APP),
        ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testCheckSwitchPermission_004, TestSize.Level1)
{
    IMSA_HILOGI("testCheckSwitchPermission_004 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetSystemApp(true);
    IdentityCheckerMock::SetPermission(false);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    SwitchInfo switchInfo = { std::chrono::system_clock::now(), "com.test.ime", "" };
    EXPECT_EQ(imsa->CheckSwitchPermission(userId, switchInfo, SwitchTrigger::SYSTEM_APP),
        ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testCheckSwitchPermission_005, TestSize.Level1)
{
    IMSA_HILOGI("testCheckSwitchPermission_005 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetSystemApp(true);
    IdentityCheckerMock::SetPermission(true);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    SwitchInfo switchInfo = { std::chrono::system_clock::now(), "com.test.ime", "" };
    EXPECT_EQ(imsa->CheckSwitchPermission(userId, switchInfo, SwitchTrigger::SYSTEM_APP), ErrorCode::NO_ERROR);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testCheckSwitchPermission_006, TestSize.Level1)
{
    IMSA_HILOGI("testCheckSwitchPermission_006 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetPermission(true);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    SwitchInfo switchInfo = { std::chrono::system_clock::now(), "com.test.ime", "" };
    EXPECT_EQ(imsa->CheckSwitchPermission(userId, switchInfo, SwitchTrigger::CURRENT_IME), ErrorCode::NO_ERROR);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testCheckSwitchPermission_007, TestSize.Level1)
{
    IMSA_HILOGI("testCheckSwitchPermission_007 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetPermission(false);
    IdentityCheckerMock::SetBundleNameValid(false);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    int32_t userId = TddUtil::GetCurrentUserId();
    UserSessionManager::GetInstance().userSessions_.clear();
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.erase(userId);
    SwitchInfo switchInfo = { std::chrono::system_clock::now(), "com.test.ime", "" };
    EXPECT_EQ(imsa->CheckSwitchPermission(userId, switchInfo, SwitchTrigger::CURRENT_IME),
        ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testIsSwitchingAllow_001, TestSize.Level1)
{
    IMSA_HILOGI("testIsSwitchingAllow_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    ExamModeManager::GetInstance().SetExamMode(false);
    EXPECT_TRUE(imsa->IsSwitchingAllow(0, "com.test.ime"));
}

HWTEST_F(InputMethodServiceTest, testIsSwitchingAllow_002, TestSize.Level1)
{
    IMSA_HILOGI("testIsSwitchingAllow_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    ExamModeManager::GetInstance().SetExamMode(true);
    EXPECT_FALSE(imsa->IsSwitchingAllow(0, "com.non.sys.ime"));
    ExamModeManager::GetInstance().SetExamMode(false);
}

HWTEST_F(InputMethodServiceTest, testIsOneTimeCodeInput_001, TestSize.Level1)
{
    IMSA_HILOGI("testIsOneTimeCodeInput_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    InputClientInfo clientInfo;
    clientInfo.config.inputAttribute.inputPattern = InputAttribute::PATTERN_PASSWORD;
    EXPECT_TRUE(imsa->IsOneTimeCodeInput(clientInfo));
}

HWTEST_F(InputMethodServiceTest, testIsOneTimeCodeInput_002, TestSize.Level1)
{
    IMSA_HILOGI("testIsOneTimeCodeInput_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    InputClientInfo clientInfo;
    clientInfo.config.inputAttribute.inputPattern = InputAttribute::PATTERN_ONE_TIME_CODE;
    EXPECT_TRUE(imsa->IsOneTimeCodeInput(clientInfo));
}

HWTEST_F(InputMethodServiceTest, testIsOneTimeCodeInput_003, TestSize.Level1)
{
    IMSA_HILOGI("testIsOneTimeCodeInput_003 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    InputClientInfo clientInfo;
    EXPECT_FALSE(imsa->IsOneTimeCodeInput(clientInfo));
}

HWTEST_F(InputMethodServiceTest, testSwitchToDefaultIme_001, TestSize.Level1)
{
    IMSA_HILOGI("testSwitchToDefaultIme_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    ImeInfoInquirer::GetInstance().systemConfig_.defaultInputMethod = "";
    EXPECT_EQ(imsa->SwitchToDefaultIme(TddUtil::GetCurrentUserId()), ErrorCode::ERROR_IMSA_GET_IME_INFO_FAILED);
}

HWTEST_F(InputMethodServiceTest, testSwitchToDefaultIme_002, TestSize.Level1)
{
    IMSA_HILOGI("testSwitchToDefaultIme_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    ImeInfoInquirer::GetInstance().systemConfig_.defaultInputMethod = "com.default.ime/ServiceExtAbility";
    UserSessionManager::GetInstance().userSessions_.clear();
    EXPECT_EQ(imsa->SwitchToDefaultIme(TddUtil::GetCurrentUserId()), ErrorCode::ERROR_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testSwitchToPreviousIme_001, TestSize.Level1)
{
    IMSA_HILOGI("testSwitchToPreviousIme_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    ExamModeManager::GetInstance().ClearPreviousIme();
    EXPECT_EQ(imsa->SwitchToPreviousIme(TddUtil::GetCurrentUserId()), ErrorCode::NO_ERROR);
}

HWTEST_F(InputMethodServiceTest, testSwitchToPreviousIme_002, TestSize.Level1)
{
    IMSA_HILOGI("testSwitchToPreviousIme_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    ExamModeManager::GetInstance().SavePreviousIme("com.previous.ime", "subName");
    UserSessionManager::GetInstance().userSessions_.clear();
    EXPECT_EQ(imsa->SwitchToPreviousIme(TddUtil::GetCurrentUserId()), ErrorCode::ERROR_NULL_POINTER);
    ExamModeManager::GetInstance().ClearPreviousIme();
}

HWTEST_F(InputMethodServiceTest, testHandleEDCInputMethodInstall_001, TestSize.Level1)
{
    IMSA_HILOGI("testHandleEDCInputMethodInstall_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    ImeInfoInquirer::GetInstance().systemConfig_.defaultInputMethod = "";
    imsa->HandleEDCInputMethodInstall(0, "com.test.edc.ime");
    SUCCEED();
}

HWTEST_F(InputMethodServiceTest, testHandleEDCInputMethodRemove_001, TestSize.Level1)
{
    IMSA_HILOGI("testHandleEDCInputMethodRemove_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    ImeInfoInquirer::GetInstance().systemConfig_.defaultInputMethod = "";
    imsa->HandleEDCInputMethodRemove(0, "com.test.edc.ime");
    SUCCEED();
}

HWTEST_F(InputMethodServiceTest, testGetCurrentImeInfoForHiSysEvent_001, TestSize.Level1)
{
    IMSA_HILOGI("testGetCurrentImeInfoForHiSysEvent_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    UserSessionManager::GetInstance().userSessions_.clear();
    auto imeInfo = imsa->GetCurrentImeInfoForHiSysEvent(TddUtil::GetCurrentUserId());
    EXPECT_EQ(imeInfo.first, 0);
}

HWTEST_F(InputMethodServiceTest, testGetCurrentImeInfoForHiSysEvent_002, TestSize.Level1)
{
    IMSA_HILOGI("testGetCurrentImeInfoForHiSysEvent_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    int32_t userId = TddUtil::GetCurrentUserId();
    auto session = std::make_shared<PerUserSession>(userId, nullptr);
    UserSessionManager::GetInstance().userSessions_[userId] = session;
    auto imeInfo = imsa->GetCurrentImeInfoForHiSysEvent(userId);
    EXPECT_EQ(imeInfo.first, 0);
    EXPECT_TRUE(imeInfo.second.empty());
    UserSessionManager::GetInstance().userSessions_.clear();
}

HWTEST_F(InputMethodServiceTest, testIsPanelShown_001, TestSize.Level1)
{
    IMSA_HILOGI("testIsPanelShown_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    imsa->identityChecker_ = nullptr;
    PanelInfo panelInfo;
    bool isShown = false;
    EXPECT_EQ(imsa->IsPanelShown(panelInfo, isShown), ErrorCode::ERROR_NULL_POINTER);
}

HWTEST_F(InputMethodServiceTest, testIsPanelShown_002, TestSize.Level1)
{
    IMSA_HILOGI("testIsPanelShown_002 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetSystemApp(false);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    PanelInfo panelInfo;
    bool isShown = false;
    EXPECT_EQ(imsa->IsPanelShown(panelInfo, isShown), ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION);
    IdentityCheckerMock::ResetParam();
}

HWTEST_F(InputMethodServiceTest, testIsPanelShown_displayId_001, TestSize.Level1)
{
    IMSA_HILOGI("testIsPanelShown_displayId_001 TEST START");
    auto imsa = new (std::nothrow) InputMethodSystemAbility();
    ASSERT_NE(imsa, nullptr);
    IdentityCheckerMock::ResetParam();
    IdentityCheckerMock::SetSystemApp(true);
    imsa->identityChecker_ = std::make_shared<IdentityCheckerMock>();
    PanelInfo panelInfo;
    bool isShown = false;
    auto ret = imsa->IsPanelShown(static_cast<uint64_t>(0), panelInfo, isShown);
    EXPECT_TRUE(ret == ErrorCode::ERROR_ACCOUNT_LOCALID_FAILED || ret == ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND);
    IdentityCheckerMock::ResetParam();
}
} // namespace MiscServices
} // namespace OHOS
#endif // !defined(target_cpu_x86_64)
