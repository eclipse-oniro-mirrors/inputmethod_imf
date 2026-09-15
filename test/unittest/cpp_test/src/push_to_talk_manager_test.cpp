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

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../mock/datashare_helper.h"
#include "full_ime_info_manager.h"
#include "ime_info_inquirer.h"
#include "input_method_controller.h"
#include "input_method_system_ability.h"
#include "push_to_talk_manager.h"
#include "settings_data_utils.h"
#include "user_session_manager.h"

#include "event_runner.h"
#include "global.h"
#include "input_client_service_impl.h"
#include "input_death_recipient.h"
#include "input_method_core_service_impl.h"
#include "ipc_skeleton.h"
#include "ptt_settings_manager.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
namespace {
constexpr int32_t PTT_TEST_USER_ID = 8701;
constexpr int32_t PTT_MISSING_USER_ID = 8702;
constexpr pid_t PTT_TEST_CLIENT_PID = 101;
constexpr int32_t PTT_TEST_CLIENT_UID = 102;
constexpr pid_t PTT_TEST_IME_PID = 103;
constexpr uint64_t PTT_TEST_GROUP_ID = 91;
constexpr uint32_t PTT_TEST_WINDOW_ID = 92;
constexpr uint64_t PTT_TEST_DISPLAY_ID = 93;
constexpr const char *PTT_TEST_IME_BUNDLE = "com.test.ptt.ime";

KeyboardEventInfo MakePttSpaceDownEvent()
{
    return { MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN, { MMI::KeyEvent::KEYCODE_SPACE } };
}

class ScopedFullImeInfos {
public:
    explicit ScopedFullImeInfos(int32_t userId) : userId_(userId)
    {
        auto &manager = FullImeInfoManager::GetInstance();
        std::lock_guard<std::mutex> lock(manager.lock_);
        auto iter = manager.fullImeInfos_.find(userId_);
        hadOriginalInfo_ = iter != manager.fullImeInfos_.end();
        if (hadOriginalInfo_) {
            originalInfos_ = iter->second;
        }
    }

    ~ScopedFullImeInfos()
    {
        auto &manager = FullImeInfoManager::GetInstance();
        std::lock_guard<std::mutex> lock(manager.lock_);
        if (hadOriginalInfo_) {
            manager.fullImeInfos_.insert_or_assign(userId_, std::move(originalInfos_));
            return;
        }
        manager.fullImeInfos_.erase(userId_);
    }

    void ReplaceWith(const FullImeInfo &info)
    {
        auto &manager = FullImeInfoManager::GetInstance();
        std::lock_guard<std::mutex> lock(manager.lock_);
        manager.fullImeInfos_.insert_or_assign(userId_, std::vector<FullImeInfo> { info });
    }

private:
    int32_t userId_;
    bool hadOriginalInfo_ { false };
    std::vector<FullImeInfo> originalInfos_;
};
} // namespace

class PushToTalkManagerTest : public testing::Test {
public:
    struct EligibleClientContext {
        std::shared_ptr<PerUserSession> session;
        std::shared_ptr<ClientGroup> group;
        sptr<IInputClient> client;
        sptr<IRemoteObject> channel;
    };

    struct OriginalSession {
        bool existed { false };
        std::shared_ptr<PerUserSession> session;
    };

    void SetUp() override
    {
        originalSettingsToken_ = SettingsDataUtils::GetInstance().remoteObj_;
        originalDataShareHelper_ = DataShare::DataShareHelper::instance_;
        originalLongPressMs_ = ImeInfoInquirer::GetInstance().systemConfig_.pushToTalkLongPressMs;
        RemoveSessionForTest(PTT_TEST_USER_ID);
        RemoveSessionForTest(PTT_MISSING_USER_ID);

        auto controller = InputMethodController::GetInstance();
        ASSERT_NE(controller, nullptr);
        originalEditable_ = controller->isEditable_.load();
        originalBound_ = controller->isBound_.load();
        originalSpaceKeyState_ = controller->pttSpaceKeyEventState_.load();

        manager_ = std::make_shared<PushToTalkManager>(
            [this]() {
                return handler_;
            },
            [](int32_t) {
                return ErrorCode::NO_ERROR;
            });
        ASSERT_NE(manager_, nullptr);

        settingsToken_ = new (std::nothrow) InputMethodCoreServiceImpl();
        ASSERT_NE(settingsToken_, nullptr);
        auto helper = std::make_shared<DataShare::DataShareHelper>();
        ASSERT_NE(helper, nullptr);

        SettingsDataUtils::GetInstance().remoteObj_ = settingsToken_->AsObject();
        DataShare::DataShareHelper::instance_ = helper;
        SetPttSetting("false");
    }

    void TearDown() override
    {
        if (handler_ != nullptr) {
            handler_->RemoveTask(PushToTalkManager::KEY_EVENT_TASK);
            handler_->RemoveTask(PushToTalkManager::TIMEOUT_TASK);
            // Drain any running key action before releasing the manager.
            EXPECT_TRUE(handler_->PostSyncTask([]() { }, "PttManagerTestDrain"));
        }
        manager_ = nullptr;
        handler_ = nullptr;
        ImeInfoInquirer::GetInstance().systemConfig_.pushToTalkLongPressMs = originalLongPressMs_;
        auto &sessionManager = UserSessionManager::GetInstance();
        for (const auto &[userId, original] : originalSessions_) {
            if (!original.existed) {
                sessionManager.userSessions_.erase(userId);
            } else {
                sessionManager.userSessions_.insert_or_assign(userId, original.session);
            }
        }
        originalSessions_.clear();

        SettingsDataUtils::GetInstance().remoteObj_ = originalSettingsToken_;
        DataShare::DataShareHelper::instance_ = originalDataShareHelper_;

        auto controller = InputMethodController::GetInstance();
        if (controller != nullptr) {
            controller->isEditable_.store(originalEditable_);
            controller->isBound_.store(originalBound_);
            controller->pttSpaceKeyEventState_.store(originalSpaceKeyState_);
        }
        settingsToken_ = nullptr;
    }

    void SetPttSetting(const std::string &value)
    {
        auto helper = DataShare::DataShareHelper::instance_;
        ASSERT_NE(helper, nullptr);
        helper->resultSet_ = std::make_shared<DataShare::DataShareResultSet>();
        ASSERT_NE(helper->resultSet_, nullptr);
        helper->resultSet_->strValue_ = value;
    }

    EligibleClientContext CreateEligibleClientContext(int32_t userId = PTT_TEST_USER_ID)
    {
        EligibleClientContext context;
        context.session = std::make_shared<PerUserSession>(userId, nullptr);
        context.client = new (std::nothrow) InputClientServiceImpl();
        sptr<InputMethodCoreServiceImpl> channelStub = new (std::nothrow) InputMethodCoreServiceImpl();
        sptr<InputDeathRecipient> deathRecipient = new (std::nothrow) InputDeathRecipient();
        if (context.session == nullptr || context.client == nullptr || channelStub == nullptr ||
            deathRecipient == nullptr) {
            return { };
        }
        context.channel = channelStub->AsObject();

        InputClientInfo clientInfo;
        clientInfo.pid = PTT_TEST_CLIENT_PID;
        clientInfo.uid = PTT_TEST_CLIENT_UID;
        clientInfo.userID = userId;
        clientInfo.client = context.client;
        clientInfo.channel = context.channel;
        clientInfo.deathRecipient = deathRecipient;
        clientInfo.clientGroupId = PTT_TEST_GROUP_ID;
        clientInfo.state = ClientState::ACTIVE;
        clientInfo.bindImeData = std::make_shared<BindImeData>(PTT_TEST_IME_PID, ImeType::IME);
        clientInfo.config.inputAttribute.editorWindowId = PTT_TEST_WINDOW_ID;
        clientInfo.config.inputAttribute.editorDisplayId = PTT_TEST_DISPLAY_ID;

        if (context.session->OnPrepareInput(clientInfo) != ErrorCode::NO_ERROR) {
            return { };
        }
        context.group = context.session->GetClientGroupByGroupId(PTT_TEST_GROUP_ID);
        if (context.group == nullptr) {
            return { };
        }
        context.group->SetCurrentClient(context.client);
        InstallSessionForTest(userId, context.session);
        return context;
    }

    void SaveOriginalSession(int32_t userId)
    {
        if (originalSessions_.find(userId) != originalSessions_.end()) {
            return;
        }
        auto &sessions = UserSessionManager::GetInstance().userSessions_;
        auto iter = sessions.find(userId);
        OriginalSession original;
        original.existed = iter != sessions.end();
        original.session = original.existed ? iter->second : nullptr;
        originalSessions_.insert_or_assign(userId, std::move(original));
    }

    void RemoveSessionForTest(int32_t userId)
    {
        SaveOriginalSession(userId);
        UserSessionManager::GetInstance().userSessions_.erase(userId);
    }

    void InstallSessionForTest(int32_t userId, const std::shared_ptr<PerUserSession> &session)
    {
        SaveOriginalSession(userId);
        UserSessionManager::GetInstance().userSessions_.insert_or_assign(userId, session);
    }

    std::shared_ptr<PushToTalkManager> manager_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
    sptr<InputMethodCoreServiceImpl> settingsToken_;
    sptr<IRemoteObject> originalSettingsToken_;
    std::shared_ptr<DataShare::DataShareHelper> originalDataShareHelper_;
    std::unordered_map<int32_t, OriginalSession> originalSessions_;
    uint32_t originalLongPressMs_ { 0 };
    bool originalEditable_ { false };
    bool originalBound_ { false };
    InputMethodController::PttSpaceKeyEventState originalSpaceKeyState_ {
        InputMethodController::PttSpaceKeyEventState::UP
    };
};

class PttServiceTest : public PushToTalkManagerTest {
public:
    void SetUp() override
    {
        originalServiceHandler_ = InputMethodSystemAbility::serviceHandler_;
        PushToTalkManagerTest::SetUp();
        if (HasFatalFailure()) {
            return;
        }
        InputMethodSystemAbility::serviceHandler_ = nullptr;
        ability_ = new (std::nothrow) InputMethodSystemAbility();
        ASSERT_NE(ability_, nullptr);
    }

    void TearDown() override
    {
        ability_ = nullptr;
        InputMethodSystemAbility::serviceHandler_ = originalServiceHandler_;
        PushToTalkManagerTest::TearDown();
    }

    sptr<InputMethodSystemAbility> ability_;
    std::shared_ptr<AppExecFwk::EventHandler> originalServiceHandler_;
};

/**
 * @tc.name: PttService_IpcGuards_001
 * @tc.desc: Preserve the IPC parameter/readiness checks and the generic input-type entry.
 * @tc.type: FUNC
 */
HWTEST_F(PttServiceTest, PttService_IpcGuards_001, TestSize.Level0)
{
    bool isAvailable = true;
    EXPECT_EQ(ability_->IsPttGestureAvailable(nullptr, isAvailable), ErrorCode::ERROR_BAD_PARAMETERS);
    EXPECT_FALSE(isAvailable);
    EXPECT_EQ(ability_->IsPttGestureAvailable(settingsToken_->AsObject(), isAvailable), ERR_OK);
    EXPECT_FALSE(isAvailable);

    EXPECT_EQ(ability_->StartInputType(PTT_MISSING_USER_ID, InputType::PUSH_TO_TALK_INPUT, true),
        ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND);
}

/**
 * @tc.name: PushToTalkManager_HandlerReadiness_001
 * @tc.desc: Resolve the current service handler without retaining it or resetting the gesture on stop.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerTest, PushToTalkManager_HandlerReadiness_001, TestSize.Level0)
{
    EXPECT_FALSE(manager_->IsReady());
    manager_->SetKeyEventMonitorReady(true);
    EXPECT_FALSE(manager_->IsReady());

    auto runner = AppExecFwk::EventRunner::Create("PttManagerReadiness");
    ASSERT_NE(runner, nullptr);
    handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_NE(handler_, nullptr);
    EXPECT_TRUE(manager_->IsReady());
    manager_->SetKeyEventMonitorReady(false);
    EXPECT_FALSE(manager_->IsReady());
    manager_->SetKeyEventMonitorReady(true);
    EXPECT_TRUE(manager_->IsReady());

    manager_->controller_.HandleKeyEvent(MakePttSpaceDownEvent());
    manager_->gestureUserId_ = PTT_TEST_USER_ID;
    manager_->gestureClientSnapshot_.client = settingsToken_->AsObject();
    std::weak_ptr<AppExecFwk::EventHandler> previousHandler = handler_;
    manager_->SetKeyEventMonitorReady(false);
    handler_ = nullptr;
    EXPECT_TRUE(previousHandler.expired());
    EXPECT_EQ(manager_->GetServiceHandler(), nullptr);
    EXPECT_FALSE(manager_->IsReady());
    manager_->HandleKeyEvent({ MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_UP, { } });
    EXPECT_EQ(manager_->controller_.GetState(), PttState::PENDING);
    EXPECT_EQ(manager_->gestureUserId_, PTT_TEST_USER_ID);
    EXPECT_EQ(manager_->gestureClientSnapshot_.client, settingsToken_->AsObject());
}

/**
 * @tc.name: PushToTalkManager_QueuedReleaseCancelsTimer_001
 * @tc.desc: Dispatch space-up on the service queue and clear the pending timer's gesture context.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerTest, PushToTalkManager_QueuedReleaseCancelsTimer_001, TestSize.Level0)
{
    auto runner = AppExecFwk::EventRunner::Create("PttManagerKeyEvent");
    ASSERT_NE(runner, nullptr);
    handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_NE(handler_, nullptr);
    ImeInfoInquirer::GetInstance().systemConfig_.pushToTalkLongPressMs = 60000;
    manager_->controller_.HandleKeyEvent(MakePttSpaceDownEvent());
    manager_->gestureUserId_ = PTT_TEST_USER_ID;
    manager_->gestureClientSnapshot_.client = settingsToken_->AsObject();
    manager_->ScheduleLongPressTimer();
    ASSERT_EQ(manager_->controller_.GetState(), PttState::PENDING);

    manager_->HandleKeyEvent({ MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_UP, { } });
    ASSERT_TRUE(handler_->PostSyncTask([]() { }, "PttManagerTestDrain", AppExecFwk::EventQueue::Priority::IMMEDIATE));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::IDLE);
    EXPECT_EQ(manager_->gestureUserId_, PushToTalkManager::INVALID_USER_ID);
    EXPECT_EQ(manager_->gestureClientSnapshot_.client, nullptr);
}

/**
 * @tc.name: PushToTalkManager_InvalidTimerConfig_001
 * @tc.desc: Suppress a pending gesture and clear its snapshot when the configured delay is zero.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerTest, PushToTalkManager_InvalidTimerConfig_001, TestSize.Level0)
{
    auto runner = AppExecFwk::EventRunner::Create("PttManagerInvalidTimer");
    ASSERT_NE(runner, nullptr);
    handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_NE(handler_, nullptr);
    ImeInfoInquirer::GetInstance().systemConfig_.pushToTalkLongPressMs = 0;
    manager_->controller_.HandleKeyEvent(MakePttSpaceDownEvent());
    manager_->gestureUserId_ = PTT_MISSING_USER_ID;
    manager_->gestureClientSnapshot_.client = settingsToken_->AsObject();

    manager_->ScheduleLongPressTimer();
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    EXPECT_EQ(manager_->gestureUserId_, PushToTalkManager::INVALID_USER_ID);
    EXPECT_EQ(manager_->gestureClientSnapshot_.client, nullptr);
}

/**
 * @tc.name: PttSettingsManager_ValueParsing_001
 * @tc.desc: Verify invalid users and the exact enabled setting value.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerTest, PttSettingsManager_ValueParsing_001, TestSize.Level0)
{
    EXPECT_FALSE(PttSettingsManager::IsEnabled(-1));

    SetPttSetting("true");
    EXPECT_FALSE(PttSettingsManager::IsEnabled(PTT_TEST_USER_ID));
    SetPttSetting("false");
    EXPECT_FALSE(PttSettingsManager::IsEnabled(PTT_TEST_USER_ID));
    SetPttSetting("TRUE");
    EXPECT_FALSE(PttSettingsManager::IsEnabled(PTT_TEST_USER_ID));
}

/**
 * @tc.name: PttService_GestureContextLifecycle_001
 * @tc.desc: Verify eligible-client binding, identity comparison, validation, and cleanup.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerTest, PttService_GestureContextLifecycle_001, TestSize.Level0)
{
    auto context = CreateEligibleClientContext();
    ASSERT_NE(context.session, nullptr);
    ASSERT_NE(context.group, nullptr);
    ASSERT_NE(context.client, nullptr);
    SetPttSetting("true");

    FocusedRealImeClientSnapshot snapshot;
    EXPECT_FALSE(manager_->GetEligibleClient(PTT_TEST_USER_ID, snapshot));
    EXPECT_EQ(snapshot.client, context.client->AsObject());
    EXPECT_EQ(snapshot.channel, context.channel);
    EXPECT_EQ(snapshot.clientGroupId, PTT_TEST_GROUP_ID);
    EXPECT_EQ(snapshot.editorWindowId, PTT_TEST_WINDOW_ID);
    EXPECT_EQ(snapshot.editorDisplayId, PTT_TEST_DISPLAY_ID);

    EXPECT_TRUE(PushToTalkManager::IsSameInputClient(snapshot, snapshot));
    auto different = snapshot;
    different.client = nullptr;
    EXPECT_FALSE(PushToTalkManager::IsSameInputClient(different, snapshot));
    different = snapshot;
    different.channel = nullptr;
    EXPECT_FALSE(PushToTalkManager::IsSameInputClient(snapshot, different));
    different = snapshot;
    ++different.clientGroupId;
    EXPECT_FALSE(PushToTalkManager::IsSameInputClient(snapshot, different));
    different = snapshot;
    ++different.editorWindowId;
    EXPECT_FALSE(PushToTalkManager::IsSameInputClient(snapshot, different));
    different = snapshot;
    ++different.editorDisplayId;
    EXPECT_FALSE(PushToTalkManager::IsSameInputClient(snapshot, different));

    EXPECT_FALSE(manager_->BindGestureContext(PTT_TEST_USER_ID));
    manager_->gestureUserId_ = PTT_TEST_USER_ID;
    EXPECT_FALSE(manager_->IsGestureContextValid(PTT_TEST_USER_ID));

    auto clientInfo = context.group->GetClientInfo(context.client->AsObject());
    ASSERT_NE(clientInfo, nullptr);
    ++clientInfo->config.inputAttribute.editorWindowId;
    EXPECT_FALSE(manager_->IsGestureContextValid(PTT_TEST_USER_ID));
    --clientInfo->config.inputAttribute.editorWindowId;

    manager_->ClearGestureContext();
    EXPECT_EQ(manager_->gestureUserId_, PushToTalkManager::INVALID_USER_ID);
    EXPECT_EQ(manager_->gestureClientSnapshot_.client, nullptr);
    EXPECT_FALSE(manager_->IsGestureContextValid(PTT_TEST_USER_ID));

    SetPttSetting("false");
    EXPECT_FALSE(manager_->GetEligibleClient(PTT_TEST_USER_ID, snapshot));
}

/**
 * @tc.name: PttService_UnavailablePaths_001
 * @tc.desc: Verify the manager's missing-handler, missing-session, and missing-client guards.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerTest, PttService_UnavailablePaths_001, TestSize.Level0)
{
    EXPECT_EQ(manager_->NotifyRollbackSpace(PTT_MISSING_USER_ID), ErrorCode::ERROR_NULL_POINTER);
    EXPECT_EQ(manager_->RestoreCurrentIme(PTT_MISSING_USER_ID), ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND);

    FocusedRealImeClientSnapshot snapshot;
    EXPECT_FALSE(manager_->GetEligibleClient(PTT_MISSING_USER_ID, snapshot));
    EXPECT_FALSE(manager_->BindGestureContext(PTT_MISSING_USER_ID));
    manager_->gestureUserId_ = PTT_MISSING_USER_ID;
    EXPECT_FALSE(manager_->IsGestureContextValid(PTT_MISSING_USER_ID));
    manager_->NotifyGestureCancelled(PushToTalkManager::INVALID_USER_ID);
    manager_->NotifyGestureCancelled(PTT_MISSING_USER_ID);

    manager_->HandleKeyEvent(MakePttSpaceDownEvent());
    EXPECT_EQ(manager_->controller_.GetState(), PttState::IDLE);

    manager_->controller_.HandleKeyEvent(MakePttSpaceDownEvent());
    EXPECT_FALSE(manager_->EnableSpaceKeyEventBlock(PTT_MISSING_USER_ID));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
}

/**
 * @tc.name: PttService_AvailabilityReadyPaths_001
 * @tc.desc: Verify current-IME validation and exact input-channel matching when PTT handling is ready.
 * @tc.type: FUNC
 */
HWTEST_F(PttServiceTest, PttService_AvailabilityReadyPaths_001, TestSize.Level0)
{
    int32_t callingUserId = ability_->GetCallingUserId();
    ASSERT_GE(callingUserId, 0);
    auto context = CreateEligibleClientContext(callingUserId);
    ASSERT_NE(context.session, nullptr);
    ASSERT_NE(context.channel, nullptr);
    auto imeData = std::make_shared<ImeData>(settingsToken_, nullptr, nullptr, PTT_TEST_IME_PID);
    ASSERT_NE(imeData, nullptr);
    imeData->type = ImeType::IME;
    imeData->imeStatus = ImeStatus::READY;
    imeData->ime = { PTT_TEST_IME_BUNDLE, "PttImeExtension" };
    context.session->realImeData_ = imeData;

    auto runner = AppExecFwk::EventRunner::Create("PttServiceAvailability");
    ASSERT_NE(runner, nullptr);
    auto handler = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_NE(handler, nullptr);
    sptr<InputMethodCoreServiceImpl> otherChannel = new (std::nothrow) InputMethodCoreServiceImpl();
    ASSERT_NE(otherChannel, nullptr);
    SetPttSetting("true");

    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    ScopedFullImeInfos fullImeInfos(callingUserId);
    FullImeInfo nonCurrentInfo;
    nonCurrentInfo.tokenId = callingTokenId;
    nonCurrentInfo.prop.name = "com.test.other.ime";
    fullImeInfos.ReplaceWith(nonCurrentInfo);

    ability_->serviceHandler_ = handler;
    bool isAvailable = true;
    EXPECT_EQ(ability_->IsPttGestureAvailable(context.channel, isAvailable), ERR_OK);
    EXPECT_FALSE(isAvailable);
    ability_->pushToTalkManager_->SetKeyEventMonitorReady(true);
    EXPECT_EQ(ability_->IsPttGestureAvailable(context.channel, isAvailable), ErrorCode::ERROR_NOT_CURRENT_IME);
    EXPECT_FALSE(isAvailable);

    FullImeInfo currentInfo;
    currentInfo.tokenId = callingTokenId;
    currentInfo.prop.name = PTT_TEST_IME_BUNDLE;
    fullImeInfos.ReplaceWith(currentInfo);
    EXPECT_EQ(ability_->IsPttGestureAvailable(otherChannel->AsObject(), isAvailable), ERR_OK);
    EXPECT_FALSE(isAvailable);
    EXPECT_EQ(ability_->IsPttGestureAvailable(context.channel, isAvailable), ERR_OK);
    EXPECT_FALSE(isAvailable);
}

/**
 * @tc.name: PttService_ActionFailureCleanup_001
 * @tc.desc: Verify every action branch cleans up failed gesture state safely.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerTest, PttService_ActionFailureCleanup_001, TestSize.Level0)
{
    manager_->controller_.HandleKeyEvent(MakePttSpaceDownEvent());
    manager_->ApplyAction(PttAction::START_TIMER, PTT_MISSING_USER_ID);
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    EXPECT_EQ(manager_->gestureUserId_, PushToTalkManager::INVALID_USER_ID);

    manager_->controller_.Reset();
    manager_->controller_.HandleKeyEvent(MakePttSpaceDownEvent());
    manager_->gestureUserId_ = PTT_MISSING_USER_ID;
    manager_->ScheduleLongPressTimer();
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    EXPECT_EQ(manager_->gestureUserId_, PushToTalkManager::INVALID_USER_ID);

    manager_->gestureUserId_ = PTT_MISSING_USER_ID;
    manager_->ApplyAction(PttAction::CANCEL_TIMER, PTT_MISSING_USER_ID);
    EXPECT_EQ(manager_->gestureUserId_, PushToTalkManager::INVALID_USER_ID);

    manager_->controller_.Reset();
    manager_->controller_.HandleKeyEvent(MakePttSpaceDownEvent());
    manager_->controller_.HandleTimeout();
    manager_->gestureUserId_ = PushToTalkManager::INVALID_USER_ID;
    manager_->ApplyAction(PttAction::START_VOICE, PTT_MISSING_USER_ID);
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);

    manager_->controller_.Reset();
    manager_->controller_.HandleKeyEvent(MakePttSpaceDownEvent());
    manager_->controller_.HandleTimeout();
    manager_->gestureUserId_ = PushToTalkManager::INVALID_USER_ID;
    manager_->ApplyAction(PttAction::STOP_VOICE, PTT_MISSING_USER_ID);
    EXPECT_EQ(manager_->gestureUserId_, PushToTalkManager::INVALID_USER_ID);

    manager_->controller_.Reset();
    manager_->gestureUserId_ = PTT_MISSING_USER_ID;
    manager_->ApplyAction(PttAction::NONE, PTT_MISSING_USER_ID);
    EXPECT_EQ(manager_->gestureUserId_, PushToTalkManager::INVALID_USER_ID);
    manager_->ApplyAction(static_cast<PttAction>(255), PTT_MISSING_USER_ID);
}

/**
 * @tc.name: PttService_EnableClientSpaceBlock_001
 * @tc.desc: Verify the service enables blocking through the captured input client.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerTest, PttService_EnableClientSpaceBlock_001, TestSize.Level0)
{
    auto context = CreateEligibleClientContext();
    ASSERT_NE(context.client, nullptr);

    auto controller = InputMethodController::GetInstance();
    ASSERT_NE(controller, nullptr);
    controller->isEditable_.store(true);
    controller->isBound_.store(true);
    controller->pttSpaceKeyEventState_.store(InputMethodController::PttSpaceKeyEventState::DOWN);
    manager_->gestureClientSnapshot_.client = context.client->AsObject();

    EXPECT_TRUE(manager_->EnableSpaceKeyEventBlock(PTT_TEST_USER_ID));
    EXPECT_EQ(controller->pttSpaceKeyEventState_.load(), InputMethodController::PttSpaceKeyEventState::BLOCKED);

    EXPECT_EQ(context.client->StartPttSpaceKeyEventBlock(), ErrorCode::ERROR_BAD_PARAMETERS);
    controller->pttSpaceKeyEventState_.store(InputMethodController::PttSpaceKeyEventState::DOWN);
    EXPECT_EQ(context.client->StartPttSpaceKeyEventBlock(), ERR_OK);
}
} // namespace MiscServices
} // namespace OHOS
