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

#include <chrono>
#include <cstdlib>
#include <future>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <unordered_map>
#include <vector>

#include "../mock/push_to_talk_test_env.h"
#include "cJSON.h"
#include "event_runner.h"
#include "ime_info_inquirer.h"
#include "input_death_recipient.h"
#include "input_type_manager.h"
#include "ptt_settings_manager.h"
#include "push_to_talk_manager.h"
#include "user_session_manager.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
namespace {
constexpr uint32_t PTT_TIMER_DELAY_MS = 10;
constexpr uint32_t PTT_MANUAL_TIMER_DELAY_MS = 60000;
constexpr uint32_t PTT_TIMER_BARRIER_DELAY_MS = PTT_TIMER_DELAY_MS + 1;
constexpr int64_t PTT_TIMER_WAIT_TIMEOUT_SECONDS = 3;
constexpr pid_t PTT_CLIENT_PID = 101;
constexpr int32_t PTT_CLIENT_UID = 102;
constexpr pid_t PTT_IME_PID = 103;
constexpr int32_t PTT_SINGLE_DIALOG_ACTION_COUNT = 1;
constexpr uint64_t PTT_GROUP_ID = 91;
constexpr uint32_t PTT_WINDOW_ID = 92;
constexpr uint64_t PTT_DISPLAY_ID = 93;
constexpr const char *PTT_DIALOG_PARAM_KEY = "ability.want.params.uiExtensionType";
constexpr const char *PTT_DIALOG_PARAM_VALUE = "sysDialog/common";

struct CJsonAllocationState {
    size_t allocationCount { 0 };
    size_t failedAllocation { 0 };
};

CJsonAllocationState &GetCJsonAllocationState()
{
    static CJsonAllocationState state;
    return state;
}

void *AllocateCJsonMemory(size_t size)
{
    auto &state = GetCJsonAllocationState();
    ++state.allocationCount;
    return state.failedAllocation == state.allocationCount ? nullptr : std::malloc(size);
}

void FreeCJsonMemory(void *ptr)
{
    std::free(ptr);
}

KeyboardEventInfo SpaceDown()
{
    return { MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_DOWN, { MMI::KeyEvent::KEYCODE_SPACE } };
}

KeyboardEventInfo SpaceUp()
{
    return { MMI::KeyEvent::KEYCODE_SPACE, MMI::KeyEvent::KEY_ACTION_UP, {} };
}
} // namespace

class PushToTalkManagerUnitTest : public testing::Test {
public:
    void SetUp() override
    {
        state_ = {};
        originalConfig_ = ImeInfoInquirer::GetInstance().systemConfig_;
        originalInputTypeStarted_ = InputTypeManager::GetInstance().IsStarted();
        originalInputTypeIme_ = InputTypeManager::GetInstance().GetCurrentIme();
        SaveSessions();
        auto runner = AppExecFwk::EventRunner::Create("PttManagerUnitTest");
        ASSERT_NE(runner, nullptr);
        handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
        ASSERT_NE(handler_, nullptr);
        serviceHandler_ = handler_;
        CreateManager();
        ASSERT_NE(manager_, nullptr);
        CreateClientContext();
        ASSERT_FALSE(HasFatalFailure());
        auto &config = ImeInfoInquirer::GetInstance().systemConfig_;
        config.pushToTalkLongPressMs = PTT_MANUAL_TIMER_DELAY_MS;
        config.enablePushToTalk = true;
        config.pushToTalkDialogBundleName = "com.test.ptt.dialog";
        config.pushToTalkDialogAbilityName = "PttDialogAbility";
        state_.currentIme = std::make_shared<Property>();
        ASSERT_NE(state_.currentIme, nullptr);
        state_.currentIme->name = "com.test.ptt.ime";
    }

    void TearDown() override
    {
        ResetCJsonHooks();
        if (handler_ != nullptr) {
            handler_->RemoveTask(PushToTalkManager::KEY_EVENT_TASK);
            // Remove timers on the runner after any in-flight key action has finished scheduling them.
            EXPECT_TRUE(handler_->PostSyncTask(
                [this]() {
                    handler_->RemoveTask(PushToTalkManager::TIMEOUT_TASK);
                },
                "PttUnitTestDrain", AppExecFwk::EventQueue::Priority::IMMEDIATE));
        }
        manager_.reset();
        serviceHandler_.reset();
        handler_.reset();
        ImeInfoInquirer::GetInstance().systemConfig_ = originalConfig_;
        InputTypeManager::GetInstance().Set(originalInputTypeStarted_, originalInputTypeIme_);
        auto &sessions = UserSessionManager::GetInstance();
        {
            std::lock_guard<std::mutex> lock(sessions.userSessionsLock_);
            sessions.userSessions_.swap(originalSessions_);
        }
        originalSessions_.clear();
        group_.reset();
        session_.reset();
    }

    void SaveSessions()
    {
        auto &sessions = UserSessionManager::GetInstance();
        std::lock_guard<std::mutex> lock(sessions.userSessionsLock_);
        originalSessions_.swap(sessions.userSessions_);
    }

    void CreateManager(bool hasStartHandler = true)
    {
        PushToTalkManager::StartInputTypeHandler startHandler;
        if (hasStartHandler) {
            startHandler = [this](int32_t userId) {
                state_.calls.emplace_back("start");
                state_.startedUserId = userId;
                return state_.startResult;
            };
        }
        manager_ = std::make_shared<PushToTalkManager>(
            [this]() {
                return serviceHandler_;
            },
            startHandler);
    }

    void CreateClientContext()
    {
        session_ = std::make_shared<PerUserSession>(PTT_UNIT_TEST_USER_ID, nullptr);
        ASSERT_NE(session_, nullptr);
        client_ = new (std::nothrow) PttTestClient();
        channel_ = new (std::nothrow) PttTestClient();
        sptr<InputDeathRecipient> recipient = new (std::nothrow) InputDeathRecipient();
        ASSERT_NE(client_, nullptr);
        ASSERT_NE(channel_, nullptr);
        ASSERT_NE(recipient, nullptr);
        InputClientInfo info;
        info.pid = PTT_CLIENT_PID;
        info.uid = PTT_CLIENT_UID;
        info.userID = PTT_UNIT_TEST_USER_ID;
        info.client = client_;
        info.channel = channel_->AsObject();
        info.deathRecipient = recipient;
        info.clientGroupId = PTT_GROUP_ID;
        info.state = ClientState::ACTIVE;
        info.bindImeData = std::make_shared<BindImeData>(PTT_IME_PID, ImeType::IME);
        ASSERT_NE(info.bindImeData, nullptr);
        info.config.inputAttribute.editorWindowId = PTT_WINDOW_ID;
        info.config.inputAttribute.editorDisplayId = PTT_DISPLAY_ID;
        ASSERT_EQ(session_->OnPrepareInput(info), ErrorCode::NO_ERROR);
        group_ = session_->GetClientGroupByGroupId(PTT_GROUP_ID);
        ASSERT_NE(group_, nullptr);
        group_->SetCurrentClient(client_);
        auto &sessions = UserSessionManager::GetInstance();
        std::lock_guard<std::mutex> lock(sessions.userSessionsLock_);
        sessions.userSessions_.emplace(PTT_UNIT_TEST_USER_ID, session_);
    }

    bool BindPendingGesture()
    {
        manager_->controller_.Reset();
        if (manager_->controller_.HandleKeyEvent(SpaceDown()) != PttAction::START_TIMER ||
            !manager_->BindGestureContext(PTT_UNIT_TEST_USER_ID)) {
            return false;
        }
        manager_->gestureUserId_ = PTT_UNIT_TEST_USER_ID;
        return true;
    }

    bool PrepareVoice()
    {
        return BindPendingGesture() && manager_->controller_.HandleTimeout() == PttAction::START_VOICE;
    }

    bool SendKeyEvent(const KeyboardEventInfo &event)
    {
        manager_->HandleKeyEvent(event);
        return handler_->PostSyncTask([]() {}, "PttUnitKeyBarrier", AppExecFwk::EventQueue::Priority::IMMEDIATE);
    }

    bool WaitForTimer()
    {
        auto done = std::make_shared<std::promise<void>>();
        auto future = done->get_future();
        auto callback = [done]() {
            done->set_value();
        };
        if (!handler_->PostTask(callback, "PttUnitTimerBarrier", PTT_TIMER_BARRIER_DELAY_MS)) {
            return false;
        }
        return future.wait_for(std::chrono::seconds(PTT_TIMER_WAIT_TIMEOUT_SECONDS)) == std::future_status::ready;
    }

    void ConfigureCJsonFailure(size_t failedAllocation)
    {
        GetCJsonAllocationState() = { 0, failedAllocation };
        cJSON_Hooks hooks { AllocateCJsonMemory, FreeCJsonMemory };
        cJSON_InitHooks(&hooks);
    }

    size_t CountCJsonParameterAllocations()
    {
        ConfigureCJsonFailure(0);
        cJSON *paramJson = cJSON_CreateObject();
        if (paramJson == nullptr) {
            return 0;
        }
        cJSON_AddStringToObject(paramJson, PTT_DIALOG_PARAM_KEY, PTT_DIALOG_PARAM_VALUE);
        const size_t allocationCount = GetCJsonAllocationState().allocationCount;
        cJSON_Delete(paramJson);
        return allocationCount;
    }

    void ResetCJsonHooks()
    {
        cJSON_InitHooks(nullptr);
        GetCJsonAllocationState() = {};
    }

    void ExpectContextCleared()
    {
        EXPECT_EQ(manager_->gestureUserId_, PushToTalkManager::INVALID_USER_ID);
        std::lock_guard<std::mutex> lock(manager_->gestureClientSnapshotMutex_);
        const auto &snapshot = manager_->gestureClientSnapshot_;
        EXPECT_EQ(snapshot.client, nullptr);
        EXPECT_EQ(snapshot.channel, nullptr);
        EXPECT_EQ(snapshot.clientGroupId, 0);
        EXPECT_EQ(snapshot.editorWindowId, 0);
        EXPECT_EQ(snapshot.editorDisplayId, 0);
    }

    PttTestState &state_ { GetPttTestState() };
    std::shared_ptr<PushToTalkManager> manager_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
    std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    std::shared_ptr<PerUserSession> session_;
    std::shared_ptr<ClientGroup> group_;
    sptr<PttTestClient> client_;
    sptr<PttTestClient> channel_;
    SystemConfig originalConfig_;
    bool originalInputTypeStarted_ { false };
    ImeIdentification originalInputTypeIme_;
    std::unordered_map<int32_t, std::shared_ptr<PerUserSession>> originalSessions_;
};

/**
 * @tc.name: HandlerReadiness
 * @tc.desc: Readiness follows the monitor flag and the current handler provider.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, HandlerReadiness, TestSize.Level0)
{
    PushToTalkManager noProvider(nullptr, nullptr);
    noProvider.SetKeyEventMonitorReady(true);
    EXPECT_FALSE(noProvider.IsReady());
    EXPECT_FALSE(manager_->IsReady());
    manager_->SetKeyEventMonitorReady(true);
    EXPECT_TRUE(manager_->IsReady());
    serviceHandler_.reset();
    EXPECT_FALSE(manager_->IsReady());
    manager_->HandleKeyEvent(SpaceDown());
    EXPECT_EQ(manager_->controller_.GetState(), PttState::IDLE);
    serviceHandler_ = handler_;
    EXPECT_TRUE(manager_->IsReady());
    manager_->SetKeyEventMonitorReady(false);
    EXPECT_FALSE(manager_->IsReady());
}

/**
 * @tc.name: GestureEligibility
 * @tc.desc: Require an enabled setting, a focused real client and the matching channel.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, GestureEligibility, TestSize.Level0)
{
    ASSERT_TRUE(PttSettingsManager::IsEnabled(PTT_UNIT_TEST_USER_ID));
    EXPECT_TRUE(manager_->IsGestureAvailable(PTT_UNIT_TEST_USER_ID, channel_->AsObject()));
    EXPECT_FALSE(manager_->IsGestureAvailable(PTT_UNIT_TEST_USER_ID, client_->AsObject()));
    EXPECT_FALSE(manager_->IsGestureAvailable(PTT_UNIT_TEST_USER_ID, nullptr));
    EXPECT_FALSE(manager_->IsGestureAvailable(PTT_UNIT_MISSING_USER_ID, channel_->AsObject()));
    state_.settingValue = "false";
    EXPECT_FALSE(manager_->IsGestureAvailable(PTT_UNIT_TEST_USER_ID, channel_->AsObject()));
    state_.settingValue = "true";
    state_.settingResult = ErrorCode::ERROR_NULL_POINTER;
    EXPECT_FALSE(manager_->IsGestureAvailable(PTT_UNIT_TEST_USER_ID, channel_->AsObject()));
    state_.settingResult = ErrorCode::NO_ERROR;
    group_->SetCurrentClient(nullptr);
    EXPECT_FALSE(manager_->IsGestureAvailable(PTT_UNIT_TEST_USER_ID, channel_->AsObject()));
}

/**
 * @tc.name: SnapshotIdentity
 * @tc.desc: Every captured client and editor identity field participates in validation.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, SnapshotIdentity, TestSize.Level0)
{
    FocusedRealImeClientSnapshot original;
    ASSERT_TRUE(session_->GetFocusedRealImeClient(original));
    FocusedRealImeClientSnapshot identicalSnapshot = original;
    EXPECT_TRUE(PushToTalkManager::IsSameInputClient(original, identicalSnapshot));
    std::vector<FocusedRealImeClientSnapshot> changed(5, original);
    changed[0].client = channel_->AsObject();
    changed[1].channel = client_->AsObject();
    ++changed[2].clientGroupId;
    ++changed[3].editorWindowId;
    ++changed[4].editorDisplayId;
    for (const auto &snapshot : changed) {
        EXPECT_FALSE(PushToTalkManager::IsSameInputClient(original, snapshot));
    }
    EXPECT_FALSE(PushToTalkManager::IsSameInputClient({}, {}));
}

/**
 * @tc.name: BindAndClearContext
 * @tc.desc: Bind a valid snapshot, reject another user and fully clear a completed gesture.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, BindAndClearContext, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    EXPECT_TRUE(manager_->IsGestureContextValid(PTT_UNIT_TEST_USER_ID));
    EXPECT_FALSE(manager_->IsGestureContextValid(PTT_UNIT_MISSING_USER_ID));
    manager_->ClearGestureContext();
    ExpectContextCleared();
    EXPECT_FALSE(manager_->IsGestureContextValid(PTT_UNIT_TEST_USER_ID));
    ASSERT_TRUE(PrepareVoice());
    state_.settingValue = "false";
    EXPECT_FALSE(manager_->BindGestureContext(PTT_UNIT_TEST_USER_ID));
    EXPECT_EQ(manager_->gestureClientSnapshot_.client, nullptr);
    EXPECT_EQ(manager_->gestureClientSnapshot_.channel, nullptr);
}

/**
 * @tc.name: LongPressStartsAndReleaseRestores
 * @tc.desc: A real queued timeout starts voice in order; releasing space stops and restores the IME.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, LongPressStartsAndReleaseRestores, TestSize.Level0)
{
    ImeInfoInquirer::GetInstance().systemConfig_.pushToTalkLongPressMs = PTT_TIMER_DELAY_MS;
    ASSERT_TRUE(SendKeyEvent(SpaceDown()));
    ASSERT_TRUE(WaitForTimer());
    EXPECT_EQ(manager_->controller_.GetState(), PttState::ACTIVE);
    EXPECT_EQ(state_.foregroundQueries, 1);
    EXPECT_EQ(state_.startedUserId, PTT_UNIT_TEST_USER_ID);
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "block", "rollback", "start" }));
    EXPECT_TRUE(manager_->IsGestureContextValid(PTT_UNIT_TEST_USER_ID));
    InputTypeManager::GetInstance().Set(true);
    ASSERT_TRUE(SendKeyEvent(SpaceUp()));
    const std::vector<std::string> expectedCallSequence { "block", "rollback", "start", "stop", "restore" };
    EXPECT_EQ(state_.calls, expectedCallSequence);
    EXPECT_EQ(state_.sessionUserIds, (std::vector<int32_t>(3, PTT_UNIT_TEST_USER_ID)));
    EXPECT_FALSE(state_.inputTypeStartedOnRestore);
    EXPECT_FALSE(InputTypeManager::GetInstance().IsStarted());
    EXPECT_EQ(manager_->controller_.GetState(), PttState::IDLE);
    ExpectContextCleared();
}

/**
 * @tc.name: ReleaseBeforeTimeoutCancels
 * @tc.desc: Queue a down/up pair together so cancellation cannot race with a slow test thread.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, ReleaseBeforeTimeoutCancels, TestSize.Level0)
{
    ImeInfoInquirer::GetInstance().systemConfig_.pushToTalkLongPressMs = PTT_TIMER_DELAY_MS;
    ASSERT_TRUE(handler_->PostSyncTask(
        [this]() {
            manager_->HandleKeyEvent(SpaceDown());
            manager_->HandleKeyEvent(SpaceUp());
        },
        "PttUnitShortPress", AppExecFwk::EventQueue::Priority::IMMEDIATE));
    ASSERT_TRUE(handler_->PostSyncTask([]() {}, "PttUnitShortPressDrain", AppExecFwk::EventQueue::Priority::IMMEDIATE));
    ASSERT_TRUE(WaitForTimer());
    EXPECT_TRUE(state_.calls.empty());
    EXPECT_EQ(manager_->controller_.GetState(), PttState::IDLE);
    ExpectContextCleared();
}

/**
 * @tc.name: StaleTimerDoesNotStartAnotherUser
 * @tc.desc: A timeout captured for an earlier user cannot affect the current gesture.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, StaleTimerDoesNotStartAnotherUser, TestSize.Level0)
{
    ImeInfoInquirer::GetInstance().systemConfig_.pushToTalkLongPressMs = PTT_TIMER_DELAY_MS;
    ASSERT_TRUE(handler_->PostSyncTask(
        [this]() {
            manager_->controller_.HandleKeyEvent(SpaceDown());
            manager_->ApplyAction(PttAction::START_TIMER, PTT_UNIT_TEST_USER_ID);
            manager_->gestureUserId_ = PTT_UNIT_MISSING_USER_ID;
        },
        "PttUnitStaleTimer", AppExecFwk::EventQueue::Priority::IMMEDIATE));
    ASSERT_TRUE(WaitForTimer());
    EXPECT_TRUE(state_.calls.empty());
    EXPECT_EQ(manager_->controller_.GetState(), PttState::PENDING);
    EXPECT_EQ(manager_->gestureUserId_, PTT_UNIT_MISSING_USER_ID);
}

/**
 * @tc.name: TimeoutAfterResetDoesNotStartVoice
 * @tc.desc: A timeout in IDLE resolves to no action and clears the obsolete context.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, TimeoutAfterResetDoesNotStartVoice, TestSize.Level0)
{
    ImeInfoInquirer::GetInstance().systemConfig_.pushToTalkLongPressMs = PTT_TIMER_DELAY_MS;
    ASSERT_TRUE(handler_->PostSyncTask(
        [this]() {
            manager_->controller_.HandleKeyEvent(SpaceDown());
            manager_->ApplyAction(PttAction::START_TIMER, PTT_UNIT_TEST_USER_ID);
            manager_->controller_.Reset();
        },
        "PttUnitResetTimer", AppExecFwk::EventQueue::Priority::IMMEDIATE));
    ASSERT_TRUE(WaitForTimer());
    EXPECT_TRUE(state_.calls.empty());
    EXPECT_EQ(manager_->controller_.GetState(), PttState::IDLE);
    ExpectContextCleared();
}

/**
 * @tc.name: ForegroundLookupFailureSuppresses
 * @tc.desc: Both a failed account query and an invalid returned user suppress the pending gesture.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, ForegroundLookupFailureSuppresses, TestSize.Level0)
{
    state_.foregroundResult = ErrorCode::ERROR_NULL_POINTER;
    ASSERT_TRUE(SendKeyEvent(SpaceDown()));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
    ASSERT_TRUE(SendKeyEvent(SpaceUp()));
    state_.foregroundResult = ERR_OK;
    state_.foregroundUserId = PushToTalkManager::INVALID_USER_ID;
    ASSERT_TRUE(SendKeyEvent(SpaceDown()));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    EXPECT_EQ(state_.foregroundQueries, 2);
    EXPECT_TRUE(state_.calls.empty());
    ExpectContextCleared();
}

/**
 * @tc.name: DisabledGestureNotifiesCancellation
 * @tc.desc: Failure to bind a client cancels IME key tracking and suppresses until space up.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, DisabledGestureNotifiesCancellation, TestSize.Level0)
{
    state_.settingValue = "false";
    ASSERT_TRUE(SendKeyEvent(SpaceDown()));
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "cancel" }));
    EXPECT_EQ(state_.sessionUserIds, (std::vector<int32_t> { PTT_UNIT_TEST_USER_ID }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
    ASSERT_TRUE(SendKeyEvent(SpaceDown()));
    EXPECT_EQ(state_.calls.size(), 1);
    ASSERT_TRUE(SendKeyEvent(SpaceUp()));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::IDLE);
}

/**
 * @tc.name: TimerSetupFailuresCancelAndClear
 * @tc.desc: Missing handlers and zero delay reject scheduling and release the bound context.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, TimerSetupFailuresCancelAndClear, TestSize.Level0)
{
    ASSERT_TRUE(BindPendingGesture());
    serviceHandler_.reset();
    manager_->ScheduleLongPressTimer();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
    serviceHandler_ = handler_;
    ASSERT_TRUE(BindPendingGesture());
    ImeInfoInquirer::GetInstance().systemConfig_.pushToTalkLongPressMs = 0;
    manager_->ScheduleLongPressTimer();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "cancel", "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
}

/**
 * @tc.name: FailedTaskPostingDoesNotLeaveBoundGesture
 * @tc.desc: An unbound EventHandler rejects key tasks and cancels a timer that cannot be posted.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, FailedTaskPostingDoesNotLeaveBoundGesture, TestSize.Level0)
{
    serviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(nullptr);
    ASSERT_NE(serviceHandler_, nullptr);
    ASSERT_EQ(serviceHandler_->GetEventRunner(), nullptr);
    manager_->HandleKeyEvent(SpaceDown());
    EXPECT_EQ(manager_->controller_.GetState(), PttState::IDLE);
    EXPECT_TRUE(state_.calls.empty());
    ASSERT_TRUE(BindPendingGesture());
    manager_->ScheduleLongPressTimer();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
}

/**
 * @tc.name: CancelWithoutHandlerClearsContext
 * @tc.desc: Losing the service handler still permits local gesture cleanup.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, CancelWithoutHandlerClearsContext, TestSize.Level0)
{
    ASSERT_TRUE(BindPendingGesture());
    serviceHandler_.reset();
    manager_->ApplyAction(PttAction::CANCEL_TIMER, PTT_UNIT_TEST_USER_ID);
    ExpectContextCleared();
    EXPECT_TRUE(state_.calls.empty());
}

/**
 * @tc.name: InvalidVoiceUserSuppresses
 * @tc.desc: Starting without a bound user cannot block space or call the voice handler.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, InvalidVoiceUserSuppresses, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    manager_->gestureUserId_ = PushToTalkManager::INVALID_USER_ID;
    manager_->ApplyAction(PttAction::START_VOICE, PTT_UNIT_TEST_USER_ID);
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    EXPECT_TRUE(state_.calls.empty());
    ExpectContextCleared();
}

/**
 * @tc.name: BackgroundUserCancelsOriginalGesture
 * @tc.desc: A foreground user switch cancels the original user's gesture before starting voice.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, BackgroundUserCancelsOriginalGesture, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    state_.foregroundUserId = PTT_UNIT_MISSING_USER_ID;
    manager_->HandleStartVoice();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "cancel" }));
    EXPECT_EQ(state_.sessionUserIds, (std::vector<int32_t> { PTT_UNIT_TEST_USER_ID }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
}

/**
 * @tc.name: EditorChangeCancelsVoice
 * @tc.desc: A changed editor window invalidates a previously eligible focused client.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, EditorChangeCancelsVoice, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    auto info = group_->GetClientInfo(client_->AsObject());
    ASSERT_NE(info, nullptr);
    ++info->config.inputAttribute.editorWindowId;
    EXPECT_FALSE(manager_->IsGestureContextValid(PTT_UNIT_TEST_USER_ID));
    manager_->HandleStartVoice();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
}

/**
 * @tc.name: SettingDisabledDuringGestureCancelsVoice
 * @tc.desc: Recheck the setting at timeout instead of trusting the value captured on key down.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, SettingDisabledDuringGestureCancelsVoice, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    state_.settingValue = "false";
    manager_->HandleStartVoice();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
}

/**
 * @tc.name: SpaceBlockFailurePreventsRollbackAndStart
 * @tc.desc: A client-side blocking error must cancel before rollback or voice startup.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, SpaceBlockFailurePreventsRollbackAndStart, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    state_.blockResult = ErrorCode::ERROR_NULL_POINTER;
    manager_->HandleStartVoice();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "block", "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
}

/**
 * @tc.name: MissingBlockClientCancels
 * @tc.desc: A missing captured remote client fails the block request and clears the gesture.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, MissingBlockClientCancels, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    manager_->gestureClientSnapshot_.client = nullptr;
    EXPECT_FALSE(manager_->EnableSpaceKeyEventBlock(PTT_UNIT_TEST_USER_ID));
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
}

/**
 * @tc.name: RollbackFailureStillStartsVoice
 * @tc.desc: Rollback errors are nonfatal and must not discard an otherwise valid voice gesture.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, RollbackFailureStillStartsVoice, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    state_.rollbackResult = ErrorCode::ERROR_IME_NOT_STARTED;
    manager_->HandleStartVoice();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "block", "rollback", "start" }));
    EXPECT_EQ(state_.startedUserId, PTT_UNIT_TEST_USER_ID);
    EXPECT_EQ(manager_->controller_.GetState(), PttState::ACTIVE);
    EXPECT_TRUE(manager_->IsGestureContextValid(PTT_UNIT_TEST_USER_ID));
}

/**
 * @tc.name: StartFailureCancelsAndSuppresses
 * @tc.desc: Propagate a failed voice callback into cancellation and wait for space up.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, StartFailureCancelsAndSuppresses, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    state_.startResult = ErrorCode::ERROR_IME_NOT_STARTED;
    manager_->HandleStartVoice();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "block", "rollback", "start", "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
    ASSERT_TRUE(SendKeyEvent(SpaceUp()));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::IDLE);
    EXPECT_EQ(state_.calls.size(), 4);
}

/**
 * @tc.name: MissingStartCallbackCancels
 * @tc.desc: An absent start callback follows the same cleanup path as a failed callback.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, MissingStartCallbackCancels, TestSize.Level0)
{
    CreateManager(false);
    ASSERT_NE(manager_, nullptr);
    ASSERT_TRUE(PrepareVoice());
    manager_->HandleStartVoice();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "block", "rollback", "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
}

/**
 * @tc.name: StopFailureStillRestoresOriginalUser
 * @tc.desc: Restore the bound user's IME even when stop fails and another user becomes foreground.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, StopFailureStillRestoresOriginalUser, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    state_.stopResult = ErrorCode::ERROR_IME_NOT_STARTED;
    state_.foregroundUserId = PTT_UNIT_MISSING_USER_ID;
    InputTypeManager::GetInstance().Set(true);
    manager_->ApplyAction(PttAction::STOP_VOICE, PTT_UNIT_MISSING_USER_ID);
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "stop", "restore" }));
    EXPECT_EQ(state_.sessionUserIds, (std::vector<int32_t>(2, PTT_UNIT_TEST_USER_ID)));
    EXPECT_FALSE(state_.inputTypeStartedOnRestore);
    EXPECT_FALSE(InputTypeManager::GetInstance().IsStarted());
    ExpectContextCleared();
}

/**
 * @tc.name: RestoreFailureReturnsErrorAndStopClears
 * @tc.desc: Expose restoration errors while still clearing gesture state after stop.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, RestoreFailureReturnsErrorAndStopClears, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    state_.restoreResult = ErrorCode::ERROR_IME_NOT_STARTED;
    InputTypeManager::GetInstance().Set(true);
    EXPECT_EQ(manager_->RestoreCurrentIme(PTT_UNIT_TEST_USER_ID), ErrorCode::ERROR_IME_NOT_STARTED);
    EXPECT_FALSE(InputTypeManager::GetInstance().IsStarted());
    state_.calls.clear();
    manager_->HandleStopVoice();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "stop", "restore" }));
    ExpectContextCleared();
}

/**
 * @tc.name: MissingSessionAndInvalidStopAreSafe
 * @tc.desc: Missing users return the documented rollback/restore errors without external calls.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, MissingSessionAndInvalidStopAreSafe, TestSize.Level0)
{
    EXPECT_EQ(manager_->NotifyRollbackSpace(PTT_UNIT_MISSING_USER_ID), ErrorCode::ERROR_NULL_POINTER);
    EXPECT_EQ(
        manager_->RestoreCurrentIme(PTT_UNIT_MISSING_USER_ID), ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND);
    manager_->HandleStopVoice();
    ExpectContextCleared();
    manager_->gestureUserId_ = PTT_UNIT_MISSING_USER_ID;
    manager_->HandleStopVoice();
    ExpectContextCleared();
    EXPECT_TRUE(state_.calls.empty());
}

/**
 * @tc.name: CancellationGuardsAndFailure
 * @tc.desc: Skip invalid/missing users and tolerate cancellation IPC failure for an existing user.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, CancellationGuardsAndFailure, TestSize.Level0)
{
    manager_->NotifyGestureCancelled(PushToTalkManager::INVALID_USER_ID);
    manager_->NotifyGestureCancelled(PTT_UNIT_MISSING_USER_ID);
    EXPECT_TRUE(state_.calls.empty());
    ASSERT_TRUE(PrepareVoice());
    state_.cancelResult = ErrorCode::ERROR_IME_NOT_STARTED;
    state_.isForeground = false;
    manager_->HandleStartVoice();
    EXPECT_EQ(state_.calls, (std::vector<std::string> { "cancel" }));
    EXPECT_EQ(manager_->controller_.GetState(), PttState::SUPPRESSED);
    ExpectContextCleared();
}

/**
 * @tc.name: NoActionPreservesLiveGesture
 * @tc.desc: No action preserves active state; IDLE cleans up; unknown actions leave state intact.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, NoActionPreservesLiveGesture, TestSize.Level0)
{
    ASSERT_TRUE(PrepareVoice());
    manager_->ApplyAction(PttAction::NONE, PTT_UNIT_TEST_USER_ID);
    EXPECT_TRUE(manager_->IsGestureContextValid(PTT_UNIT_TEST_USER_ID));
    manager_->ApplyAction(static_cast<PttAction>(255), PTT_UNIT_TEST_USER_ID);
    EXPECT_EQ(manager_->controller_.GetState(), PttState::ACTIVE);
    EXPECT_TRUE(manager_->IsGestureContextValid(PTT_UNIT_TEST_USER_ID));
    manager_->controller_.Reset();
    manager_->ApplyAction(PttAction::NONE, PTT_UNIT_TEST_USER_ID);
    ExpectContextCleared();
    EXPECT_TRUE(state_.calls.empty());
}

/**
 * @tc.name: DialogPrerequisites
 * @tc.desc: Reject disabled configuration, missing/current third-party IMEs and incomplete endpoints.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, DialogPrerequisites, TestSize.Level0)
{
    auto &dialog = GetPttDialogTestState();
    const auto reads = dialog.reads;
    const auto writes = dialog.writes;
    const auto connections = dialog.connections;
    auto &config = ImeInfoInquirer::GetInstance().systemConfig_;
    config.enablePushToTalk = false;
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    EXPECT_EQ(state_.currentImeQueries, 0);
    config.enablePushToTalk = true;
    auto property = state_.currentIme;
    state_.currentIme.reset();
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    state_.currentIme = property;
    state_.isSystemIme = false;
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    state_.isSystemIme = true;
    config.pushToTalkDialogBundleName.clear();
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    config.pushToTalkDialogBundleName = "com.test.ptt.dialog";
    config.pushToTalkDialogAbilityName.clear();
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    EXPECT_EQ(state_.currentImeQueries, 4);
    const bool hasDialogSideEffect =
        dialog.reads != reads || dialog.writes != writes || dialog.connections != connections;
    EXPECT_FALSE(hasDialogSideEffect);
}

/**
 * @tc.name: DialogFailuresRetryAndConnectOnce
 * @tc.desc: Cover parameter, serialization and connection failures before connecting only once.
 * @tc.type: FUNC
 */
HWTEST_F(PushToTalkManagerUnitTest, DialogFailuresRetryAndConnectOnce, TestSize.Level0)
{
    auto &dialog = GetPttDialogTestState();
    ConfigureCJsonFailure(PTT_SINGLE_DIALOG_ACTION_COUNT);
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    ResetCJsonHooks();
    const size_t printFailureAllocation = CountCJsonParameterAllocations() + PTT_SINGLE_DIALOG_ACTION_COUNT;
    ASSERT_GT(printFailureAllocation, PTT_SINGLE_DIALOG_ACTION_COUNT);
    ConfigureCJsonFailure(printFailureAllocation);
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    ResetCJsonHooks();
    state_.failConnectionCreation = true;
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    state_.failConnectionCreation = false;
    EXPECT_EQ(dialog.writes, 0);
    EXPECT_EQ(dialog.connections, 0);
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    manager_->StartDialogAbility(PTT_UNIT_TEST_USER_ID);
    EXPECT_EQ(state_.dialogUserId, PTT_UNIT_TEST_USER_ID);
    EXPECT_EQ(dialog.reads, PTT_SINGLE_DIALOG_ACTION_COUNT);
    EXPECT_EQ(dialog.writes, PTT_SINGLE_DIALOG_ACTION_COUNT);
    EXPECT_EQ(dialog.connections, PTT_SINGLE_DIALOG_ACTION_COUNT);
    EXPECT_EQ(dialog.connectionUserId, -1);
    EXPECT_EQ(dialog.bundleName, "com.ohos.sceneboard");
    EXPECT_EQ(dialog.abilityName, "com.ohos.sceneboard.systemdialog");
    ASSERT_NE(dialog.connection, nullptr);
    auto connection = static_cast<PushToTalkConnection *>(dialog.connection.GetRefPtr());
    EXPECT_EQ(connection->bundleName_, "com.test.ptt.dialog");
    EXPECT_EQ(connection->abilityName_, "PttDialogAbility");
    std::unique_ptr<cJSON, decltype(&cJSON_Delete)> params(cJSON_Parse(connection->paramStr_.c_str()), cJSON_Delete);
    ASSERT_NE(params, nullptr);
    auto type = cJSON_GetObjectItemCaseSensitive(params.get(), "ability.want.params.uiExtensionType");
    ASSERT_TRUE(cJSON_IsString(type));
    EXPECT_STREQ(type->valuestring, "sysDialog/common");
}
} // namespace MiscServices
} // namespace OHOS
