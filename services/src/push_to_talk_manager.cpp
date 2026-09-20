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

#include "push_to_talk_manager.h"

#include <utility>

#include "ability_manager_client.h"
#include "ime_info_inquirer.h"
#include "input_type_manager.h"
#include "os_account_adapter.h"
#include "os_account_manager.h"
#include "ptt_settings_manager.h"
#include "push_to_talk_connection.h"
#include "serializable.h"
#include "settings_data_utils.h"
#include "user_session_manager.h"

namespace OHOS {
namespace MiscServices {
PushToTalkManager::PushToTalkManager(
    ServiceHandlerProvider serviceHandlerProvider, StartInputTypeHandler startInputTypeHandler)
    : serviceHandlerProvider_(std::move(serviceHandlerProvider)),
      startInputTypeHandler_(std::move(startInputTypeHandler))
{
}

std::shared_ptr<AppExecFwk::EventHandler> PushToTalkManager::GetServiceHandler() const
{
    return serviceHandlerProvider_ == nullptr ? nullptr : serviceHandlerProvider_();
}

void PushToTalkManager::SetKeyEventMonitorReady(bool isReady)
{
    isKeyEventMonitorReady_.store(isReady);
}

bool PushToTalkManager::IsReady() const
{
    return GetServiceHandler() != nullptr && isKeyEventMonitorReady_.load();
}

bool PushToTalkManager::IsGestureAvailable(int32_t userId, const sptr<IRemoteObject> &channel)
{
    FocusedRealImeClientSnapshot snapshot;
    if (!GetEligibleClient(userId, snapshot)) {
        return false;
    }
    bool isAvailable = snapshot.channel == channel;
    IMSA_HILOGD("PTT: gesture availability query finished, userId=%{public}d, result=%{public}d.", userId, isAvailable);
    return isAvailable;
}

int32_t PushToTalkManager::NotifyRollbackSpace(int32_t userId)
{
    IMSA_HILOGI("PTT: request rollback space, userId=%{public}d.", userId);
    auto session = UserSessionManager::GetInstance().GetUserSession(userId);
    if (session == nullptr) {
        IMSA_HILOGE("PTT: rollback space failed, user session is nullptr, userId=%{public}d.", userId);
        return ErrorCode::ERROR_NULL_POINTER;
    }
    int32_t ret = session->NotifyRollbackSpace();
    IMSA_HILOGI("PTT: rollback space finished, userId=%{public}d, ret=%{public}d.", userId, ret);
    return ret;
}

void PushToTalkManager::HandleKeyEvent(const KeyboardEventInfo &eventInfo)
{
    auto handler = GetServiceHandler();
    if (handler == nullptr) {
        IMSA_HILOGE("PTT: discard key event because service handler is nullptr, controllerState=%{public}s.",
            PttController::StateToString(controller_.GetState()));
        return;
    }

    std::weak_ptr<PushToTalkManager> weakManager = shared_from_this();
    auto task = [weakManager, eventInfo]() {
        auto manager = weakManager.lock();
        if (manager == nullptr) {
            IMSA_HILOGW("PTT: discard key event because manager is nullptr.");
            return;
        }
        PttAction action = manager->controller_.HandleKeyEvent(eventInfo);
        IMSA_HILOGD("PTT: key event resolved, action=%{public}s, controllerState=%{public}s.",
            PttController::ActionToString(action), PttController::StateToString(manager->controller_.GetState()));
        manager->ApplyAction(action, INVALID_USER_ID);
    };

    auto ret = handler->PostTask(task, std::string(KEY_EVENT_TASK), 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    if (!ret) {
        IMSA_HILOGE("PTT: post key event task failed, controllerState=%{public}s.",
            PttController::StateToString(controller_.GetState()));
    } else {
        IMSA_HILOGD("PTT: key event task posted, taskName=%{public}s.", KEY_EVENT_TASK);
    }
}

void PushToTalkManager::ApplyAction(PttAction action, int32_t eventUserId)
{
    IMSA_HILOGD("PTT: apply action, action=%{public}s, controllerState=%{public}s, "
                "eventUserId=%{public}d, gestureUserId=%{public}d.",
        PttController::ActionToString(action), PttController::StateToString(controller_.GetState()), eventUserId,
        gestureUserId_);
    switch (action) {
        case PttAction::START_TIMER:
            HandleStartTimer(eventUserId);
            break;
        case PttAction::CANCEL_TIMER:
            HandleCancelTimer();
            break;
        case PttAction::START_VOICE:
            HandleStartVoice();
            break;
        case PttAction::STOP_VOICE:
            HandleStopVoice();
            break;
        case PttAction::NONE:
            HandleNoAction();
            break;
        default:
            IMSA_HILOGW("PTT: unknown action=%{public}d.", static_cast<int32_t>(action));
            break;
    }
}

void PushToTalkManager::HandleStartTimer(int32_t eventUserId)
{
    if (eventUserId == INVALID_USER_ID) {
        int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(eventUserId);
        if (ret != ERR_OK || eventUserId == INVALID_USER_ID) {
            PttState failureState = controller_.SuppressUntilSpaceUp();
            ClearGestureContext();
            IMSA_HILOGE("PTT: cannot bind gesture user, ret=%{public}d, userId=%{public}d, "
                        "controllerState=%{public}s.",
                ret, eventUserId, PttController::StateToString(failureState));
            return;
        }
        IMSA_HILOGI("PTT: resolved gesture user in queued start action, userId=%{public}d.", eventUserId);
    }
    if (!BindGestureContext(eventUserId)) {
        PttState failureState = controller_.SuppressUntilSpaceUp();
        NotifyGestureCancelled(eventUserId);
        ClearGestureContext();
        IMSA_HILOGI("PTT: gesture rejected because setting is disabled or no input client is focused, "
                    "userId=%{public}d, controllerState=%{public}s.",
            eventUserId, PttController::StateToString(failureState));
        return;
    }
    gestureUserId_ = eventUserId;
    IMSA_HILOGI("PTT: bound user to gesture, userId=%{public}d.", gestureUserId_);
    ScheduleLongPressTimer();
}

void PushToTalkManager::ScheduleLongPressTimer()
{
    auto handler = GetServiceHandler();
    if (handler == nullptr) {
        HandleTimerStartFailure("service handler is nullptr");
        return;
    }
    uint32_t longPressDelayMs = ImeInfoInquirer::GetInstance().GetPushToTalkLongPressMs();
    if (longPressDelayMs == 0) {
        HandleTimerStartFailure("long press delay config is invalid");
        return;
    }
    handler->RemoveTask(std::string(TIMEOUT_TASK));
    int32_t gestureUserId = gestureUserId_;
    std::weak_ptr<PushToTalkManager> weakManager = shared_from_this();
    auto timeoutTask = [weakManager, gestureUserId]() {
        auto manager = weakManager.lock();
        if (manager == nullptr) {
            IMSA_HILOGW("PTT: discard long press timer because manager is nullptr.");
            return;
        }
        if (gestureUserId != manager->gestureUserId_) {
            IMSA_HILOGW("PTT: ignore stale long press timer, timerUserId=%{public}d, "
                        "gestureUserId=%{public}d.",
                gestureUserId, manager->gestureUserId_);
            return;
        }
        IMSA_HILOGI("PTT: long press timer fired, controllerState=%{public}s, userId=%{public}d.",
            PttController::StateToString(manager->controller_.GetState()), gestureUserId);
        PttAction timeoutAction = manager->controller_.HandleTimeout();
        manager->ApplyAction(timeoutAction, gestureUserId);
    };
    auto ret = handler->PostTask(timeoutTask, std::string(TIMEOUT_TASK), longPressDelayMs);
    if (!ret) {
        PttState failureState = controller_.SuppressUntilSpaceUp();
        IMSA_HILOGE("PTT: post long press timer failed, delay=%{public}u"
                    ", userId=%{public}d, controllerState=%{public}s.",
            longPressDelayMs, gestureUserId_, PttController::StateToString(failureState));
        NotifyGestureCancelled(gestureUserId_);
        ClearGestureContext();
    } else {
        IMSA_HILOGI("PTT: long press timer started, delay=%{public}u"
                    ", taskName=%{public}s, userId=%{public}d.",
            longPressDelayMs, TIMEOUT_TASK, gestureUserId_);
    }
}

void PushToTalkManager::HandleTimerStartFailure(const char *reason)
{
    PttState failureState = controller_.SuppressUntilSpaceUp();
    IMSA_HILOGE("PTT: cannot start timer because %{public}s, userId=%{public}d, "
                "controllerState=%{public}s.",
        reason, gestureUserId_, PttController::StateToString(failureState));
    NotifyGestureCancelled(gestureUserId_);
    ClearGestureContext();
}

void PushToTalkManager::HandleCancelTimer()
{
    auto handler = GetServiceHandler();
    if (handler != nullptr) {
        handler->RemoveTask(std::string(TIMEOUT_TASK));
        IMSA_HILOGI("PTT: long press timer cancelled, taskName=%{public}s, userId=%{public}d.", TIMEOUT_TASK,
            gestureUserId_);
    } else {
        IMSA_HILOGW("PTT: cannot cancel timer because service handler is nullptr.");
    }
    ClearGestureContext();
}

void PushToTalkManager::HandleStartVoice()
{
    int32_t userId = gestureUserId_;
    if (userId == INVALID_USER_ID) {
        PttState failureState = controller_.SuppressUntilSpaceUp();
        IMSA_HILOGE("PTT: start voice rejected because gesture user is invalid, "
                    "controllerState=%{public}s.",
            PttController::StateToString(failureState));
        ClearGestureContext();
        return;
    }
    if (!OsAccountAdapter::IsOsAccountForeground(userId)) {
        PttState failureState = controller_.SuppressUntilSpaceUp();
        IMSA_HILOGW("PTT: start voice cancelled because gesture user is no longer foreground, "
                    "userId=%{public}d, controllerState=%{public}s.",
            userId, PttController::StateToString(failureState));
        NotifyGestureCancelled(userId);
        ClearGestureContext();
        return;
    }
    if (!IsGestureContextValid(userId)) {
        PttState failureState = controller_.SuppressUntilSpaceUp();
        IMSA_HILOGI("PTT: start voice rejected because setting is disabled or the input client lost focus, "
                    "userId=%{public}d, controllerState=%{public}s.",
            userId, PttController::StateToString(failureState));
        NotifyGestureCancelled(userId);
        ClearGestureContext();
        return;
    }
    if (!EnableSpaceKeyEventBlock(userId)) {
        return;
    }
    int32_t rollbackRet = NotifyRollbackSpace(userId);
    if (rollbackRet != ErrorCode::NO_ERROR) {
        IMSA_HILOGW("PTT: rollback space failed before starting voice, ret=%{public}d.", rollbackRet);
    }
    int32_t ret = startInputTypeHandler_ == nullptr ? ErrorCode::ERROR_NULL_POINTER : startInputTypeHandler_(userId);
    if (ret != ErrorCode::NO_ERROR) {
        PttState failureState = controller_.SuppressUntilSpaceUp();
        IMSA_HILOGE("PTT: start voice failed, userId=%{public}d, ret=%{public}d, "
                    "controllerState=%{public}s.",
            userId, ret, PttController::StateToString(failureState));
        NotifyGestureCancelled(userId);
        ClearGestureContext();
    } else {
        IMSA_HILOGI("PTT: start voice succeeded, userId=%{public}d.", userId);
    }
}

bool PushToTalkManager::EnableSpaceKeyEventBlock(int32_t userId)
{
    int32_t ret = ErrorCode::ERROR_NULL_POINTER;
    sptr<IRemoteObject> clientObject;
    {
        std::lock_guard<std::mutex> lock(gestureClientSnapshotMutex_);
        clientObject = gestureClientSnapshot_.client;
    }
    sptr<IInputClient> client = iface_cast<IInputClient>(clientObject);
    if (client != nullptr) {
        ret = client->StartPttSpaceKeyEventBlock();
    }
    if (ret == ErrorCode::NO_ERROR) {
        return true;
    }
    PttState failureState = controller_.SuppressUntilSpaceUp();
    IMSA_HILOGE("PTT: start voice rejected because repeated space down cannot be blocked, "
                "userId=%{public}d, ret=%{public}d, controllerState=%{public}s.",
        userId, ret, PttController::StateToString(failureState));
    NotifyGestureCancelled(userId);
    ClearGestureContext();
    return false;
}

void PushToTalkManager::HandleStopVoice()
{
    int32_t userId = gestureUserId_;
    if (userId == INVALID_USER_ID) {
        IMSA_HILOGE("PTT: stop voice rejected because gesture user is invalid.");
        ClearGestureContext();
        return;
    }
    auto session = UserSessionManager::GetInstance().GetUserSession(userId);
    if (session == nullptr) {
        IMSA_HILOGE("PTT: stop voice failed, user session is nullptr, userId=%{public}d.", userId);
    } else {
        int32_t ret = session->SendPttStopPrivateCommand();
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("PTT: stop command failed; continue restoring current IME as fallback, "
                        "userId=%{public}d, ret=%{public}d.",
                userId, ret);
        } else {
            IMSA_HILOGI("PTT: stop voice succeeded, userId=%{public}d.", userId);
        }
    }
    int32_t restoreRet = RestoreCurrentIme(userId);
    if (restoreRet != ErrorCode::NO_ERROR) {
        IMSA_HILOGE(
            "PTT: restore current IME after stop failed, userId=%{public}d, ret=%{public}d.", userId, restoreRet);
    }
    ClearGestureContext();
}

int32_t PushToTalkManager::RestoreCurrentIme(int32_t userId)
{
    auto session = UserSessionManager::GetInstance().GetUserSession(userId);
    if (session == nullptr) {
        IMSA_HILOGE("PTT: restore current IME failed, user session is nullptr, userId=%{public}d.", userId);
        return ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND;
    }
    InputTypeManager::GetInstance().Set(false);
    int32_t ret = session->StartCurrentIme();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("PTT: restore current IME failed, userId=%{public}d, ret=%{public}d.", userId, ret);
        return ret;
    }
    IMSA_HILOGI("PTT: restore current IME succeeded, userId=%{public}d.", userId);
    return ErrorCode::NO_ERROR;
}

void PushToTalkManager::HandleNoAction()
{
    IMSA_HILOGD("PTT: no action required, controllerState=%{public}s.",
        PttController::StateToString(controller_.GetState()));
    if (controller_.GetState() == PttState::IDLE) {
        ClearGestureContext();
    }
}

bool PushToTalkManager::BindGestureContext(int32_t userId)
{
    {
        std::lock_guard<std::mutex> lock(gestureClientSnapshotMutex_);
        gestureClientSnapshot_ = {};
    }
    FocusedRealImeClientSnapshot snapshot;
    if (!GetEligibleClient(userId, snapshot)) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(gestureClientSnapshotMutex_);
        gestureClientSnapshot_ = std::move(snapshot);
    }
    return true;
}

bool PushToTalkManager::IsGestureContextValid(int32_t userId)
{
    FocusedRealImeClientSnapshot gestureSnapshot;
    {
        std::lock_guard<std::mutex> lock(gestureClientSnapshotMutex_);
        gestureSnapshot = gestureClientSnapshot_;
    }
    if (userId != gestureUserId_ || gestureSnapshot.client == nullptr) {
        return false;
    }
    FocusedRealImeClientSnapshot currentSnapshot;
    return GetEligibleClient(userId, currentSnapshot) && IsSameInputClient(gestureSnapshot, currentSnapshot);
}

bool PushToTalkManager::GetEligibleClient(int32_t userId, FocusedRealImeClientSnapshot &snapshot)
{
    snapshot = {};
    auto session = UserSessionManager::GetInstance().GetUserSession(userId);
    if (session == nullptr) {
        IMSA_HILOGW("PTT: user session is nullptr, userId=%{public}d.", userId);
        return false;
    }
    if (!session->GetFocusedRealImeClient(snapshot)) {
        IMSA_HILOGI("PTT: no input client is focused, userId=%{public}d.", userId);
        return false;
    }
    if (!PttSettingsManager::IsEnabled(userId)) {
        IMSA_HILOGI("PTT: setting is disabled, userId=%{public}d.", userId);
        return false;
    }
    return true;
}

void PushToTalkManager::NotifyGestureCancelled(int32_t userId)
{
    if (userId == INVALID_USER_ID) {
        return;
    }
    auto session = UserSessionManager::GetInstance().GetUserSession(userId);
    if (session == nullptr) {
        IMSA_HILOGW("PTT: cannot cancel IME key tracking because user session is nullptr, userId=%{public}d.", userId);
        return;
    }
    int32_t ret = session->NotifyPttGestureCancelled();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGW("PTT: cancel IME key tracking failed, userId=%{public}d, ret=%{public}d.", userId, ret);
    }
}

void PushToTalkManager::ClearGestureContext()
{
    gestureUserId_ = INVALID_USER_ID;
    std::lock_guard<std::mutex> lock(gestureClientSnapshotMutex_);
    gestureClientSnapshot_ = {};
}

bool PushToTalkManager::IsSameInputClient(
    const FocusedRealImeClientSnapshot &left, const FocusedRealImeClientSnapshot &right)
{
    return left.client != nullptr && left.client == right.client && left.channel == right.channel &&
        left.clientGroupId == right.clientGroupId && left.editorWindowId == right.editorWindowId &&
        left.editorDisplayId == right.editorDisplayId;
}

sptr<AAFwk::IAbilityConnection> CreatePushToTalkDialogConnection(
    const std::string &dialogBundleName, const std::string &dialogAbilityName, const std::string &paramStr)
{
    sptr<AAFwk::IAbilityConnection> connection {
        new (std::nothrow) PushToTalkConnection(dialogBundleName, dialogAbilityName, paramStr)
    };
    if (connection == nullptr) {
        IMSA_HILOGE("create push-to-talk dialog connection failed");
        return nullptr;
    }
    return connection;
}

namespace {
class DialogParams final : public Serializable {
public:
    bool Marshal(cJSON *node) const override
    {
        const std::string uiExtensionType = "sysDialog/common";
        return SetValue(node, "ability.want.params.uiExtensionType", uiExtensionType);
    }
};

bool ConnectPushToTalkDialog(const std::string &dialogBundleName, const std::string &dialogAbilityName)
{
    // connect serviceExternsionAbility
    DialogParams params;
    std::string paramStr;
    if (!params.Marshall(paramStr)) {
        IMSA_HILOGE("serialize push-to-talk dialog parameters failed");
        return false;
    }
    sptr<AAFwk::IAbilityConnection> connection =
        CreatePushToTalkDialogConnection(dialogBundleName, dialogAbilityName, paramStr);
    if (connection == nullptr) {
        IMSA_HILOGE("create push-to-talk dialog connection failed");
        return false;
    }
    AAFwk::Want want;
    want.SetElementName("com.ohos.sceneboard", "com.ohos.sceneboard.systemdialog");
    AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, connection, -1);
    return true;
}
} // namespace

void PushToTalkManager::StartDialogAbility(int32_t userId)
{
    // systemConfig to control dialog display
    auto &inquirer = ImeInfoInquirer::GetInstance();
    auto flag = inquirer.IsEnablePushToTalkDialog();
    if (!flag) {
        IMSA_HILOGI("push-to-talk dialog is disabled by config, skip");
        return;
    }

    // check whether its default input method
    auto prop = inquirer.GetCurrentInputMethod(userId);
    if (prop == nullptr) {
        IMSA_HILOGE("prop is nullptr!");
        return;
    }
    if (!inquirer.IsSysIme(prop->name)) {
        return;
    }

    std::string dialogBundleName = inquirer.GetPushToTalkDialogBundleName();
    std::string dialogAbilityName = inquirer.GetPushToTalkDialogAbilityName();
    if (dialogBundleName.empty() || dialogAbilityName.empty()) {
        IMSA_HILOGW("push-to-talk dialog endpoint is not configured, skip");
        return;
    }

    // Atomically reserve the one-time dialog pop before connecting so concurrent callers cannot duplicate it.
    static std::atomic_bool isDialogPopped { SettingsDataUtils::GetInstance().GetPushToTalkDialogPopped() };
    bool expected = false;
    if (!isDialogPopped.compare_exchange_strong(expected, true)) {
        IMSA_HILOGI("Dialog popped already, not pop again");
        return;
    }
    if (!ConnectPushToTalkDialog(dialogBundleName, dialogAbilityName)) {
        isDialogPopped.store(false);
        return;
    }
    SettingsDataUtils::GetInstance().SetPushToTalkDialogPopped();
}

} // namespace MiscServices
} // namespace OHOS
