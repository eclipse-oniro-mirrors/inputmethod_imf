/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "unordered_map"
#include "variant"
#include "peruser_session.h"

#include <cinttypes>
#include <algorithm>
#include "ability_manager_client.h"
#include "full_ime_info_manager.h"
#include "identity_checker_impl.h"
#include "im_common_event_manager.h"
#include "ime_enabled_info_manager.h"
#include "ime_event_listener_manager.h"
#include "ime_info_inquirer.h"
#include "input_control_channel_service_impl.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "mem_mgr_client.h"
#include "numkey_apps_manager.h"
#include "on_demand_start_stop_sa.h"
#include "os_account_adapter.h"
#include "scene_board_judgement.h"
#include "system_ability_definition.h"
#include "system_param_adapter.h"
#include "wms_connection_observer.h"
#include "dm_common.h"
#include "display_manager.h"
#include "parameters.h"
#ifdef IMF_SCREENLOCK_MGR_ENABLE
#include "screenlock_manager.h"
#endif
#include "window_adapter.h"
#include "input_method_tools.h"
#include "ime_state_manager_factory.h"
#include "inputmethod_trace.h"
#include "notify_service_impl.h"
#include "display_adapter.h"
#include "imf_hook_manager.h"
#include "res_sched_client.h"

namespace OHOS {
namespace MiscServices {
using namespace std::chrono;
using namespace MessageID;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Rosen;
constexpr uint32_t STOP_IME_TIME = 600;
constexpr const char *STRICT_MODE = "strictMode";
constexpr const char *ISOLATED_SANDBOX = "isolatedSandbox";
constexpr const char *SUB_NAME = "subName";
constexpr uint32_t CHECK_IME_RUNNING_RETRY_INTERVAL = 60;
constexpr uint32_t CHECK_IME_RUNNING_RETRY_TIMES = 10;
constexpr uint32_t MAX_RESTART_NUM = 3;
constexpr int32_t IME_RESET_TIME_OUT = 3;
constexpr int32_t MAX_RESTART_TASKS = 2;
constexpr uint32_t MAX_ATTACH_COUNT = 100000;
constexpr const char *UNDEFINED = "undefined";
constexpr int32_t WAIT_ATTACH_FINISH_DELAY = 50;
constexpr int32_t WAIT_ATTACH_FINISH_MAX_TIMES = 20;
constexpr uint32_t MAX_SCB_START_COUNT = 2;
constexpr int32_t PROXY_REGISTERATION_TIME_INTERVAL = 1; // 1s
constexpr uint32_t MAX_REGISTRATIONS_NUM = 3;
PerUserSession::PerUserSession(int userId) : userId_(userId) { }

PerUserSession::PerUserSession(int32_t userId, const std::shared_ptr<AppExecFwk::EventHandler> &eventHandler)
    : userId_(userId), eventHandler_(eventHandler)
{
    // if bms not start, AppMgrClient::GetProcessRunningInfosByUserId will blocked
    if (IsSaReady(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID)) {
        auto bundleNames = ImeInfoInquirer::GetInstance().GetRunningIme(userId_);
        if (!bundleNames.empty()) {
            runningIme_ = bundleNames[0]; // one user only has one ime at present
        }
    }
}

PerUserSession::~PerUserSession() { }

int PerUserSession::AddClientInfo(sptr<IRemoteObject> inputClient, const InputClientInfo &clientInfo)
{
    IMSA_HILOGD("PerUserSession start.");
    uint64_t clientGroupId = clientInfo.clientGroupId;
    auto clientGroup = GetClientGroupByGroupId(clientGroupId);
    if (clientGroup != nullptr) {
        return clientGroup->AddClientInfo(inputClient, clientInfo);
    }
    clientGroup = std::make_shared<ClientGroup>(
        clientGroupId, [this](const sptr<IInputClient> &remote) { this->OnClientDied(remote); });
    auto ret = clientGroup->AddClientInfo(inputClient, clientInfo);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to AddClientInfo: %{public}d", ret);
        return ret;
    }
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    clientGroupMap_.insert(std::make_pair(clientGroupId, clientGroup));
    IMSA_HILOGI("add client group: %{public}" PRIu64 " end.", clientGroupId);
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::HideKeyboard(
    const sptr<IInputClient> &currentClient, const std::shared_ptr<ClientGroup> &clientGroup)
{
    IMSA_HILOGD("PerUserSession::HideKeyboard start.");
    if (currentClient == nullptr || clientGroup == nullptr) {
        IMSA_HILOGE("current client is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto clientInfo = clientGroup->GetClientInfo(currentClient->AsObject());
    if (clientInfo == nullptr) {
        IMSA_HILOGE("client info is nullptr!");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    auto data = GetImeData(clientInfo->bindImeData);
    if (data == nullptr) {
        IMSA_HILOGE("%{public}d ime is not exist!", clientInfo->pid);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::NORMAL, [&data] { return data->core->HideKeyboard(); });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to hide keyboard, ret: %{public}d!", ret);
        return ErrorCode::ERROR_KBD_HIDE_FAILED;
    }
    bool isShowKeyboard = false;
    clientGroup->UpdateClientInfo(currentClient->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, isShowKeyboard } });
    if (data->IsRealIme()) {
        RestoreCurrentImeSubType();
    }
    ImeEventListenerManager::GetInstance().NotifyInputStop(userId_, clientGroup->GetDisplayGroupId());
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::ShowKeyboard(const sptr<IInputClient> &currentClient,
    const std::shared_ptr<ClientGroup> &clientGroup, int32_t requestKeyboardReason)
{
    if (currentClient == nullptr || clientGroup == nullptr) {
        IMSA_HILOGE("client is nullptr");
        return ErrorCode::ERROR_IMSA_NULLPTR;
    }
    auto clientInfo = clientGroup->GetClientInfo(currentClient->AsObject());
    if (clientInfo == nullptr) {
        IMSA_HILOGE("client info is nullptr!");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    auto data = GetImeData(clientInfo->bindImeData);
    if (data == nullptr) {
        IMSA_HILOGE("%{public}d ime is not exist!", clientInfo->pid);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::REQUEST_SHOW,
        [&data, requestKeyboardReason] { return data->core->ShowKeyboard(requestKeyboardReason); });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to show keyboard, ret: %{public}d!", ret);
        return ErrorCode::ERROR_KBD_SHOW_FAILED;
    }
    bool isShowKeyboard = true;
    clientGroup->UpdateClientInfo(currentClient->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, isShowKeyboard } });
    ImeEventListenerManager::GetInstance().NotifyInputStart(
        userId_, clientInfo->config.windowId, clientInfo->clientGroupId, requestKeyboardReason);
    return ErrorCode::NO_ERROR;
}

/** Handle the situation a remote input client died.
 * It's called when a remote input client died
 * @param the remote object handler of the input client died.
 */
void PerUserSession::OnClientDied(sptr<IInputClient> remote)
{
    if (remote == nullptr) {
        return;
    }
    auto clientGroup = GetClientGroup(remote->AsObject());
    if (clientGroup == nullptr) {
        return;
    }
    if (clientGroup->IsNotifyInputStop(remote)) {
        ImeEventListenerManager::GetInstance().NotifyInputStop(userId_, clientGroup->GetDisplayGroupId());
    }
    auto clientInfo = clientGroup->GetClientInfo(remote->AsObject());
    IMSA_HILOGI("userId: %{public}d.", userId_);
    if (IsSameClient(remote, clientGroup->GetCurrentClient())) {
        if (clientInfo != nullptr) {
            auto imeData = GetImeData(clientInfo->bindImeData);
            StopImeInput(imeData, clientInfo, 0);
        }
        clientGroup->SetCurrentClient(nullptr);
    }
    if (IsSameClient(remote, clientGroup->GetInactiveClient())) {
        if (clientInfo != nullptr) {
            auto imeData = GetImeData(clientInfo->bindImeData);
            StopImeInput(imeData, clientInfo, 0);
        }
        clientGroup->SetInactiveClient(nullptr);
    }
    clientGroup->RemoveClientInfo(remote->AsObject());
}

/** Handle the situation that an ime died
 * It's called when an ime died
 * @param the remote object handler of the ime who died.
 */
void PerUserSession::OnImeDied(const sptr<IInputMethodCore> &remote, ImeType type, pid_t pid)
{
    if (remote == nullptr) {
        return;
    }
    IMSA_HILOGI("type: %{public}d.", type);
    auto imeData = GetImeData(pid, type);
    if (imeData != nullptr && imeData->imeStatus == ImeStatus::EXITING) {
        RemoveImeData(pid);
        InputTypeManager::GetInstance().Set(false);
        NotifyImeStopFinished();
        IMSA_HILOGI("%{public}d not current imeData.", type);
        return;
    }
    RemoveImeData(pid);
    if (!OsAccountAdapter::IsOsAccountForeground(userId_)) {
        IMSA_HILOGW("userId:%{public}d in background, no need to restart ime.", userId_);
        return;
    }
    auto [clientGroup, clientInfo] = GetClientBoundImeByImePid(pid);
    if (clientGroup != nullptr && clientInfo != nullptr) {
        auto currentClient = clientGroup->GetCurrentClient();
        if (IsSameClient(currentClient, clientInfo->client)) {
            ImeEventListenerManager::GetInstance().NotifyInputStop(userId_, clientGroup->GetDisplayGroupId());
            StopClientInput(clientInfo);
            if (type == ImeType::IME) {
                StartImeInImeDied();
            }
            return;
        }
    }
    auto currentImeInfo = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
    if (currentImeInfo == nullptr) {
        IMSA_HILOGE("currentImeInfo is nullptr!");
        return;
    }
    auto defaultImeInfo = ImeInfoInquirer::GetInstance().GetDefaultImeCfgProp();
    if (defaultImeInfo == nullptr) {
        IMSA_HILOGE("defaultImeInfo is nullptr!");
        return;
    }
    if (type == ImeType::IME && currentImeInfo->bundleName == defaultImeInfo->name) {
        if (!SystemParamAdapter::GetInstance().GetBoolParam(SystemParamAdapter::MEMORY_WATERMARK_KEY)) {
            StartImeInImeDied();
        } else {
            isBlockStartedByLowMem_.store(true);
        }
    }
}

int32_t PerUserSession::OnHideCurrentInput(uint64_t displayGroupId)
{
    auto clientGroup = GetClientGroupByGroupId(displayGroupId);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("client group not found");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    sptr<IInputClient> client = clientGroup->GetCurrentClient();
    if (client == nullptr) {
        IMSA_HILOGE("current client is nullptr!");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    return HideKeyboard(client, clientGroup);
}

int32_t PerUserSession::OnShowCurrentInput(uint64_t displayGroupId)
{
    IMSA_HILOGD("PerUserSession::OnShowCurrentInput start.");
    auto clientGroup = GetClientGroupByGroupId(displayGroupId);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("client group not found");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    if (clientGroup == nullptr) {
        IMSA_HILOGE("client group not found");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    sptr<IInputClient> client = clientGroup->GetCurrentClient();
    if (client == nullptr) {
        IMSA_HILOGE("current client is nullptr!");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    return ShowKeyboard(client, clientGroup);
}

int32_t PerUserSession::OnShowCurrentInputInTargetDisplay(uint64_t displayId)
{
    IMSA_HILOGD("start.");
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo == nullptr) {
        IMSA_HILOGE("clientInfo is nullptr");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    if (clientInfo->config.inputAttribute.callingDisplayId != displayId) {
        IMSA_HILOGE("keyboard in displayId:%{public}" PRIu64 ", not in displayId:%{public}" PRIu64 ".",
            clientInfo->config.inputAttribute.callingDisplayId, displayId);
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    return ShowKeyboard(clientInfo->client, clientGroup);
}

int32_t PerUserSession::OnHideCurrentInputInTargetDisplay(uint64_t displayId)
{
    IMSA_HILOGD("start.");
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo == nullptr) {
        IMSA_HILOGE("clientInfo is nullptr");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    if (clientInfo->config.inputAttribute.callingDisplayId != displayId) {
        IMSA_HILOGE("keyboard in displayId:%{public}" PRIu64 ", not in displayId:%{public}" PRIu64 ".",
            clientInfo->config.inputAttribute.callingDisplayId, displayId);
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    return HideKeyboard(clientInfo->client, clientGroup);
}

int32_t PerUserSession::OnHideInput(sptr<IInputClient> client)
{
    IMSA_HILOGD("PerUserSession::OnHideInput start.");
    if (client == nullptr) {
        IMSA_HILOGE("client is nullptr");
        return ErrorCode::ERROR_CLIENT_NOT_FOCUSED;
    }
    auto clientGroup = GetClientGroup(client->AsObject());
    if (clientGroup == nullptr) {
        IMSA_HILOGE("client group not found");
        return ErrorCode::ERROR_CLIENT_NOT_FOCUSED;
    }
    if (!IsSameClient(client, clientGroup->GetCurrentClient())) {
        IMSA_HILOGE("client is not current client!");
        return ErrorCode::ERROR_CLIENT_NOT_FOCUSED;
    }
    return HideKeyboard(client, clientGroup);
}

int32_t PerUserSession::OnShowInput(sptr<IInputClient> client, int32_t requestKeyboardReason)
{
    IMSA_HILOGD("PerUserSession::OnShowInput start.");
    if (client == nullptr) {
        IMSA_HILOGE("client is nullptr");
        return ErrorCode::ERROR_CLIENT_NOT_FOCUSED;
    }
    auto clientGroup = GetClientGroup(client->AsObject());
    if (clientGroup == nullptr) {
        IMSA_HILOGE("client group not found");
        return ErrorCode::ERROR_CLIENT_NOT_FOCUSED;
    }
    if (!IsSameClient(client, clientGroup->GetCurrentClient())) {
        IMSA_HILOGE("client is not current client!");
        return ErrorCode::ERROR_CLIENT_NOT_FOCUSED;
    }
    return ShowKeyboard(client, clientGroup, requestKeyboardReason);
}

void PerUserSession::OnHideSoftKeyBoardSelf()
{
    IMSA_HILOGD("PerUserSession::OnHideSoftKeyBoardSel start.");
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientGroup == nullptr || clientInfo->client == nullptr) {
        IMSA_HILOGE("current client is nullptr!");
        return;
    }
    clientGroup->UpdateClientInfo(clientInfo->client->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, false } });
    RestoreCurrentImeSubType();
}

int32_t PerUserSession::OnRequestHideInput(uint64_t displayId, const std::string &callerBundleName)
{
    auto displayGroupId = WindowAdapter::GetInstance().GetDisplayGroupId(displayId);
    IMSA_HILOGD("start, displayId: %{public}" PRIu64 ", groupId: %{public}" PRIu64 ".", displayId, displayGroupId);
    if (RequestHideRealIme(displayGroupId)) {
        IMSA_HILOGI("hide real ime");
    } else if (RequestHideProxyIme(displayId)) {
        IMSA_HILOGI("hide proxy ime");
    }
    UpdateClientAfterRequestHide(displayGroupId, callerBundleName);

    ImeEventListenerManager::GetInstance().NotifyInputStop(userId_, displayGroupId);
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::RequestHideRealIme(uint64_t displayGroupId)
{
    auto realImeData = GetRealImeData(true);
    if (realImeData == nullptr) {
        IMSA_HILOGD("real ime data is nullptr");
        return false;
    }
    if (!NeedHideRealIme(displayGroupId)) {
        IMSA_HILOGD("no need");
        return false;
    }
    IMSA_HILOGI("need hide: %{public}" PRIu64 ".", displayGroupId);
    int32_t ret = RequestIme(
        realImeData, RequestType::REQUEST_HIDE, [&realImeData] { return realImeData->core->HideKeyboard(); });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to hide keyboard, ret: %{public}d!", ret);
    }
    RestoreCurrentImeSubType();
    return ret == ErrorCode::NO_ERROR;
}

bool PerUserSession::RequestHideProxyIme(uint64_t displayId)
{
    auto proxyImeData = GetProxyImeData(displayId);
    if (proxyImeData == nullptr) {
        auto clientGroup = GetClientGroup(displayId);
        if (clientGroup == nullptr) {
            return false;
        }
        auto clientInfo = clientGroup->GetCurrentClientInfo();
        if (clientInfo == nullptr) {
            return false;
        }
        if (clientInfo->bindImeData == nullptr) {
            return false;
        }
        proxyImeData = GetImeData(clientInfo->bindImeData);
        if (proxyImeData == nullptr) {
            return false;
        }
        IMSA_HILOGD("get proxy ime data by clientInfo, displayId: %{public}" PRIu64 ".", displayId);
    }
    if (!IsEnable(proxyImeData, displayId)) {
        IMSA_HILOGD("not enable");
        return false;
    }
    int32_t ret = RequestIme(
        proxyImeData, RequestType::REQUEST_HIDE, [&proxyImeData] { return proxyImeData->core->HideKeyboard(); });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to hide keyboard, ret: %{public}d!", ret);
    }
    return ret == ErrorCode::NO_ERROR;
}

int32_t PerUserSession::UpdateClientAfterRequestHide(uint64_t displayGroupId, const std::string &callerBundleName)
{
    auto clientGroup = GetClientGroupByGroupId(displayGroupId);
    if (clientGroup == nullptr) {
        return ErrorCode::NO_ERROR;
    }
    auto currentClient = clientGroup->GetCurrentClient();
    if (currentClient != nullptr) {
        auto currentClientInfo = clientGroup->GetClientInfo(currentClient->AsObject());
        if (!callerBundleName.empty() && currentClientInfo != nullptr &&
            callerBundleName != currentClientInfo->attribute.bundleName) {
            IMSA_HILOGI("remove current client: %{public}d", currentClientInfo->pid);
            DetachOptions options = { .sessionId = 0, .isUnbindFromClient = false };
            RemoveClient(currentClient, clientGroup, options);
        } else {
            clientGroup->UpdateClientInfo(currentClient->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, false } });
        }
    }
    auto inactiveClient = clientGroup->GetInactiveClient();
    if (inactiveClient != nullptr) {
        DetachOptions options = { .sessionId = 0, .isUnbindFromClient = false, .isInactiveClient = true };
        RemoveClient(inactiveClient, clientGroup, options);
    }
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::NeedHideRealIme(uint64_t clientGroupId)
{
    auto [clientGroup, clientInfo] = GetClientBoundRealIme();
    if (clientInfo == nullptr) {
        return true;
    }
    if (!WindowAdapter::GetInstance().IsDisplayGroupIdExist(clientInfo->clientGroupId) ||
        !WindowAdapter::GetInstance().IsDisplayGroupIdExist(clientInfo->config.inputAttribute.displayGroupId)) {
        return true;
    }
    /* requestHide triggered by the group where the edit box resides/where the soft keyboard resides
     * special scenarios: specifying keyboard show in the main display */
    return clientInfo->clientGroupId == clientGroupId ||
           clientInfo->config.inputAttribute.displayGroupId == clientGroupId;
}

int32_t PerUserSession::OnPrepareInput(const InputClientInfo &clientInfo)
{
    IMSA_HILOGD("PerUserSession::OnPrepareInput start");
    if (clientInfo.client == nullptr) {
        IMSA_HILOGE("client is nullptr");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    HandleSameClientInMultiGroup(clientInfo);
    return AddClientInfo(clientInfo.client->AsObject(), clientInfo);
}

/** Release input. Called by an input client.Run in work thread of this user
 * @param the parameters from remote client
 * @return ErrorCode
 */
int32_t PerUserSession::OnReleaseInput(const sptr<IInputClient> &client, uint32_t sessionId)
{
    IMSA_HILOGD("PerUserSession::OnReleaseInput start");
    if (client == nullptr) {
        IMSA_HILOGE("client nullptr");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    auto clientGroup = GetClientGroup(client->AsObject());
    if (clientGroup == nullptr) {
        IMSA_HILOGD("client not found");
        return ErrorCode::NO_ERROR;
    }
    bool isReady = clientGroup->IsNotifyInputStop(client);
    DetachOptions options = { .sessionId = sessionId, .isUnbindFromClient = true };
    int32_t ret = RemoveClient(client, clientGroup, options);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("remove client failed");
        return ret;
    }
    if (isReady) {
        ImeEventListenerManager::GetInstance().NotifyInputStop(userId_, clientGroup->GetDisplayGroupId());
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::RemoveClient(
    const sptr<IInputClient> &client, const std::shared_ptr<ClientGroup> &clientGroup, const DetachOptions &options)
{
    if (client == nullptr || clientGroup == nullptr) {
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    // if client is current client, unbind firstly
    auto clientInfo = clientGroup->GetClientInfo(client->AsObject());
    if (IsSameClient(client, clientGroup->GetCurrentClient())) {
        UnBindClientWithIme(clientInfo, options);
        clientGroup->SetCurrentClient(nullptr);
        StopClientInput(clientInfo, options);
    } else if (IsSameClient(client, clientGroup->GetInactiveClient())) {
        clientGroup->SetInactiveClient(nullptr);
        StopClientInput(clientInfo, options);
    } else if (options.needNotifyClient) {
        StopClientInput(clientInfo, options);
    }
    clientGroup->RemoveClientInfo(client->AsObject());
    return ErrorCode::NO_ERROR;
}

void PerUserSession::DeactivateClient(const sptr<IInputClient> &client, const std::shared_ptr<ClientGroup> &clientGroup)
{
    if (client == nullptr || clientGroup == nullptr) {
        IMSA_HILOGD("client is nullptr.");
        return;
    }
    auto clientInfo = clientGroup->GetClientInfo(client->AsObject());
    if (clientInfo == nullptr) {
        return;
    }
    IMSA_HILOGI("deactivate client[%{public}d].", clientInfo->pid);
    clientGroup->UpdateClientInfo(client->AsObject(), { { UpdateFlag::STATE, ClientState::INACTIVE } });
    if (IsSameClient(client, clientGroup->GetCurrentClient())) {
        clientGroup->SetCurrentClient(nullptr);
    }
    clientGroup->SetInactiveClient(client);
    client->DeactivateClient();
    auto data = GetImeData(clientInfo->bindImeData);
    if (data == nullptr) {
        IMSA_HILOGE("%{public}d bind ime is abnormal!", clientInfo->pid);
        return;
    }
    RequestAllIme(data, RequestType::NORMAL, [&clientInfo](const sptr<IInputMethodCore> &core) {
        core->OnClientInactive(clientInfo->channel);
        return ErrorCode::NO_ERROR;
    }, clientInfo->clientGroupId);
    InputMethodSysEvent::GetInstance().ReportImeState(
        ImeState::UNBIND, data->pid, ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_)->bundleName);
    Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, INPUT_METHOD_SYSTEM_ABILITY_ID);
}

int32_t PerUserSession::OnStartInput(
    InputClientInfo &inputClientInfo, std::vector<sptr<IRemoteObject>> &agents, std::vector<BindImeInfo> &imeInfos)
{
    IMSA_HILOGD("start input with keyboard[%{public}d].", inputClientInfo.isShowKeyboard);
    auto data = GetReadyImeDataToBind(inputClientInfo.config.inputAttribute.displayId);
    if (data == nullptr || data->agent == nullptr) {
        IMSA_HILOGE("data or agent is nullptr!");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    if (data->IsRealIme()) {
        SetInputType();
    }
    auto clientGroup = GetClientGroupByGroupId(inputClientInfo.clientGroupId);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("not found group");
        return ErrorCode::ERROR_IMSA_NULLPTR;
    }
    HandleBindImeChanged(inputClientInfo, data, clientGroup);
    inputClientInfo.config.requestKeyboardReason = inputClientInfo.requestKeyboardReason;
    int32_t ret = BindClientWithIme(std::make_shared<InputClientInfo>(inputClientInfo), data, true);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("bind failed, ret: %{public}d!", ret);
        return ret;
    }
    return PrepareImeInfos(data, agents, imeInfos, inputClientInfo.clientGroupId);
}

std::shared_ptr<ImeData> PerUserSession::GetRealImeData(bool isReady)
{
    std::lock_guard<std::mutex> lock(realImeDataLock_);
    if (realImeData_ == nullptr) {
        return nullptr;
    }
    if (!isReady) {
        return realImeData_;
    }
    if (realImeData_->imeStatus != ImeStatus::READY) {
        return nullptr;
    }
    return realImeData_;
}

void PerUserSession::RemoveRealImeData()
{
    std::lock_guard<std::mutex> lock(realImeDataLock_);
    if (realImeData_ != nullptr && realImeData_->core != nullptr) {
        IMSA_HILOGD("deathRecipient remove.");
        RemoveDeathRecipient(realImeData_->deathRecipient, realImeData_->core->AsObject());
    }
    realImeData_ = nullptr;
}

void PerUserSession::RemoveRealImeData(pid_t pid)
{
    std::lock_guard<std::mutex> lock(realImeDataLock_);
    if (realImeData_ == nullptr || realImeData_->pid != pid) {
        return;
    }
    if (realImeData_->core != nullptr) {
        IMSA_HILOGD("deathRecipient remove.");
        RemoveDeathRecipient(realImeData_->deathRecipient, realImeData_->core->AsObject());
    }
    realImeData_ = nullptr;
}

void PerUserSession::RemoveMirrorImeData(pid_t pid)
{
    std::lock_guard<std::mutex> lock(mirrorImeDataLock_);
    if (mirrorImeData_ == nullptr || mirrorImeData_->pid != pid) {
        return;
    }
    if (mirrorImeData_->core != nullptr) {
        IMSA_HILOGD("deathRecipient remove.");
        RemoveDeathRecipient(mirrorImeData_->deathRecipient, mirrorImeData_->core->AsObject());
    }
    mirrorImeData_ = nullptr;
}

void PerUserSession::RemoveProxyImeData(pid_t pid)
{
    std::lock_guard<std::mutex> lock(proxyImeDataLock_);
    auto mapIter = proxyImeData_.begin();
    while (mapIter != proxyImeData_.end()) {
        auto &imeDataList = mapIter->second;
        auto vecIter = std::find_if(
            imeDataList.begin(), imeDataList.end(), [pid](const std::shared_ptr<ImeData> &existingImeData) {
                return existingImeData != nullptr && pid == existingImeData->pid;
            });
        if (vecIter != imeDataList.end()) {
            auto imeData = *vecIter;
            if (imeData->core != nullptr) {
                RemoveDeathRecipient(imeData->deathRecipient, imeData->core->AsObject());
            }
            imeDataList.erase(vecIter);
        }
        if (imeDataList.empty()) {
            mapIter = proxyImeData_.erase(mapIter);
        } else {
            mapIter++;
        }
    }
}

std::shared_ptr<ImeData> PerUserSession::GetReadyImeDataToBind(uint64_t displayId)
{
    auto proxyIme = GetProxyImeData(displayId);
    if (proxyIme != nullptr && IsEnable(proxyIme, displayId)) {
        return proxyIme;
    }
    if (displayId != ImfCommonConst::DEFAULT_DISPLAY_ID) {
        proxyIme = GetProxyImeData(ImfCommonConst::DEFAULT_DISPLAY_ID);
        if (proxyIme != nullptr && proxyIme->uid == ImfCommonConst::COL_PROXY_IME && IsEnable(proxyIme, displayId)) {
            return proxyIme;
        }
    }
    return GetRealImeData(true);
}

std::shared_ptr<ImeData> PerUserSession::GetProxyImeData(uint64_t displayId)
{
    std::lock_guard<std::mutex> lock(proxyImeDataLock_);
    auto iter = proxyImeData_.find(displayId);
    if (iter == proxyImeData_.end()) {
        return nullptr;
    }
    auto proxyImeList = iter->second;
    if (proxyImeList.empty()) {
        return nullptr;
    }
    return proxyImeList.back();
}

bool PerUserSession::IsDefaultGroup(uint64_t clientGroupId)
{
    return clientGroupId == ImfCommonConst::DEFAULT_DISPLAY_GROUP_ID;
}

int32_t PerUserSession::SendAllReadyImeToClient(
    std::shared_ptr<ImeData> data, const std::shared_ptr<InputClientInfo> &clientInfo)
{
    if (data == nullptr || clientInfo == nullptr) {
        IMSA_HILOGW("no need to send");
        return ErrorCode::NO_ERROR;
    }

    std::vector<std::shared_ptr<ImeData>> imeDataVec = { data };
    if (!data->IsImeMirror() && IsDefaultGroup(clientInfo->clientGroupId)) {
        auto mirrorIme = GetMirrorImeData();
        if (mirrorIme != nullptr) {
            imeDataVec.push_back(mirrorIme);
        }
    }

    int32_t finalResult = ErrorCode::NO_ERROR;
    int32_t ret;
    for (const auto &dataItem : imeDataVec) {
        BindImeInfo imeInfo;
        imeInfo.pid = dataItem->pid;
        imeInfo.bundleName = dataItem->ime.first;
        ret = clientInfo->client->OnInputReady(dataItem->agent, imeInfo);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("OnInputReady failed, ret = %{public}d", ret);
        }
        if (!dataItem->IsImeMirror()) {
            finalResult = ret;
        }
    }
    return finalResult;
}

int32_t PerUserSession::BindClientWithIme(
    const std::shared_ptr<InputClientInfo> &clientInfo, const std::shared_ptr<ImeData> &imeData, bool isBindFromClient)
{
    if (clientInfo == nullptr) {
        IMSA_HILOGE("clientInfo is nullptr!");
        return ErrorCode::ERROR_IMSA_NULLPTR;
    }
    if (imeData == nullptr) {
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto groupId = clientInfo->clientGroupId;
    auto clientGroup = GetClientGroupByGroupId(groupId);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("not found group");
        return ErrorCode::ERROR_IMSA_NULLPTR;
    }
    IMSA_HILOGD("imePid: %{public}d, isShowKeyboard: %{public}d, isBindFromClient: %{public}d, groupId: "
                "%{public}" PRIu64 ".",
        imeData->pid, clientInfo->isShowKeyboard, isBindFromClient, groupId);
    if (!imeData->imeExtendInfo.privateCommand.empty()) {
        auto ret = SendPrivateData(imeData->imeExtendInfo.privateCommand);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("before start input notify send private data failed, ret: %{public}d!", ret);
        }
    }
    InputClientInfoInner inputClientInfoInner = InputMethodTools::GetInstance().InputClientInfoToInner(*clientInfo);
    auto ret = RequestAllIme(
        imeData, RequestType::START_INPUT,
        [&inputClientInfoInner, isBindFromClient](
            const sptr<IInputMethodCore> &core) { return core->StartInput(inputClientInfoInner, isBindFromClient); },
        groupId);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("start input failed, ret: %{public}d!", ret);
        return ErrorCode::ERROR_IME_START_INPUT_FAILED;
    }
    if (imeData->IsRealIme()) {
        InputMethodSysEvent::GetInstance().ReportImeState(
            ImeState::BIND, imeData->pid, ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_)->bundleName);
        Memory::MemMgrClient::GetInstance().SetCritical(getpid(), true, INPUT_METHOD_SYSTEM_ABILITY_ID);
        PostCurrentImeInfoReportHook(imeData->ime.first);
    }
    if (!isBindFromClient) {
        ret = SendAllReadyImeToClient(imeData, clientInfo);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("start client input failed, ret: %{public}d!", ret);
            return ErrorCode::ERROR_IMSA_CLIENT_INPUT_READY_FAILED;
        }
    }

    if (imeData->IsImeMirror()) {
        return ErrorCode::NO_ERROR;
    }
    HandleSameImeInMultiGroup(*clientInfo, imeData);
    HandleRealImeInMultiGroup(*clientInfo, imeData);
    auto bindImeData = std::make_shared<BindImeData>(imeData->pid, imeData->type);
    clientGroup->UpdateClientInfo(clientInfo->client->AsObject(),
        { { UpdateFlag::ISSHOWKEYBOARD, clientInfo->isShowKeyboard }, { UpdateFlag::STATE, ClientState::ACTIVE },
            { UpdateFlag::BIND_IME_DATA, bindImeData } });
    ReplaceCurrentClient(clientInfo->client, clientGroup);
    if (clientInfo->isShowKeyboard) {
        ImeEventListenerManager::GetInstance().NotifyInputStart(
            userId_, clientInfo->config.windowId, groupId, static_cast<int32_t>(clientInfo->requestKeyboardReason));
    }
    return ErrorCode::NO_ERROR;
}

void PerUserSession::HandleSameImeInMultiGroup(
    const InputClientInfo &newClientInfo, const std::shared_ptr<ImeData> &newImeData)
{
    if (newImeData == nullptr) {
        return;
    }
    auto [oldClientGroup, oldClientInfo] = GetClientBoundImeByImePid(newImeData->pid);
    HandleInMultiGroup(newClientInfo, oldClientGroup, oldClientInfo);
}

void PerUserSession::HandleRealImeInMultiGroup(
    const InputClientInfo &newClientInfo, const std::shared_ptr<ImeData> &newImeData)
{
    if (newImeData == nullptr || !newImeData->IsRealIme()) {
        return;
    }
    auto [oldClientGroup, oldClientInfo] = GetClientBoundRealIme();
    HandleInMultiGroup(newClientInfo, oldClientGroup, oldClientInfo);
}

void PerUserSession::HandleSameClientInMultiGroup(const InputClientInfo &newClientInfo)
{
    auto [oldClientGroup, oldClientInfo] = GetClientBySelfPidOrHostPid(newClientInfo.pid);
    HandleInMultiGroup(newClientInfo, oldClientGroup, oldClientInfo, true);
}

void PerUserSession::HandleInMultiGroup(const InputClientInfo &newClientInfo,
    const std::shared_ptr<ClientGroup> &oldClientGroup, const std::shared_ptr<InputClientInfo> &oldClientInfo,
    bool needStopIme)
{
    if (oldClientGroup == nullptr || oldClientInfo == nullptr) {
        return;
    }
    if (IsSameClientGroup(oldClientInfo->clientGroupId, newClientInfo.clientGroupId)) {
        IMSA_HILOGD("same group.");
        return;
    }
    IMSA_HILOGI("needStopIme:%{public}d, remove client:%{public}d from group:%{public}" PRIu64 ".", needStopIme,
        oldClientInfo->pid, oldClientInfo->clientGroupId);
    if (needStopIme) {
        StopImeInput(GetImeData(oldClientInfo->bindImeData), oldClientInfo, 0);
    }
    if (oldClientInfo->pid != newClientInfo.pid) {
        StopClientInput(oldClientInfo,
            { .isInactiveClient = IsSameClient(oldClientInfo->client, oldClientGroup->GetInactiveClient()) });
    }
    if (IsSameClient(oldClientInfo->client, oldClientGroup->GetCurrentClient())) {
        oldClientGroup->SetCurrentClient(nullptr);
    }
    if (IsSameClient(oldClientInfo->client, oldClientGroup->GetInactiveClient())) {
        oldClientGroup->SetInactiveClient(nullptr);
    }
    if (oldClientInfo->client != nullptr) {
        oldClientGroup->RemoveClientInfo(oldClientInfo->client->AsObject());
    }
}

std::shared_ptr<ImeData> PerUserSession::GetImeData(const std::shared_ptr<BindImeData> &bindImeData)
{
    if (bindImeData == nullptr) {
        return nullptr;
    }
    return GetImeData(bindImeData->pid, bindImeData->type);
}

std::shared_ptr<ImeData> PerUserSession::GetImeData(pid_t pid, ImeType type)
{
    switch (type) {
        case ImeType::IME: {
            return GetRealImeData(pid);
        }
        case ImeType::IME_MIRROR: {
            return GetMirrorImeData(pid);
        }
        case ImeType::PROXY_IME: {
            return GetProxyImeData(pid);
        }
        default: {
            return nullptr;
        }
    }
}

std::shared_ptr<ImeData> PerUserSession::GetProxyImeData(pid_t pid)
{
    std::lock_guard<std::mutex> lock(proxyImeDataLock_);
    for (const auto &[key, imeDataVec] : proxyImeData_) {
        auto iter = std::find_if(imeDataVec.begin(), imeDataVec.end(),
            [pid](const auto &imeData) { return imeData != nullptr && imeData->pid == pid; });
        if (iter != imeDataVec.end()) {
            return *iter;
        }
    }
    return nullptr;
}

bool PerUserSession::IsSameClientGroup(uint64_t oldGroupId, uint64_t newGroupId)
{
    return newGroupId == oldGroupId;
}

int32_t PerUserSession::PostCurrentImeInfoReportHook(const std::string &bundleName)
{
    if (!ImeInfoInquirer::GetInstance().IsCapacitySupport(SystemConfig::IME_DAU_STATISTICS_CAP_NAME)) {
        IMSA_HILOGD("ime dau statistics cap is not enable.");
        return ErrorCode::ERROR_DEVICE_UNSUPPORTED;
    }
    if (eventHandler_ == nullptr) {
        IMSA_HILOGE("eventHandler_ is nullptr.");
        return ErrorCode::ERROR_IMSA_NULLPTR;
    }
    auto now = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    auto task = [userId = userId_, bundleName, now]() {
        ImfHookMgr::GetInstance().ExecuteCurrentImeInfoReportHook(userId, bundleName, now);
    };
    eventHandler_->PostTask(task, "ExecuteCurrentImeInfoReportHook", 0, AppExecFwk::EventQueue::Priority::LOW);
    return ErrorCode::NO_ERROR;
}

void PerUserSession::UnBindClientWithIme(
    const std::shared_ptr<InputClientInfo> &currentClientInfo, const DetachOptions &options)
{
    if (currentClientInfo == nullptr) {
        return;
    }
    if (!options.isUnbindFromClient) {
        IMSA_HILOGD("unbind from service.");
        StopClientInput(currentClientInfo, options);
    }
    StopImeInput(GetImeData(currentClientInfo->bindImeData), currentClientInfo, options.sessionId);
}

void PerUserSession::StopClientInput(const std::shared_ptr<InputClientInfo> &clientInfo, DetachOptions options)
{
    if (clientInfo == nullptr || clientInfo->client == nullptr) {
        return;
    }
    int32_t ret;
    if (options.isNotifyClientAsync) {
        ret = clientInfo->client->OnInputStopAsync(options.isInactiveClient, options.isSendKeyboardStatus);
    } else {
        auto onInputStopObject = new (std::nothrow) OnInputStopNotifyServiceImpl(clientInfo->pid);
        if (onInputStopObject == nullptr) {
            IMSA_HILOGE("Failed to create onInputStopObject.");
            return;
        }
        std::lock_guard<std::mutex> lock(isNotifyFinishedLock_);
        isNotifyFinished_.Clear(false);
        ret =
            clientInfo->client->OnInputStop(options.isInactiveClient, onInputStopObject, options.isSendKeyboardStatus);
        if (!isNotifyFinished_.GetValue()) {
            IMSA_HILOGE("OnInputStop is not finished!");
        }
    }
    IMSA_HILOGI("isStopInactiveClient: %{public}d, client pid: %{public}d, ret: %{public}d.", options.isInactiveClient,
        clientInfo->pid, ret);
}

void PerUserSession::StopImeInput(
    const std::shared_ptr<ImeData> &imeData, const std::shared_ptr<InputClientInfo> &clientInfo, uint32_t sessionId)
{
    if (imeData == nullptr || clientInfo == nullptr) {
        return;
    }
    auto ret = RequestAllIme(
        imeData, RequestType::STOP_INPUT,
        [&clientInfo, sessionId](
            const sptr<IInputMethodCore> &core) { return core->StopInput(clientInfo->channel, sessionId); },
        clientInfo->clientGroupId);
    IMSA_HILOGI("stop ime input, ret: %{public}d.", ret);
    if (ret == ErrorCode::NO_ERROR && imeData->IsRealIme()) {
        InputMethodSysEvent::GetInstance().ReportImeState(
            ImeState::UNBIND, imeData->pid, ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_)->bundleName);
        Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, INPUT_METHOD_SYSTEM_ABILITY_ID);
    }
    if (imeData->IsRealIme()) {
        RestoreCurrentImeSubType();
    }
}

void PerUserSession::OnSecurityChange(int32_t security)
{
    auto data = GetRealImeData(true);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return;
    }
    auto ret = RequestIme(data, RequestType::NORMAL, [&data, security] {
        return data->core->OnSecurityChange(security);
    });
    IMSA_HILOGD("on security change, ret: %{public}d.", ret);
}

int32_t PerUserSession::OnSetCoreAndAgent(const sptr<IInputMethodCore> &core, const sptr<IRemoteObject> &agent)
{
    IMSA_HILOGI("start.");
    auto imeData = UpdateRealImeData(core, agent, IPCSkeleton::GetCallingPid());
    if (imeData == nullptr) {
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    auto action = GetImeAction(ImeEvent::SET_CORE_AND_AGENT);
    if (action == ImeAction::DO_NOTHING) {
        return ErrorCode::NO_ERROR;
    }
    if (action != ImeAction::DO_SET_CORE_AND_AGENT) {
        return ErrorCode::ERROR_IME;
    }
    auto ret = InitInputControlChannel();
    IMSA_HILOGI("init input control channel ret: %{public}d.", ret);
    if (GetAttachCount() == 0) {
        auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
        if (clientInfo != nullptr) {
            ClearRequestKeyboardReason(clientInfo);
            BindClientWithIme(clientInfo, imeData);
            SetInputType();
        }
    }
    bool isStarted = true;
    isImeStarted_.SetValue(isStarted);
    return ErrorCode::NO_ERROR;
}

std::pair<std::shared_ptr<ClientGroup>, std::shared_ptr<InputClientInfo>> PerUserSession::GetCurrentClientBoundRealIme()
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    for (const auto &[groupId, group] : clientGroupMap_) {
        if (group == nullptr) {
            continue;
        }
        auto currentClientInfo = group->GetCurrentClientInfoBoundRealIme();
        if (currentClientInfo == nullptr) {
            continue;
        }
        return { group, currentClientInfo };
    }
    return { nullptr, nullptr };
}

std::pair<std::shared_ptr<ClientGroup>, std::shared_ptr<InputClientInfo>> PerUserSession::GetClientBoundRealIme()
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    for (const auto &[groupId, group] : clientGroupMap_) {
        if (group == nullptr) {
            continue;
        }
        auto clientInfo = group->GetClientInfoBoundRealIme();
        if (clientInfo != nullptr) {
            return { group, clientInfo };
        }
    }
    return { nullptr, nullptr };
}

std::pair<std::shared_ptr<ClientGroup>, std::shared_ptr<InputClientInfo>> PerUserSession::GetClientBoundImeByWindowId(
    uint32_t windowId)
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    for (const auto &[groupId, group] : clientGroupMap_) {
        if (group == nullptr) {
            continue;
        }
        auto clientInfo = group->GetClientBoundImeByWindowId(windowId);
        if (clientInfo != nullptr) {
            return { group, clientInfo };
        }
    }
    return { nullptr, nullptr };
}

std::pair<std::shared_ptr<ClientGroup>, std::shared_ptr<InputClientInfo>> PerUserSession::GetClientBySelfPidOrHostPid(
    pid_t clientPid)
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    for (const auto &[groupId, group] : clientGroupMap_) {
        if (group == nullptr) {
            continue;
        }
        auto clientInfo = group->GetClientInfo(clientPid);
        if (clientInfo != nullptr) {
            return { group, clientInfo };
        }
        clientInfo = group->GetClientInfoByHostPid(clientPid);
        if (clientInfo != nullptr) {
            return { group, clientInfo };
        }
    }
    return { nullptr, nullptr };
}

std::pair<std::shared_ptr<ClientGroup>, std::shared_ptr<InputClientInfo>> PerUserSession::GetClientBySelfPid(
    pid_t clientPid)
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    for (const auto &[groupId, group] : clientGroupMap_) {
        if (group == nullptr) {
            continue;
        }
        auto clientInfo = group->GetClientInfo(clientPid);
        if (clientInfo != nullptr) {
            return { group, clientInfo };
        }
    }
    return { nullptr, nullptr };
}

std::pair<std::shared_ptr<ClientGroup>, std::shared_ptr<InputClientInfo>> PerUserSession::GetClientBoundImeByImePid(
    pid_t bindImePid)
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    for (const auto &[groupId, group] : clientGroupMap_) {
        if (group == nullptr) {
            continue;
        }
        auto clientInfo = group->GetClientInfoByBindIme(bindImePid);
        if (clientInfo != nullptr) {
            return { group, clientInfo };
        }
    }
    return { nullptr, nullptr };
}

int32_t PerUserSession::OnRegisterProxyIme(
    uint64_t displayId, const sptr<IInputMethodCore> &core, const sptr<IRemoteObject> &agent, int32_t pid)
{
    IMSA_HILOGD("start.");
    if (displayId == ImfCommonConst::DEFAULT_DISPLAY_ID) {
        auto result = IsRequestOverLimit(
            TimeLimitType::PROXY_IME_LIMIT, PROXY_REGISTERATION_TIME_INTERVAL, MAX_REGISTRATIONS_NUM);
        if (result != ErrorCode::NO_ERROR) {
            IMSA_HILOGI("frequent calls, service is busy.");
            return result;
        }
    }
    auto lastImeData = GetProxyImeData(displayId);
    if (lastImeData != nullptr && lastImeData->core != nullptr && core != nullptr &&
        lastImeData->core->AsObject() != core->AsObject()) {
        lastImeData->core->NotifyPreemption();
    }
    auto newImeData = AddProxyImeData(displayId, core, agent, pid);
    if (newImeData == nullptr) {
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    auto clientInfo = GetCurrentClientInfo(displayId);
    if (clientInfo == nullptr) {
        return ErrorCode::NO_ERROR;
    }
    if (!IsSameIme(clientInfo->bindImeData, newImeData)) {
        UnBindClientWithIme(clientInfo, { .sessionId = 0 });
    }
    BindClientWithIme(clientInfo, newImeData);
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::CompareExchange(const int32_t value)
{
    std::lock_guard<std::mutex> lock(largeMemoryStateMutex_);
    if (largeMemoryState_ == value) {
        IMSA_HILOGD("Duplicate message.");
        return true;
    }
    largeMemoryState_ = value;
    return false;
}

int32_t PerUserSession::UpdateLargeMemorySceneState(const int32_t memoryState)
{
    if (CompareExchange(memoryState)) {
        return ErrorCode::NO_ERROR;
    }
    IMSA_HILOGI("large memory state: %{public}d.", memoryState);
    if (memoryState == LargeMemoryState::LARGE_MEMORY_NOT_NEED) {
        StartCurrentIme();
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnUnregisterProxyIme(uint64_t displayId, int32_t pid)
{
    IMSA_HILOGD("proxy unregister.");
    auto clientInfo = GetCurrentClientInfo(displayId);
    if (clientInfo != nullptr && clientInfo->bindImeData != nullptr && clientInfo->bindImeData->pid == pid) {
        UnBindClientWithIme(clientInfo, { .sessionId = 0 });
    }
    RemoveProxyImeData(displayId, pid);
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::RemoveProxyImeData(uint64_t displayId, pid_t pid)
{
    std::lock_guard<std::mutex> lock(proxyImeDataLock_);
    auto iter = proxyImeData_.find(displayId);
    if (iter == proxyImeData_.end()) {
        IMSA_HILOGD("displayId %{public}" PRIu64 " not found, no ImeData to remove", displayId);
        return ErrorCode::NO_ERROR;
    }
    auto &imeDataList = iter->second;
    auto vecIter =
        std::find_if(imeDataList.begin(), imeDataList.end(), [pid](const std::shared_ptr<ImeData> &existingImeData) {
            return existingImeData != nullptr && pid == existingImeData->pid;
        });
    if (vecIter != imeDataList.end()) {
        auto imeData = *vecIter;
        if (imeData->core != nullptr) {
            RemoveDeathRecipient(imeData->deathRecipient, imeData->core->AsObject());
        }
        imeDataList.erase(vecIter);
    }
    if (imeDataList.empty()) {
        proxyImeData_.erase(iter);
    }
    return ErrorCode::NO_ERROR;
}

std::shared_ptr<ImeData> PerUserSession::AddMirrorImeData(
    const sptr<IInputMethodCore> &core, const sptr<IRemoteObject> &agent, pid_t pid)
{
    std::lock_guard<std::mutex> lock(mirrorImeDataLock_);
    auto imeData = std::make_shared<ImeData>(nullptr, nullptr, nullptr, -1);
    auto ret = FillImeData(core, agent, pid, ImeType::IME_MIRROR, imeData);
    if (ret != ErrorCode::NO_ERROR) {
        return nullptr;
    }
    mirrorImeData_ = imeData;
    return imeData;
}

int32_t PerUserSession::OnBindImeMirror(const sptr<IInputMethodCore> &core, const sptr<IRemoteObject> &agent)
{
    IMSA_HILOGI("[ImeMirrorTag]star");
    auto pid = IPCSkeleton::GetCallingPid();
    auto clientInfo = GetCurrentClientInfo();
    auto oldImeData = GetMirrorImeData();
    if (oldImeData != nullptr && oldImeData->pid != pid) {
        if (oldImeData->core != nullptr) {
            oldImeData->core->NotifyPreemption();
        }
        if (clientInfo != nullptr && clientInfo->client != nullptr) {
            clientInfo->client->OnImeMirrorStop(oldImeData->agent);
        }
        RemoveMirrorImeData(oldImeData->pid);
    }
    if (oldImeData != nullptr && oldImeData->pid == pid) {
        if (clientInfo != nullptr) {
            BindClientWithIme(clientInfo, oldImeData);
        }
        return ErrorCode::NO_ERROR;
    }
    auto imeData = AddMirrorImeData(core, agent, pid);
    if (imeData == nullptr) {
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    if (clientInfo != nullptr) {
        BindClientWithIme(clientInfo, imeData);
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnUnbindImeMirror()
{
    IMSA_HILOGD("[ImeMirrorTag]start");
    auto pid = IPCSkeleton::GetCallingPid();
    auto mirrorIme = GetMirrorImeData();
    if (mirrorIme == nullptr || mirrorIme->pid != pid) {
        IMSA_HILOGD("[ImeMirrorTag]no ime mirror or not same ime mirror");
        return ErrorCode::NO_ERROR;
    }
    auto clientInfo = GetCurrentClientInfo();
    if (clientInfo == nullptr) {
        IMSA_HILOGD("[ImeMirrorTag]no current client");
        RemoveMirrorImeData(pid);
        return ErrorCode::NO_ERROR;
    }
    if (clientInfo->client != nullptr) {
        clientInfo->client->OnImeMirrorStop(mirrorIme->agent);
    }
    StopImeInput(mirrorIme, clientInfo, 0);
    RemoveMirrorImeData(pid);
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::InitInputControlChannel()
{
    IMSA_HILOGD("PerUserSession::InitInputControlChannel start.");
    sptr<IInputControlChannel> inputControlChannel = new (std::nothrow) InputControlChannelServiceImpl(userId_);
    if (inputControlChannel == nullptr) {
        IMSA_HILOGE("new inputControlChannel failed!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto data = GetRealImeData(true);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(data, RequestType::NORMAL, [&data, &inputControlChannel] {
        return data->core->InitInputControlChannel(inputControlChannel);
    });
}

bool PerUserSession::IsLargeMemoryStateNeed()
{
    std::lock_guard<std::mutex> lock(largeMemoryStateMutex_);
    if (largeMemoryState_ == LargeMemoryState::LARGE_MEMORY_NEED) {
        IMSA_HILOGI("large memory state is True");
        return true;
    }
    return false;
}

void PerUserSession::StartImeInImeDied()
{
    IMSA_HILOGD("StartImeInImeDied.");
    {
        auto result = IsRequestOverLimit(TimeLimitType::IME_LIMIT, IME_RESET_TIME_OUT, MAX_RESTART_NUM);
        if (result != ErrorCode::NO_ERROR) {
            return;
        }
    }
    if (!IsWmsReady()) {
        IMSA_HILOGW("not ready to start ime.");
        return;
    }
    if (IsLargeMemoryStateNeed()) {
        return;
    }
    StartImeIfInstalled(StartReason::RESTART_AFTER_DIED);
}

void PerUserSession::StartImeIfInstalled(StartReason startReason)
{
    auto imeToStart = GetRealCurrentIme(false);
    if (imeToStart == nullptr || imeToStart->imeId.empty()) {
        IMSA_HILOGE("imeToStart is nullptr!");
        return;
    }
    if (!ImeInfoInquirer::GetInstance().IsImeInstalled(userId_, imeToStart->bundleName, imeToStart->extName)) {
        IMSA_HILOGE("imeToStart is not installed, imeId = %{public}s!", imeToStart->imeId.c_str());
        return;
    }
    StartCurrentIme(false, startReason);
}

void PerUserSession::ReplaceCurrentClient(
    const sptr<IInputClient> &client, const std::shared_ptr<ClientGroup> &clientGroup)
{
    std::lock_guard<std::mutex> lock(focusedClientLock_);
    if (client == nullptr || clientGroup == nullptr) {
        return;
    }
    auto clientInfo = clientGroup->GetClientInfo(client->AsObject());
    if (clientInfo == nullptr) {
        return;
    }
    auto replacedClient = clientGroup->GetCurrentClient();
    clientGroup->SetCurrentClient(client);
    if (replacedClient != nullptr) {
        auto replacedClientInfo = clientGroup->GetClientInfo(replacedClient->AsObject());
        if (replacedClientInfo != nullptr && replacedClientInfo->pid != clientInfo->pid) {
            IMSA_HILOGI("remove replaced client: [%{public}d]", replacedClientInfo->pid);
            DetachOptions options = {
                .sessionId = 0, .isNotifyClientAsync = true, .needNotifyClient = true, .isSendKeyboardStatus = false
            };
            RemoveClient(replacedClient, clientGroup, options);
        }
    }
    auto inactiveClient = clientGroup->GetInactiveClient();
    if (inactiveClient != nullptr) {
        auto inactiveClientInfo = clientGroup->GetClientInfo(inactiveClient->AsObject());
        if (inactiveClientInfo != nullptr && inactiveClientInfo->pid != clientInfo->pid) {
            IMSA_HILOGI("remove inactive client: [%{public}d]", inactiveClientInfo->pid);
            DetachOptions options = { .sessionId = 0, .isUnbindFromClient = false };
            RemoveClient(inactiveClient, clientGroup, options);
        }
    }
}

void PerUserSession::NotifyImeChangeToClients(const Property &property, const SubProperty &subProperty)
{
    ImeEventListenerManager::GetInstance().NotifyImeChange(userId_, property, subProperty);
}

std::shared_ptr<ImeData> PerUserSession::AddProxyImeData(
    uint64_t displayId, sptr<IInputMethodCore> core, sptr<IRemoteObject> agent, pid_t pid)
{
    if (core == nullptr || agent == nullptr) {
        IMSA_HILOGE("core or agent is nullptr!");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(proxyImeDataLock_);
    auto &imeDataList = proxyImeData_[displayId];
    auto iter = std::find_if(imeDataList.begin(), imeDataList.end(),
        [pid](const auto &existingImeData) { return existingImeData != nullptr && pid == existingImeData->pid; });
    if (iter != imeDataList.end()) {
        auto imeData = *iter;
        imeDataList.erase(iter);
        IMSA_HILOGI("preempt again!");
        imeDataList.push_back(imeData);
        return imeData;
    }
    auto imeData = std::make_shared<ImeData>(nullptr, nullptr, nullptr, -1);
    auto ret = FillImeData(core, agent, pid, ImeType::PROXY_IME, imeData);
    if (ret != ErrorCode::NO_ERROR) {
        return nullptr;
    }
    AddProxyImeData(displayId, imeDataList, imeData);
    IMSA_HILOGI("add imeData with displayId: %{public}" PRIu64 ".", displayId);
    return imeData;
}

void PerUserSession::AddProxyImeData(uint64_t displayId,
    std::vector<std::shared_ptr<ImeData>> &imeDataList, const std::shared_ptr<ImeData> &imeData)
{
    if (imeDataList.empty()) {
        imeDataList.push_back(imeData);
        return;
    }
    if (!isFirstPreemption_) {
        isFirstPreemption_ = true;
        const auto &lastImeData = imeDataList.back();
        if (IsEnable(lastImeData, displayId) && !IsEnable(imeData, displayId)) {
            imeDataList.insert(imeDataList.begin(), imeData);
            return;
        }
    }
    imeDataList.push_back(imeData);
}

std::vector<std::shared_ptr<ImeData>> PerUserSession::GetAllReadyImeData(
    const std::shared_ptr<ImeData> &imeData, uint64_t groupId)
{
    if (imeData == nullptr) {
        return {};
    }

    if (imeData->IsImeMirror()) {
        return { imeData };
    }
    auto mirrorIme = GetMirrorImeData();
    if (mirrorIme == nullptr || !IsDefaultGroup(groupId)) {
        return { imeData };
    }
    return { imeData, mirrorIme };
}

void PerUserSession::RemoveImeData(pid_t pid)
{
    RemoveRealImeData(pid);
    RemoveMirrorImeData(pid);
    RemoveProxyImeData(pid);
}

void PerUserSession::RemoveDeathRecipient(
    const sptr<InputDeathRecipient> &deathRecipient, const sptr<IRemoteObject> &object)
{
    if (deathRecipient == nullptr) {
        return;
    }
    if (object == nullptr) {
        return;
    }
    object->RemoveDeathRecipient(deathRecipient);
}

void PerUserSession::OnFocused(uint64_t displayId, int32_t pid, int32_t uid)
{
    std::lock_guard<std::mutex> lock(focusedClientLock_);
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        return;
    }
    auto client = clientGroup->GetCurrentClient();
    if (client == nullptr) {
        return;
    }
    if (clientGroup->IsCurClientFocused(pid, uid)) {
        IMSA_HILOGD("current client focused, focusedPid: %{public}d", pid);
        return;
    }
    if (!OHOS::Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        IMSA_HILOGI("focus shifts to pid: %{public}d, remove current client.", pid);
        RemoveClient(client, clientGroup, { .sessionId = 0 });
        InputMethodSysEvent::GetInstance().OperateSoftkeyboardBehaviour(OperateIMEInfoCode::IME_HIDE_UNFOCUSED);
        return;
    }
    IMSA_HILOGI("focus shifts to pid: %{public}d, deactivate current client.", pid);
    DeactivateClient(client, clientGroup);
}

void PerUserSession::OnUnfocused(uint64_t displayId, int32_t pid, int32_t uid)
{
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        return;
    }
    if (clientGroup->GetCurrentClient() == nullptr) {
        return;
    }
    if (clientGroup->IsCurClientUnFocused(pid, uid)) {
        IMSA_HILOGD("current client Unfocused, unFocusedPid: %{public}d", pid);
        return;
    }
    auto clientInfo = clientGroup->GetClientInfo(pid);
    if (clientInfo == nullptr) {
        return;
    }
    RemoveClient(clientInfo->client, clientGroup, { .sessionId = 0 });
    InputMethodSysEvent::GetInstance().OperateSoftkeyboardBehaviour(OperateIMEInfoCode::IME_HIDE_UNFOCUSED);
}

void PerUserSession::OnScreenUnlock()
{
    ImeCfgManager::GetInstance().ModifyTempScreenLockImeCfg(userId_, "");
    auto imeData = GetRealImeData();
    auto userCfgIme = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
    if (imeData == nullptr || userCfgIme == nullptr || imeData->ime.first == userCfgIme->bundleName
        || !imeData->isStartedInScreenLocked) {
        return;
    }
    IMSA_HILOGI("user %{public}d unlocked, start current ime", userId_);
#ifndef IMF_ON_DEMAND_START_STOP_SA_ENABLE
    if (!ImeStateManagerFactory::GetInstance().GetDynamicStartIme()) {
        StartUserSpecifiedIme();
    }
#endif
}

void PerUserSession::OnScreenLock()
{
    auto imeData = GetRealImeData();
    if (imeData == nullptr) {
        IMSA_HILOGD("imeData is nullptr");
        std::pair<std::string, std::string> ime{ "", "" };
        SetImeUsedBeforeScreenLocked(ime);
        return;
    }
    SetImeUsedBeforeScreenLocked(imeData->ime);
}

int32_t PerUserSession::OnPackageUpdated(const std::string &bundleName)
{
    IMSA_HILOGI("bundleName: %{public}s", bundleName.c_str());
    auto currentImeCfg = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
    if (currentImeCfg != nullptr && bundleName != currentImeCfg->bundleName) {
        IMSA_HILOGD("not current ime, no need");
        return ErrorCode::NO_ERROR;
    }
    if (GetAttachCount() != 0) {
        IMSA_HILOGD("attaching, no need");
        return ErrorCode::NO_ERROR;
    }
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo != nullptr) {
        IMSA_HILOGD("current client exists, no need");
        return ErrorCode::NO_ERROR;
    }
    auto ret = StartUserSpecifiedIme();
    IMSA_HILOGI("start user specified ime result: %{public}d", ret);
    return ret;
}

std::shared_ptr<InputClientInfo> PerUserSession::GetCurrentClientInfo(uint64_t displayId)
{
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        IMSA_HILOGD("client group: %{public}" PRIu64 "", displayId);
        return nullptr;
    }
    return clientGroup->GetCurrentClientInfo();
}

bool PerUserSession::IsSameClient(sptr<IInputClient> source, sptr<IInputClient> dest)
{
    return source != nullptr && dest != nullptr && source->AsObject() == dest->AsObject();
}

std::shared_ptr<ImeNativeCfg> PerUserSession::GetRealCurrentIme(bool needMinGuarantee)
{
    std::shared_ptr<ImeNativeCfg> currentIme = nullptr;
    if (GetInputTypeToStart(currentIme)) {
        return currentIme;
    }
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo != nullptr) {
        InputType type = InputType::NONE;
        if (clientInfo->config.inputAttribute.GetSecurityFlag()) {
            type = InputType::SECURITY_INPUT;
        }
        if (type != InputType::NONE) {
            ImeIdentification inputTypeIme;
            InputTypeManager::GetInstance().GetImeByInputType(type, inputTypeIme);
            currentIme = GetImeNativeCfg(userId_, inputTypeIme.bundleName, inputTypeIme.subName);
            if (currentIme != nullptr) {
                IMSA_HILOGD("get inputType ime:%{public}d!", type);
                return currentIme;
            }
        }
        if (IsPreconfiguredDefaultImeSpecified(*clientInfo)) {
            IMSA_HILOGD("get preconfigured default ime:%{public}d/%{public}d!",
                clientInfo->config.isSimpleKeyboardEnabled, clientInfo->config.inputAttribute.IsOneTimeCodeFlag());
            auto preconfiguredIme = ImeInfoInquirer::GetInstance().GetDefaultImeCfg();
            auto defaultIme = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
            if (preconfiguredIme != nullptr && defaultIme != nullptr && defaultIme->imeId == preconfiguredIme->imeId) {
                return defaultIme;
            }
            if (preconfiguredIme != nullptr) {
                return preconfiguredIme;
            }
        }
    }
#ifdef IMF_SCREENLOCK_MGR_ENABLE
    if (IsDeviceLockAndScreenLocked()) {
        IMSA_HILOGD("get screen locked ime!");
        auto preconfiguredIme = ImeInfoInquirer::GetInstance().GetDefaultImeCfg();
        auto defaultIme = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
        if (preconfiguredIme != nullptr && (defaultIme == nullptr || defaultIme->imeId != preconfiguredIme->imeId)) {
            ImeCfgManager::GetInstance().ModifyTempScreenLockImeCfg(userId_, preconfiguredIme->imeId);
        }
    }
#endif
    IMSA_HILOGD("get user set ime:%{public}d!", needMinGuarantee);
    return needMinGuarantee ? ImeInfoInquirer::GetInstance().GetImeToStart(userId_)
                                : ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
}

int32_t PerUserSession::NotifyImeChangedToClients()
{
    auto userSpecifiedIme = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
    if (userSpecifiedIme == nullptr) {
        IMSA_HILOGW("userSpecifiedIme not find.");
        return ErrorCode::ERROR_IMSA_NULLPTR;
    }
    auto userSpecifiedImeInfo =
        ImeInfoInquirer::GetInstance().GetImeInfo(userId_, userSpecifiedIme->bundleName, userSpecifiedIme->subName);
    if (userSpecifiedImeInfo == nullptr) {
        IMSA_HILOGE("userSpecifiedIme:%{public}s not find.", userSpecifiedIme->bundleName.c_str());
        return ErrorCode::ERROR_IMSA_GET_IME_INFO_FAILED;
    }
    NotifyImeChangeToClients(userSpecifiedImeInfo->prop, userSpecifiedImeInfo->subProp);
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::NotifySubTypeChangedToIme(const std::string &bundleName, const std::string &subName)
{
    SubProperty subProp;
    subProp.name = UNDEFINED;
    subProp.id = UNDEFINED;
    if (subName.empty()) {
        IMSA_HILOGW("undefined subtype");
    } else if (InputTypeManager::GetInstance().IsInputType({ bundleName, subName })) {
        IMSA_HILOGD("inputType: %{public}s", subName.c_str());
        InputTypeManager::GetInstance().Set(true, { bundleName, subName });
        subProp.name = bundleName;
        subProp.id = subName;
    } else {
        auto currentImeInfo = ImeInfoInquirer::GetInstance().GetImeInfo(userId_, bundleName, subName);
        if (currentImeInfo != nullptr) {
            subProp = currentImeInfo->subProp;
        }
    }
    auto ret = SwitchSubtypeWithoutStartIme(subProp);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SwitchSubtype failed!");
    }
    return ret;
}

bool PerUserSession::IsKeyboardCallingProcess(int32_t pid, uint32_t windowId)
{
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo == nullptr) {
        IMSA_HILOGE("failed to get cur client info!");
        return false;
    }
    if (clientInfo->pid == pid) {
        return true;
    }
    return clientInfo->config.inputAttribute.windowId == windowId;
}

int32_t PerUserSession::StartCurrentIme(bool isStopCurrentIme, StartReason startReason)
{
    IMSA_HILOGD("enter");
    auto imeToStart = GetRealCurrentIme(true);
    if (imeToStart == nullptr) {
        IMSA_HILOGE("imeToStart is nullptr!");
        return ErrorCode::ERROR_IMSA_IME_TO_START_NULLPTR;
    }
    imeToStart->startReason = startReason;
    IMSA_HILOGI("ime info:%{public}s/%{public}s, startReason:%{public}d.",
        imeToStart->bundleName.c_str(), imeToStart->subName.c_str(), imeToStart->startReason);
    auto ret = StartIme(imeToStart, isStopCurrentIme);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to start ime!");
        InputMethodSysEvent::GetInstance().InputmethodFaultReporter(ret, imeToStart->imeId, "start ime failed!");
        return ret;
    }
    auto readyIme = GetRealImeData(true);
    if (readyIme == nullptr) {
        IMSA_HILOGE("ime abnormal.");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    NotifyImeChangedToClients();
    auto subName = readyIme->ime.first != imeToStart->bundleName ? "" : imeToStart->subName;
    NotifySubTypeChangedToIme(readyIme->ime.first, subName);
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::CanStartIme()
{
    return (IsSaReady(MEMORY_MANAGER_SA_ID) && IsWmsReady() &&
#ifdef IMF_SCREENLOCK_MGR_ENABLE
        IsSaReady(SCREENLOCK_SERVICE_ID) &&
#endif
        runningIme_.empty());
}

int32_t PerUserSession::ChangeToDefaultImeIfNeed(
    const std::shared_ptr<ImeNativeCfg> &targetIme, std::shared_ptr<ImeNativeCfg> &imeToStart)
{
#ifndef IMF_SCREENLOCK_MGR_ENABLE
    IMSA_HILOGD("no need");
    return ErrorCode::NO_ERROR;
#endif
    auto screenLockMgr = ScreenLock::ScreenLockManager::GetInstance();
    if (!IsDeviceLockAndScreenLocked()) {
        IMSA_HILOGD("no need");
        imeToStart = targetIme;
        return ErrorCode::NO_ERROR;
    }
    IMSA_HILOGI("Screen is locked, start default ime");
    auto defaultIme = ImeInfoInquirer::GetInstance().GetDefaultImeCfg();
    if (defaultIme == nullptr) {
        IMSA_HILOGE("failed to get default ime");
        return ErrorCode::ERROR_IMSA_DEFAULT_IME_NOT_FOUND;
    }
    if (defaultIme->bundleName == targetIme->bundleName) {
        IMSA_HILOGD("no need");
        imeToStart = targetIme;
        return ErrorCode::NO_ERROR;
    }
    imeToStart = defaultIme;
    ImeCfgManager::GetInstance().ModifyTempScreenLockImeCfg(userId_, imeToStart->imeId);
    return ErrorCode::NO_ERROR;
}

AAFwk::Want PerUserSession::GetWant(const std::shared_ptr<ImeNativeCfg> &ime)
{
    bool isolatedSandBox = true;
    EnabledStatus status = EnabledStatus::BASIC_MODE;
    AAFwk::Want want;
    if (ime == nullptr) {
        IMSA_HILOGE("ime is null");
        return want;
    }
    if (ImeEnabledInfoManager::GetInstance().IsDefaultFullMode(userId_, ime->bundleName)) {
        status = EnabledStatus::FULL_EXPERIENCE_MODE;
        isolatedSandBox = false;
    } else {
        auto ret = ImeEnabledInfoManager::GetInstance().GetEnabledState(userId_, ime->bundleName, status);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("%{public}d/%{public}s GetEnabledState failed.", userId_, ime->imeId.c_str());
        }
    }
    want.SetElementName(ime->bundleName, ime->extName);
    want.SetParam(STRICT_MODE, !(status == EnabledStatus::FULL_EXPERIENCE_MODE));
    want.SetParam(ISOLATED_SANDBOX, isolatedSandBox);
    auto defaultIme = ImeInfoInquirer::GetInstance().GetDefaultImeCfg();
    if (defaultIme != nullptr) {
        if (defaultIme->bundleName == ime->bundleName) {
            want.SetParam(SUB_NAME, ime->subName);
            IMSA_HILOGD("set param subName: %{public}s", ime->subName.c_str());
        }
    }
    IMSA_HILOGI("StartInputService userId: %{public}d, ime: %{public}s, mode: %{public}d, isolatedSandbox: %{public}d",
        userId_, ime->imeId.c_str(), static_cast<int32_t>(status), isolatedSandBox);
    return want;
}

int32_t PerUserSession::StartInputService(const std::shared_ptr<ImeNativeCfg> &ime)
{
    InputMethodSyncTrace tracer("StartInputService trace.");
    if (ime == nullptr) {
        return ErrorCode::ERROR_IMSA_IME_TO_START_NULLPTR;
    }
    IMSA_HILOGI("run in %{public}s", ime->imeId.c_str());
    auto imeToStart = std::make_shared<ImeNativeCfg>();
    auto ret = ChangeToDefaultImeIfNeed(ime, imeToStart);
    if (imeToStart == nullptr) {
        return ErrorCode::ERROR_IMSA_IME_TO_START_NULLPTR;
    }
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    InitRealImeData({ imeToStart->bundleName, imeToStart->extName }, ime);
    isImeStarted_.Clear(false);
    sptr<AAFwk::IAbilityConnection> connection = new (std::nothrow) ImeConnection();
    if (connection == nullptr) {
        IMSA_HILOGE("failed to create connection!");
        return ErrorCode::ERROR_IMSA_MALLOC_FAILED;
    }
    SetImeConnection(connection);
    auto want = GetWant(imeToStart);
    IMSA_HILOGI("connect %{public}s start!", imeToStart->imeId.c_str());
    ret = AAFwk::AbilityManagerClient::GetInstance()->ConnectExtensionAbility(want, connection, userId_);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("connect %{public}s failed, ret: %{public}d!", imeToStart->imeId.c_str(), ret);
        InputMethodSysEvent::GetInstance().InputmethodFaultReporter(
            ErrorCode::ERROR_IMSA_IME_CONNECT_FAILED, imeToStart->imeId, "failed to start ability.");
        SetImeConnection(nullptr);
        return ErrorCode::ERROR_IMSA_IME_CONNECT_FAILED;
    }
    if (!isImeStarted_.GetValue()) {
        IMSA_HILOGE("start %{public}s timeout!", imeToStart->imeId.c_str());
        return ErrorCode::ERROR_IMSA_IME_START_TIMEOUT;
    }
    IMSA_HILOGI("%{public}s started successfully.", imeToStart->imeId.c_str());
    if (ime->startReason != StartReason::RESTART_AFTER_DIED) {
        std::unordered_map<std::string, std::string> payload;
        payload["bundleName"] = imeToStart->bundleName;
        payload["abilityName"] = imeToStart->extName;
        ResourceSchedule::ResSchedClient::GetInstance().ReportData(
            ResourceSchedule::ResType::RES_TYPE_START_INPUT_METHOD_PROCESS, 0, payload);
    }
    InputMethodSysEvent::GetInstance().RecordEvent(IMEBehaviour::START_IME);
    return ErrorCode::NO_ERROR;
}

int64_t PerUserSession::GetCurrentClientPid(uint64_t displayId)
{
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        return INVALID_PID;
    }
    return clientGroup->GetCurrentClientPid();
}

int64_t PerUserSession::GetInactiveClientPid(uint64_t displayId)
{
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        return INVALID_PID;
    }
    return clientGroup->GetInactiveClientPid();
}

int32_t PerUserSession::OnPanelStatusChange(const InputWindowStatus &status, const ImeWindowInfo &info)
{
    return ImeEventListenerManager::GetInstance().NotifyPanelStatusChange(userId_, status, info);
}

int32_t PerUserSession::OnSetCallingWindow(const FocusedInfo &focusedInfo, sptr<IInputClient> client, uint32_t windowId)
{
    IMSA_HILOGD("OnSetCallingWindow enter");
    if (client == nullptr) {
        IMSA_HILOGE("nullptr client!");
        return ErrorCode::ERROR_CLIENT_NOT_FOCUSED;
    }
    auto clientGroup = GetClientGroup(client->AsObject());
    if (clientGroup == nullptr) {
        IMSA_HILOGE("clientGroup nullptr");
        return ErrorCode::ERROR_CLIENT_NOT_FOCUSED;
    }
    if (!IsSameClient(client, clientGroup->GetCurrentClient())) {
        IMSA_HILOGE("client is not current client!");
        return ErrorCode::ERROR_CLIENT_NOT_FOCUSED;
    }
    auto clientInfo = clientGroup->GetClientInfo(client->AsObject());
    if (clientInfo == nullptr) {
        IMSA_HILOGE("nullptr clientInfo!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    auto oldClientGroupId = clientInfo->clientGroupId;
    auto newClientGroupId = focusedInfo.displayGroupId;
    if (!IsSameClientGroup(oldClientGroupId, newClientGroupId)) {
        IMSA_HILOGW(
            "not same client group:%{public}" PRIu64 "/%{public}" PRIu64 ".", oldClientGroupId, newClientGroupId);
        return ErrorCode::NO_ERROR;
    }
    ImeEventListenerManager::GetInstance().NotifyInputStart(
        userId_, focusedInfo.windowId, newClientGroupId, static_cast<int32_t>(clientInfo->requestKeyboardReason));
    IMSA_HILOGD("windowId changed, refresh windowId info and notify clients input start.");
    HandleWindowIdChanged(focusedInfo, clientInfo, windowId);
    return ErrorCode::NO_ERROR;
}

void PerUserSession::HandleWindowIdChanged(
    const FocusedInfo &focusedInfo, const std::shared_ptr<InputClientInfo> &clientInfo, uint32_t windowId)
{
    if (clientInfo == nullptr) {
        IMSA_HILOGE("nullptr clientInfo!");
        return;
    }
    auto oldKeyboardGroupId = clientInfo->config.inputAttribute.displayGroupId;
    auto newKeyboardGroupId = focusedInfo.keyboardDisplayGroupId;
    if (!IsSameClientGroup(oldKeyboardGroupId, newKeyboardGroupId)) {
        IMSA_HILOGW("not same keyboard group:%{public}" PRIu64 "/%{public}" PRIu64 ".", oldKeyboardGroupId,
            newKeyboardGroupId);
        return;
    }
    clientInfo->config.privateCommand.insert_or_assign(
        "displayId", PrivateDataValue(static_cast<int32_t>(focusedInfo.displayId)));

    auto oldKeyboardDisplayId = clientInfo->config.inputAttribute.callingDisplayId;
    auto newKeyboardDisplayId = focusedInfo.keyboardDisplayId;
    clientInfo->config.windowId = windowId;
    clientInfo->config.inputAttribute.displayId = focusedInfo.displayId;
    clientInfo->config.inputAttribute.windowId = focusedInfo.keyboardWindowId;
    clientInfo->config.inputAttribute.callingDisplayId = newKeyboardDisplayId;
    NotifyCallingWindowIdChanged(windowId, GetImeData(clientInfo->bindImeData), focusedInfo.keyboardWindowId);
    if (oldKeyboardDisplayId != newKeyboardDisplayId) {
        NotifyCallingDisplayChanged(newKeyboardDisplayId, GetImeData(clientInfo->bindImeData));
    }
}

int32_t PerUserSession::GetInputStartInfo(
    uint64_t displayId, bool &isInputStart, uint32_t &callingWndId, int32_t &requestKeyboardReason)
{
    auto clientInfo = GetCurrentClientInfo(displayId);
    if (clientInfo == nullptr) {
        IMSA_HILOGE("nullptr clientInfo!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    isInputStart = true;
    callingWndId = clientInfo->config.windowId;
    requestKeyboardReason = static_cast<int32_t>(clientInfo->requestKeyboardReason);
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::IsSameIme(const std::shared_ptr<BindImeData> &oldIme, const std::shared_ptr<ImeData> &newIme)
{
    if (oldIme == nullptr) {
        return false;
    }
    if (newIme == nullptr) {
        return false;
    }
    return oldIme->pid == newIme->pid;
}

bool PerUserSession::IsShowSameRealImeInMainDisplayInMultiGroup(
    InputClientInfo &newClientInfo, const std::shared_ptr<InputClientInfo> &oldClientInfo)
{
    if (oldClientInfo == nullptr) {
        return false;
    }
    if (IsSameClientGroup(oldClientInfo->clientGroupId, newClientInfo.clientGroupId)) {
        IMSA_HILOGD("same group.");
        return false;
    }
    if (newClientInfo.bindImeData == nullptr) {
        return false;
    }
    if (oldClientInfo->bindImeData == nullptr) {
        return false;
    }
    if (newClientInfo.bindImeData->pid != oldClientInfo->bindImeData->pid || !newClientInfo.bindImeData->IsRealIme()) {
        return false;
    }
    return newClientInfo.config.inputAttribute.callingDisplayId == oldClientInfo->config.inputAttribute.callingDisplayId
           && oldClientInfo->config.inputAttribute.callingDisplayId == ImfCommonConst::DEFAULT_DISPLAY_ID;
}

bool PerUserSession::IsSameImeType(const std::shared_ptr<BindImeData> &oldIme, const std::shared_ptr<ImeData> &newIme)
{
    if (oldIme == nullptr) {
        return true;
    }
    if (newIme == nullptr) {
        return true;
    }
    return oldIme->type == newIme->type;
}

int32_t PerUserSession::SwitchSubtype(const SubProperty &subProperty)
{
    auto data = GetRealImeData(true);
    if (data == nullptr || data->core == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(data, RequestType::NORMAL, [&data, &subProperty] {
        return data->core->SetSubtype(subProperty);
    });
}

int32_t PerUserSession::SwitchSubtypeWithoutStartIme(const SubProperty &subProperty)
{
    auto data = GetRealImeData(true);
    if (data == nullptr || data->core == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist, or core is nullptr.", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(data, RequestType::NORMAL, [&data, &subProperty] {
        return data->core->SetSubtype(subProperty);
    });
}

int32_t PerUserSession::SetInputType()
{
    InputType inputType = InputTypeManager::GetInstance().GetCurrentInputType();
    auto data = GetRealImeData(true);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(data, RequestType::NORMAL, [&data, &inputType] {
        return data->core->OnSetInputType(static_cast<int32_t>(inputType));
    });
}

bool PerUserSession::IsBoundToClient(uint64_t displayId)
{
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("not in bound state!");
        return false;
    }
    if (clientGroup->GetCurrentClient() == nullptr) {
        IMSA_HILOGE("not in bound state!");
        return false;
    }
    return true;
}

int32_t PerUserSession::RestoreCurrentImeSubType()
{
    if (!InputTypeManager::GetInstance().IsStarted()) {
        IMSA_HILOGD("already exit.");
        return ErrorCode::NO_ERROR;
    }
    auto typeIme = InputTypeManager::GetInstance().GetCurrentIme();
    InputTypeManager::GetInstance().Set(false);
    auto imeData = GetRealImeData(true);
    if (imeData == nullptr) {
        IMSA_HILOGD("has no ready ime, not deal.");
        return ErrorCode::NO_ERROR;
    }
    if (imeData->ime.first != typeIme.bundleName) {
        IMSA_HILOGD("ready ime:%{public}s is not input type ime:%{public}s, not deal.", imeData->ime.first.c_str(),
            typeIme.bundleName.c_str());
        return ErrorCode::NO_ERROR;
    }
    auto defaultIme = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
    std::string subName;
    if (defaultIme != nullptr && imeData->ime.first == defaultIme->bundleName) {
        IMSA_HILOGD("readyIme is input type ime, same to default ime:%{public}s.", typeIme.bundleName.c_str());
        subName = defaultIme->subName;
    }
    IMSA_HILOGD("restore subtype: %{public}s/%{public}s.", imeData->ime.first.c_str(), subName.c_str());
    return NotifySubTypeChangedToIme(imeData->ime.first, subName);
}

bool PerUserSession::IsCurrentImeByPid(int32_t pid)
{
    auto imeData = GetRealImeData();
    if (imeData == nullptr) {
        IMSA_HILOGE("ime not started!");
        return false;
    }
    IMSA_HILOGD("userId: %{public}d, pid: %{public}d, current pid: %{public}d.", userId_, pid, imeData->pid);
    return imeData->pid == pid;
}

int32_t PerUserSession::IsPanelShown(uint64_t displayId, const PanelInfo &panelInfo, bool &isShown)
{
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo == nullptr) {
        IMSA_HILOGD("has no bind ime.");
        isShown = false;
        return ErrorCode::NO_ERROR;
    }
    if (clientInfo->config.inputAttribute.callingDisplayId != displayId) {
        IMSA_HILOGE("keyboard in displayId:%{public}" PRIu64 ", not in displayId:%{public}" PRIu64 ".",
            clientInfo->config.inputAttribute.callingDisplayId, displayId);
        isShown = false;
        return ErrorCode::NO_ERROR;
    }
    auto imeData = GetRealImeData(true);
    if (imeData == nullptr) {
        IMSA_HILOGD("has no ready real ime.");
        isShown = false;
        return ErrorCode::NO_ERROR;
    }
    return RequestIme(imeData, RequestType::NORMAL,
        [&imeData, &panelInfo, &isShown] { return imeData->core->IsPanelShown(panelInfo, isShown); });
}

int32_t PerUserSession::IsPanelShown(const PanelInfo &panelInfo, bool &isShown)
{
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo == nullptr) {
        IMSA_HILOGD("has no bind ime.");
        isShown = false;
        return ErrorCode::NO_ERROR;
    }
    if (clientInfo->config.inputAttribute.displayGroupId != ImfCommonConst::DEFAULT_DISPLAY_GROUP_ID) {
        IMSA_HILOGE("keyboard in displayGroupId:%{public}" PRIu64 ", not in default displayGroup.",
            clientInfo->config.inputAttribute.callingDisplayId);
        isShown = false;
        return ErrorCode::NO_ERROR;
    }
    auto imeData = GetRealImeData(true);
    if (imeData == nullptr) {
        IMSA_HILOGD("has no ready real ime.");
        isShown = false;
        return ErrorCode::NO_ERROR;
    }
    return RequestIme(imeData, RequestType::NORMAL,
        [&imeData, &panelInfo, &isShown] { return imeData->core->IsPanelShown(panelInfo, isShown); });
}

int32_t PerUserSession::RequestIme(const std::shared_ptr<ImeData> &data, RequestType type, const IpcExec &exec)
{
    if (data == nullptr || data->core == nullptr || data->imeStateManager == nullptr) {
        IMSA_HILOGE("data is nullptr!");
        return ErrorCode::NO_ERROR;
    }
    if (!data->IsRealIme()) {
        IMSA_HILOGD("proxy enable.");
        return exec();
    }
    if (!data->imeStateManager->IsIpcNeeded(type)) {
        IMSA_HILOGD("no need to request, type: %{public}d.", type);
        return ErrorCode::NO_ERROR;
    }
    data->imeStateManager->BeforeIpc(type);
    auto ret = exec();
    data->imeStateManager->AfterIpc(type, ret == ErrorCode::NO_ERROR);
    return ret;
}

int32_t PerUserSession::RequestAllIme(
    const std::shared_ptr<ImeData> &data, RequestType reqType, const CoreMethod &method, uint64_t groupId)
{
    if (data == nullptr) {
        IMSA_HILOGW("no need to request, type:%{public}d}", reqType);
        return ErrorCode::NO_ERROR;
    }

    std::vector<std::shared_ptr<ImeData>> dataArray = { data };

    if (!data->IsImeMirror() && IsDefaultGroup(groupId)) {
        auto mirrorIme = GetMirrorImeData();
        if (mirrorIme != nullptr) {
            dataArray.push_back(mirrorIme);
        }
    }

    int32_t finalResult = ErrorCode::NO_ERROR;
    for (const auto &dataItem : dataArray) {
        int32_t ret = RequestIme(dataItem, reqType, [&dataItem, &method]() {
            return method(dataItem->core); // Execute the specified core method
        });
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE(
                "request ime failed, ret: %{public}d, IsImeMirror:%{public}d", ret, dataItem->IsImeMirror());
        }
        // IME_MIRROR not effect overall result
        if (!dataItem->IsImeMirror()) {
            finalResult = ret;
        }
    }
    return finalResult;
}

int32_t PerUserSession::OnConnectSystemCmd(const sptr<IRemoteObject> &channel, sptr<IRemoteObject> &agent)
{
    auto imeData = GetRealImeData(true);
    if (imeData == nullptr || imeData->agent == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    agent = imeData->agent;
    auto ret = RequestIme(imeData, RequestType::NORMAL, [&imeData, &channel] {
        return imeData->core->OnConnectSystemCmd(channel);
    });
    IMSA_HILOGD("on connect systemCmd, ret: %{public}d.", ret);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("bind failed, ret: %{public}d!", ret);
        return ret;
    }
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::WaitForCurrentImeStop()
{
    IMSA_HILOGI("start.");
    std::unique_lock<std::mutex> lock(imeStopMutex_);
    isSwitching_.store(true);
    return imeStopCv_.wait_for(lock, std::chrono::milliseconds(STOP_IME_TIME), [this]() { return !isSwitching_; });
}

void PerUserSession::NotifyImeStopFinished()
{
    IMSA_HILOGI("start.");
    std::unique_lock<std::mutex> lock(imeStopMutex_);
    isSwitching_.store(false);
    imeStopCv_.notify_one();
}

int32_t PerUserSession::RemoveAllCurrentClient()
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    if (clientGroupMap_.empty()) {
        IMSA_HILOGI("no current client");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    for (const auto &clientGroup : clientGroupMap_) {
        auto clientGroupObject = clientGroup.second;
        if (clientGroupObject == nullptr) {
            continue;
        }
        ImeEventListenerManager::GetInstance().NotifyInputStop(userId_, clientGroupObject->GetDisplayGroupId());
        DetachOptions options = { .sessionId = 0, .isUnbindFromClient = false };
        RemoveClient(clientGroupObject->GetCurrentClient(), clientGroupObject, options);
    }
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::IsWmsReady()
{
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        IMSA_HILOGD("scb enable");
        return WmsConnectionObserver::IsWmsConnected(userId_);
    }
    return IsSaReady(WINDOW_MANAGER_SERVICE_ID);
}

bool PerUserSession::IsSaReady(int32_t saId)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        IMSA_HILOGE("get saMgr failed!");
        return false;
    }
    if (saMgr->CheckSystemAbility(saId) == nullptr) {
        IMSA_HILOGE("sa:%{public}d not ready!", saId);
        return false;
    }
    return true;
}

void PerUserSession::AddRestartIme()
{
    int32_t tasks = 0;
    {
        std::lock_guard<std::mutex> lock(restartMutex_);
        if (restartTasks_ >= MAX_RESTART_TASKS) {
            return;
        }
        restartTasks_ = std::max(restartTasks_, 0);
        tasks = ++restartTasks_;
    }
    if (tasks == 1 && !RestartIme()) {
        std::lock_guard<std::mutex> lock(restartMutex_);
        restartTasks_ = 0;
    }
}

bool PerUserSession::IsAttachFinished()
{
    static uint32_t waitAttachTimes = 0;
    if (GetAttachCount() != 0 && waitAttachTimes < WAIT_ATTACH_FINISH_MAX_TIMES) {
        IMSA_HILOGI("wait for attach finish");
        waitAttachTimes++;
        return false;
    }
    waitAttachTimes = 0;
    return true;
}

void PerUserSession::IncreaseScbStartCount()
{
    std::lock_guard<std::mutex> lock(scbStartCountMtx_);
    scbStartCount_ = std::min(scbStartCount_ + 1, MAX_SCB_START_COUNT);
    IMSA_HILOGI("scb start count: %{public}u", scbStartCount_);
}

uint32_t PerUserSession::GetScbStartCount()
{
    std::lock_guard<std::mutex> lock(scbStartCountMtx_);
    return scbStartCount_;
}

void PerUserSession::ResetRestartTasks()
{
    std::lock_guard<std::mutex> lock(restartMutex_);
    restartTasks_ = 0;
}

bool PerUserSession::RestartIme()
{
    static int32_t delayTime = 0;
    IMSA_HILOGD("enter");
    auto task = [this]() {
        // When the attach conflict with the first scb startup event, discard the first scb startup event.
        if (GetAttachCount() != 0 && GetScbStartCount() <= 1) {
            IMSA_HILOGI("attach conflict with the first scb startup event, discard the first scb startup event");
            ResetRestartTasks();
            return;
        }
        if (!IsAttachFinished()) {
            delayTime = WAIT_ATTACH_FINISH_DELAY;
            RestartIme();
            return;
        }
        delayTime = 0;
        if (CanStartIme()) {
            IMSA_HILOGI("start ime");
            ResetRestartTasks();
            auto ret = StartCurrentIme(true);
            if (ret != ErrorCode::NO_ERROR) {
                IMSA_HILOGE("start ime failed:%{public}d", ret);
            }
        }
        IMSA_HILOGD("restart again");
        int32_t tasks = 0;
        {
            std::lock_guard<std::mutex> lock(restartMutex_);
            tasks = --restartTasks_;
        }
        if (tasks > 0 && !RestartIme()) {
            ResetRestartTasks();
        }
    };
    if (eventHandler_ == nullptr) {
        IMSA_HILOGE("eventHandler_ is nullptr!");
        return false;
    }
    return eventHandler_->PostTask(
        task, "RestartCurrentImeTask", delayTime, AppExecFwk::EventQueue::Priority::IMMEDIATE);
}

BlockQueue<SwitchInfo>& PerUserSession::GetSwitchQueue()
{
    return switchQueue_;
}

int32_t PerUserSession::InitRealImeData(
    const std::pair<std::string, std::string> &ime, const std::shared_ptr<ImeNativeCfg> &imeNativeCfg)
{
    std::lock_guard<std::mutex> lock(realImeDataLock_);
    if (realImeData_ != nullptr) {
        return ErrorCode::NO_ERROR;
    }
    realImeData_ = std::make_shared<ImeData>(nullptr, nullptr, nullptr, -1);
#ifdef IMF_SCREENLOCK_MGR_ENABLE
    realImeData_->isStartedInScreenLocked = IsDeviceLockAndScreenLocked();
#endif
    realImeData_->type = ImeType::IME;
    realImeData_->startTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    realImeData_->ime = ime;
    realImeData_->imeStateManager =
        ImeStateManagerFactory::GetInstance().CreateImeStateManager(-1, [this] { StopCurrentIme(); });
    if (imeNativeCfg != nullptr && !imeNativeCfg->imeExtendInfo.privateCommand.empty()) {
        realImeData_->imeExtendInfo.privateCommand = imeNativeCfg->imeExtendInfo.privateCommand;
    }
    return ErrorCode::NO_ERROR;
}

std::shared_ptr<ImeData> PerUserSession::UpdateRealImeData(
    sptr<IInputMethodCore> core, sptr<IRemoteObject> agent, pid_t pid)
{
    if (core == nullptr || agent == nullptr) {
        IMSA_HILOGE("core or agent is nullptr!");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(realImeDataLock_);
    if (realImeData_ == nullptr) {
        return nullptr;
    }
    auto ret = FillImeData(core, agent, pid, ImeType::IME, realImeData_);
    if (ret != ErrorCode::NO_ERROR) {
        return nullptr;
    }
    if (realImeData_->imeStateManager != nullptr && IsImeStartedForeground()) {
        realImeData_->imeStateManager->ReportQos(false, pid);
    }
    return realImeData_;
}

std::shared_ptr<ImeData> PerUserSession::GetRealImeData(pid_t pid)
{
    std::lock_guard<std::mutex> lock(realImeDataLock_);
    if (realImeData_ == nullptr || realImeData_->pid != pid) {
        return nullptr;
    }
    return realImeData_;
}

std::shared_ptr<ImeData> PerUserSession::GetMirrorImeData(pid_t pid)
{
    std::lock_guard<std::mutex> lock(mirrorImeDataLock_);
    if (mirrorImeData_ == nullptr || mirrorImeData_->pid != pid) {
        return nullptr;
    }
    return mirrorImeData_;
}

std::shared_ptr<ImeData> PerUserSession::GetMirrorImeData()
{
    std::lock_guard<std::mutex> lock(mirrorImeDataLock_);
    return mirrorImeData_;
}

int32_t PerUserSession::FillImeData(
    sptr<IInputMethodCore> core, sptr<IRemoteObject> agent, pid_t pid, ImeType type, std::shared_ptr<ImeData> &imeData)
{
    if (core == nullptr || agent == nullptr || imeData == nullptr) {
        IMSA_HILOGE("core or agent is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    if (type != ImeType::IME) {
        imeData->imeStatus = ImeStatus::READY;
    }
    imeData->type = type;
    imeData->core = core;
    imeData->agent = agent;
    imeData->pid = pid;
    imeData->uid = IPCSkeleton::GetCallingUid();
    imeData->imeStateManager =
        ImeStateManagerFactory::GetInstance().CreateImeStateManager(pid, [this] { StopCurrentIme(); });
    sptr<InputDeathRecipient> deathRecipient = new (std::nothrow) InputDeathRecipient();
    if (deathRecipient == nullptr) {
        IMSA_HILOGE("failed to new deathRecipient!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    deathRecipient->SetDeathRecipient(
        [this, core, type, pid](const wptr<IRemoteObject> &) { this->OnImeDied(core, type, pid); });
    auto coreObject = core->AsObject();
    if (coreObject == nullptr || (coreObject->IsProxyObject() && !coreObject->AddDeathRecipient(deathRecipient))) {
        IMSA_HILOGE("failed to add death recipient!");
        return ErrorCode::ERROR_ADD_DEATH_RECIPIENT_FAILED;
    }
    imeData->deathRecipient = deathRecipient;
    if (type == ImeType::IME_MIRROR) {
        imeData->ime.first = IME_MIRROR_NAME;
    }
    if (type == ImeType::PROXY_IME) {
        imeData->ime.first = PROXY_IME_NAME;
    }
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::IsImeStartedForeground()
{
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo != nullptr && clientInfo->isShowKeyboard) {
        IMSA_HILOGI("ime restart with keyboard front end");
        return true;
    } else if (clientInfo == nullptr && isNeedReportQos_) {
        IMSA_HILOGI("sa start with keyboard front end");
        return true;
    }
    return false;
}

int32_t PerUserSession::InitConnect(pid_t pid)
{
    std::lock_guard<std::mutex> lock(realImeDataLock_);
    if (realImeData_ == nullptr) {
        return ErrorCode::ERROR_NULL_POINTER;
    }
    if (realImeData_->imeStateManager != nullptr && IsImeStartedForeground()) {
        realImeData_->imeStateManager->ReportQos(true, pid);
    }
    realImeData_->pid = pid;
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::StartIme(const std::shared_ptr<ImeNativeCfg> &ime, bool isStopCurrentIme)
{
    std::unique_lock<std::mutex> lock(imeStartLock_, std::defer_lock);
    if (!lock.try_lock()) {
        IMSA_HILOGW("try_lock failed!");
        return ErrorCode::ERROR_TRY_IME_START_FAILED;
    }
    if (ime == nullptr) {
        return ErrorCode::ERROR_IMSA_IME_TO_START_NULLPTR;
    }
    auto imeData = GetRealImeData();
    if (imeData == nullptr) {
        return HandleFirstStart(ime, isStopCurrentIme);
    }
    if (imeData->ime.first == ime->bundleName && imeData->ime.second == ime->extName) {
        if (isStopCurrentIme) {
            return StartNewIme(ime);
        }
        return StartCurrentIme(ime);
    }
    IMSA_HILOGD("%{public}s switch to %{public}s!", imeData->ime.first.c_str(), ime->bundleName.c_str());
    return StartNewIme(ime);
}

ImeAction PerUserSession::GetImeAction(ImeEvent action)
{
    std::lock_guard<std::mutex> lock(realImeDataLock_);
    if (realImeData_ == nullptr) {
        return ImeAction::DO_ACTION_IN_NULL_IME_DATA;
    }
    auto iter = imeEventConverter_.find({ realImeData_->imeStatus, action });
    if (iter == imeEventConverter_.end()) {
        IMSA_HILOGE("abnormal!");
        return ImeAction::DO_ACTION_IN_IME_EVENT_CONVERT_FAILED;
    }
    realImeData_->imeStatus = iter->second.first;
    return iter->second.second;
}

int32_t PerUserSession::StartCurrentIme(const std::shared_ptr<ImeNativeCfg> &ime)
{
    auto imeData = GetRealImeData();
    if (imeData == nullptr) {
        return StartInputService(ime);
    }
    auto action = GetImeAction(ImeEvent::START_IME);
    if (action == ImeAction::DO_ACTION_IN_IME_EVENT_CONVERT_FAILED) {
        return ErrorCode::ERROR_IMSA_IME_EVENT_CONVERT_FAILED;
    }
    if (action == ImeAction::DO_ACTION_IN_NULL_IME_DATA) {
        return StartInputService(ime);
    }
    if (action == ImeAction::DO_NOTHING) {
        return ErrorCode::NO_ERROR;
    }
    if (action == ImeAction::HANDLE_STARTING_IME) {
        int64_t time = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        if (time - imeData->startTime > ImeData::START_TIME_OUT) {
            IMSA_HILOGE("[%{public}s, %{public}s] start abnormal, more than eight second!", imeData->ime.first.c_str(),
                imeData->ime.second.c_str());
            return HandleStartImeTimeout(ime);
        }
        IMSA_HILOGW("%{public}s/%{public}s start retry!", imeData->ime.first.c_str(), imeData->ime.second.c_str());
        return StartInputService(ime);
    }
    IMSA_HILOGW("%{public}s/%{public}s start in exiting, force stop firstly!", imeData->ime.first.c_str(),
        imeData->ime.second.c_str());
    auto ret = ForceStopCurrentIme();
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    return StartInputService(ime);
}

int32_t PerUserSession::HandleStartImeTimeout(const std::shared_ptr<ImeNativeCfg> &ime)
{
    auto action = GetImeAction(ImeEvent::START_IME_TIMEOUT);
    if (action == ImeAction::DO_ACTION_IN_NULL_IME_DATA) {
        return StartInputService(ime);
    }
    if (action == ImeAction::DO_ACTION_IN_IME_EVENT_CONVERT_FAILED) {
        return ErrorCode::ERROR_IMSA_IME_EVENT_CONVERT_FAILED;
    }
    if (action == ImeAction::DO_NOTHING) {
        IMSA_HILOGW("ready when timeout");
        return ErrorCode::NO_ERROR;
    }
    auto ret = ForceStopCurrentIme(false);
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    return StartInputService(ime);
}

int32_t PerUserSession::StartNewIme(const std::shared_ptr<ImeNativeCfg> &ime)
{
    auto ret = StopCurrentIme();
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    return StartInputService(ime);
}

int32_t PerUserSession::StopCurrentIme()
{
    IMSA_HILOGD("enter");
    auto action = GetImeAction(ImeEvent::STOP_IME);
    if (action == ImeAction::DO_ACTION_IN_NULL_IME_DATA) {
        return ErrorCode::NO_ERROR;
    }
    if (action == ImeAction::DO_ACTION_IN_IME_EVENT_CONVERT_FAILED) {
        return  ErrorCode::ERROR_IMSA_IME_EVENT_CONVERT_FAILED;
    }
    if (action == ImeAction::STOP_READY_IME) {
        return StopReadyCurrentIme();
    }
    return ForceStopCurrentIme();
}

int32_t PerUserSession::StopReadyCurrentIme()
{
    uint64_t groupId = ImfCommonConst::NOT_DEFAULT_DISPLAY_GROUP_ID;
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo != nullptr) {
        groupId = clientInfo->clientGroupId;
        StopClientInput(clientInfo);
    }
    auto imeData = GetRealImeData();
    if (imeData == nullptr) {
        return ErrorCode::NO_ERROR;
    }
    if (imeData->core == nullptr) {
        IMSA_HILOGE("core is nullptr!");
        return ForceStopCurrentIme();
    }
    auto ret = RequestAllIme(imeData, RequestType::NORMAL, [](const sptr<IInputMethodCore> &core) {
        // failed when register onInputStop after SetCoreAndAgent
        return core->StopInputService(true);
    }, groupId);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("StopInputService failed.");
        return ForceStopCurrentIme();
    }
    if (!WaitForCurrentImeStop()) {
        IMSA_HILOGI("stop timeout.");
        return ForceStopCurrentIme();
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::ForceStopCurrentIme(bool isNeedWait)
{
    auto imeData = GetRealImeData();
    if (imeData == nullptr) {
        return ErrorCode::NO_ERROR;
    }
    if (!ImeInfoInquirer::GetInstance().IsRunningIme(userId_, imeData->ime.first)) {
        IMSA_HILOGW("[%{public}s, %{public}s] already stop.", imeData->ime.first.c_str(), imeData->ime.second.c_str());
        RemoveRealImeData();
        return ErrorCode::NO_ERROR;
    }
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo != nullptr) {
        StopClientInput(clientInfo);
    }

    AAFwk::Want want;
    want.SetElementName(imeData->ime.first, imeData->ime.second);
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->StopExtensionAbility(
        want, nullptr, userId_, AppExecFwk::ExtensionAbilityType::INPUTMETHOD);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("StopExtensionAbility [%{public}s, %{public}s] failed, ret: %{public}d!",
            imeData->ime.first.c_str(), imeData->ime.second.c_str(), ret);
        return ErrorCode::ERROR_IMSA_IME_DISCONNECT_FAILED;
    }
    if (!isNeedWait) {
        return ErrorCode::ERROR_IMSA_IME_START_MORE_THAN_EIGHT_SECOND;
    }
    WaitForCurrentImeStop();
    if (ImeInfoInquirer::GetInstance().IsRunningIme(userId_, imeData->ime.first)) {
        IMSA_HILOGW("stop [%{public}s, %{public}s] timeout.", imeData->ime.first.c_str(), imeData->ime.second.c_str());
        return ErrorCode::ERROR_IMSA_FORCE_STOP_IME_TIMEOUT;
    }
    RemoveRealImeData();
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::HandleFirstStart(const std::shared_ptr<ImeNativeCfg> &ime, bool isStopCurrentIme)
{
    if (runningIme_.empty()) {
        return StartInputService(ime);
    }
    IMSA_HILOGW("imsa abnormal restore.");
    if (isStopCurrentIme) {
        return ErrorCode::NO_ERROR;
    }
    if (BlockRetry(CHECK_IME_RUNNING_RETRY_INTERVAL, CHECK_IME_RUNNING_RETRY_TIMES,
                   [this]() -> bool { return !ImeInfoInquirer::GetInstance().IsRunningIme(userId_, runningIme_); })) {
        IMSA_HILOGI("[%{public}d, %{public}s] stop completely", userId_, runningIme_.c_str());
        runningIme_.clear();
        return StartInputService(ime);
    }
    IMSA_HILOGW("[%{public}d, %{public}s] stop timeout", userId_, runningIme_.c_str());
    return ErrorCode::ERROR_IMSA_REBOOT_OLD_IME_NOT_STOP;
}

int32_t PerUserSession::StartUserSpecifiedIme()
{
    InputMethodSyncTrace tracer("StartUserSpecifiedIme trace.");
    InputTypeManager::GetInstance().Set(false);
    auto cfgIme = ImeInfoInquirer::GetInstance().GetImeToStart(userId_);
    auto imeData = GetRealImeData(true);
    if (imeData != nullptr && cfgIme != nullptr && imeData->ime.first == cfgIme->bundleName
        && imeData->ime.second == cfgIme->extName) {
        return ErrorCode::NO_ERROR;
    }
    IMSA_HILOGD("need restore!");
    auto ret = StartIme(cfgIme);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("start ime failed!");
        return ret;
    }
    NotifyImeChangedToClients();
    cfgIme = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
    if (cfgIme != nullptr) {
        NotifySubTypeChangedToIme(cfgIme->bundleName, cfgIme->subName);
    }
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::CheckPwdInputPatternConv(InputClientInfo &clientInfo, uint64_t displayId)
{
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        IMSA_HILOGD("clientGroup not found");
        return false;
    }
    auto exClient = clientGroup->GetCurrentClient();
    if (exClient == nullptr) {
        exClient = clientGroup->GetInactiveClient();
    }
    auto exClientInfo = exClient != nullptr ? clientGroup->GetClientInfo(exClient->AsObject()) : nullptr;
    if (exClientInfo == nullptr) {
        IMSA_HILOGE("exClientInfo is nullptr!");
        return false;
    }
    // if current input pattern differ from previous in pwd and normal, need hide panel first.
    if (clientInfo.config.inputAttribute.GetSecurityFlag()) {
        IMSA_HILOGD("new input pattern is pwd.");
        return !exClientInfo->config.inputAttribute.GetSecurityFlag();
    }
    IMSA_HILOGD("new input pattern is normal.");
    return exClientInfo->config.inputAttribute.GetSecurityFlag();
}

std::shared_ptr<ImeNativeCfg> PerUserSession::GetImeNativeCfg(int32_t userId, const std::string &bundleName,
    const std::string &subName)
{
    auto targetImeProperty = ImeInfoInquirer::GetInstance().GetImeProperty(userId, bundleName);
    if (targetImeProperty == nullptr) {
        IMSA_HILOGE("GetImeProperty [%{public}d, %{public}s] failed!", userId, bundleName.c_str());
        return nullptr;
    }
    std::string targetName = bundleName + "/" + targetImeProperty->id;
    ImeNativeCfg targetIme = { targetName, bundleName, subName, targetImeProperty->id };
    return std::make_shared<ImeNativeCfg>(targetIme);
}

bool PerUserSession::GetInputTypeToStart(std::shared_ptr<ImeNativeCfg> &imeToStart)
{
    if (!InputTypeManager::GetInstance().IsStarted()) {
        return false;
    }
    auto currentInputTypeIme = InputTypeManager::GetInstance().GetCurrentIme();
    if (currentInputTypeIme.bundleName.empty()) {
        auto currentInputType = InputTypeManager::GetInstance().GetCurrentInputType();
        InputTypeManager::GetInstance().GetImeByInputType(currentInputType, currentInputTypeIme);
    }
    imeToStart = GetImeNativeCfg(userId_, currentInputTypeIme.bundleName, currentInputTypeIme.subName);
    return true;
}

void PerUserSession::HandleBindImeChanged(InputClientInfo &newClientInfo, const std::shared_ptr<ImeData> &newImeData,
    const std::shared_ptr<ClientGroup> &clientGroup)
{
    if (newImeData == nullptr || newImeData->IsImeMirror()) {
        return;
    }
    /* isClientInactive: true: represent the oldClientInfo is inactiveClient's
                         false: represent the oldClientInfo is currentClient's */

    std::shared_ptr<InputClientInfo> oldClientInfo = nullptr;
    if (clientGroup == nullptr) {
        IMSA_HILOGE("clientGroup is nullptr!");
        return;
    }
    bool isClientInactive = false;
    {
        // The following operations ensure timing sequence of HandleBindImeChanged and OnFocused
        std::lock_guard<std::mutex> lock(focusedClientLock_);
        oldClientInfo = clientGroup->GetCurrentClientInfo();
        if (oldClientInfo == nullptr) {
            auto inactiveClient = clientGroup->GetInactiveClient();
            if (inactiveClient != nullptr) {
                oldClientInfo = clientGroup->GetClientInfo(inactiveClient->AsObject());
                isClientInactive = true;
            }
        }
        if (oldClientInfo == nullptr) {
            return;
        }
        if (IsSameIme(oldClientInfo->bindImeData, newImeData)) {
            IMSA_HILOGD("ime not changed, return!");
            return;
        }
        if (IsSameClient(newClientInfo.client, oldClientInfo->client)) {
            IMSA_HILOGD("same client, ime changed!");
            newClientInfo.isNotifyInputStart = true;
        }
        if (IsSameImeType(oldClientInfo->bindImeData, newImeData) && newImeData->IsRealIme()) {
            IMSA_HILOGD("real ime switch, return!");
            return;
        }
        // has current client, but new client is not current client
        if (!isClientInactive && !IsSameClient(newClientInfo.client, oldClientInfo->client)) {
            clientGroup->SetCurrentClient(nullptr);
            if (oldClientInfo->client != nullptr) {
                clientGroup->RemoveClientInfo(oldClientInfo->client->AsObject());
            }
        }
    }
    IMSA_HILOGD("isClientInactive: %{public}d!", isClientInactive);
    if (isClientInactive) {
        StopImeInput(GetImeData(oldClientInfo->bindImeData), oldClientInfo, 0);
        return;
    }
    UnBindClientWithIme(oldClientInfo, { .sessionId = 0 });
}

void PerUserSession::TryUnloadSystemAbility()
{
    auto data = GetRealImeData(true);
    if (data != nullptr && data->imeStateManager != nullptr) {
        if (data->imeStateManager->IsImeInUse()) {
            return;
        }
    }

    auto onDemandStartStopSa = std::make_shared<OnDemandStartStopSa>();
    onDemandStartStopSa->UnloadInputMethodSystemAbility();
}

std::shared_ptr<ClientGroup> PerUserSession::GetClientGroup(uint64_t displayId)
{
    auto clientGroupId = WindowAdapter::GetInstance().GetDisplayGroupId(displayId);
    return GetClientGroupByGroupId(clientGroupId);
}

std::shared_ptr<ClientGroup> PerUserSession::GetClientGroupByGroupId(uint64_t clientGroupId)
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    auto iter = clientGroupMap_.find(clientGroupId);
    if (iter == clientGroupMap_.end()) {
        IMSA_HILOGD("not found client group with displayId: %{public}" PRIu64 "", clientGroupId);
        return nullptr;
    }
    return iter->second;
}

std::shared_ptr<ClientGroup> PerUserSession::GetClientGroup(sptr<IRemoteObject> client)
{
    if (client == nullptr) {
        IMSA_HILOGE("client is nullptr");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    auto iter = std::find_if(clientGroupMap_.begin(), clientGroupMap_.end(), [client](const auto &clientGroup) {
        if (clientGroup.second == nullptr) {
            return false;
        }
        return clientGroup.second->IsClientExist(client);
    });
    if (iter == clientGroupMap_.end()) {
        IMSA_HILOGD("not found");
        return nullptr;
    }
    return iter->second;
}

void PerUserSession::OnCallingDisplayIdChanged(
    const int32_t windowId, const int32_t callingPid, const uint64_t displayId)
{
    IMSA_HILOGD("enter!windowId:%{public}d,callingPid:%{public}d,displayId:%{public}" PRIu64 "", windowId, callingPid,
        displayId);
    auto [clientGroup, clientInfo] = GetClientBoundImeByWindowId(windowId);
    if (clientGroup == nullptr || clientInfo == nullptr) {
        IMSA_HILOGD("not window keyboard in changed:%{public}d.", windowId);
        return;
    }
    auto oldClientGroupId = clientInfo->clientGroupId;
    auto newClientGroupId = WindowAdapter::GetInstance().GetDisplayGroupId(displayId);
    // Cross-group scenarios are handled by the attach.
    if (!IsSameClientGroup(oldClientGroupId, newClientGroupId)) {
        IMSA_HILOGW(
            "not same client group:%{public}" PRIu64 "/%{public}" PRIu64 ".", oldClientGroupId, newClientGroupId);
        return;
    }
    auto oldKeyboardGroupId = clientInfo->config.inputAttribute.displayGroupId;
    auto newKeyboardDisplayId = displayId;
    auto newKeyboardGroupId = WindowAdapter::GetInstance().GetDisplayGroupId(newKeyboardDisplayId);
    // Cross-group scenarios are handled by the attach.
    if (!IsSameClientGroup(oldKeyboardGroupId, newKeyboardGroupId)) {
        IMSA_HILOGW("not same keyboard group:%{public}" PRIu64 "/%{public}" PRIu64 ".", oldKeyboardGroupId,
            newKeyboardGroupId);
        return;
    }
    clientInfo->config.inputAttribute.displayId = displayId;
    auto oldKeyboardDisplayId = clientInfo->config.inputAttribute.callingDisplayId;
    clientInfo->config.inputAttribute.callingDisplayId = newKeyboardDisplayId;
    if (newKeyboardDisplayId == oldKeyboardDisplayId) {
        IMSA_HILOGD("same, no need to deal.");
        return;
    }
    NotifyCallingDisplayChanged(newKeyboardDisplayId, GetImeData(clientInfo->bindImeData));
}

int32_t PerUserSession::NotifyCallingDisplayChanged(uint64_t displayId, const std::shared_ptr<ImeData> &imeData)
{
    IMSA_HILOGD("enter displayId:%{public}" PRIu64 "", displayId);
    if (imeData == nullptr || !imeData->IsRealIme()) {
        IMSA_HILOGD("bind ime not real ime");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto callBack = [&imeData, displayId]() -> int32_t {
        imeData->core->OnCallingDisplayIdChanged(displayId);
        return ErrorCode::NO_ERROR;
    };
    auto ret = RequestIme(imeData, RequestType::NORMAL, callBack);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("notify calling window display changed failed, ret: %{public}d!", ret);
    }
    return ret;
}

int32_t PerUserSession::NotifyCallingWindowIdChanged(
    uint32_t editorWindowId, const std::shared_ptr<ImeData> &imeData, uint32_t keyboardWindowId)
{
    IMSA_HILOGD("enter editorWindowId/keyboardWindowId:%{public}u/%{public}u.", editorWindowId, keyboardWindowId);
    if (imeData == nullptr || !imeData->IsRealIme()) {
        IMSA_HILOGD("bind ime not real ime");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto callBack = [&imeData, editorWindowId, keyboardWindowId]() -> int32_t {
        imeData->core->OnCallingWindowIdChanged(editorWindowId, keyboardWindowId);
        return ErrorCode::NO_ERROR;
    };
    auto ret = RequestIme(imeData, RequestType::NORMAL, callBack);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("notify calling window display changed failed, ret: %{public}d!", ret);
    }
    return ret;
}

bool PerUserSession::SpecialScenarioCheck()
{
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo == nullptr) {
        IMSA_HILOGE("send failed, not input Status!");
        return false;
    }
    if (clientInfo->config.isSimpleKeyboardEnabled) {
        IMSA_HILOGE("send failed, is simple keyboard!");
        return false;
    }
    if (clientInfo->config.inputAttribute.IsSecurityImeFlag() ||
        clientInfo->config.inputAttribute.IsOneTimeCodeFlag()) {
        IMSA_HILOGE("send failed, is special input box!");
        return false;
    }
    if (IsDeviceLockAndScreenLocked()) {
        IMSA_HILOGE("send failed, is screen locked");
        return false;
    }
    return true;
}

int32_t PerUserSession::SpecialSendPrivateData(const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    ImeExtendInfo imeExtendInfo;
    imeExtendInfo.privateCommand = privateCommand;
    auto [ret, status] = StartPreconfiguredDefaultIme(imeExtendInfo, true);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("start pre default ime failed, ret: %{public}d!", ret);
        return ret;
    }
    if (status == StartPreDefaultImeStatus::NO_NEED || status == StartPreDefaultImeStatus::TO_START) {
        return ret;
    }
    ret = SendPrivateData(privateCommand);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("Notify send private data failed, ret: %{public}d!", ret);
    }
    return ret;
}

int32_t PerUserSession::SendPrivateData(const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    auto data = GetRealImeData(true);
    if (data == nullptr) {
        IMSA_HILOGE("data is nullptr");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::NORMAL, [&data, &privateCommand] {
        Value value(privateCommand);
        return data->core->OnSendPrivateData(value);
    });
    if (!data->imeExtendInfo.privateCommand.empty()) {
        data->imeExtendInfo.privateCommand.clear();
    }
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("notify send private data failed, ret: %{public}d!", ret);
        return ret;
    }
    IMSA_HILOGI("notify send private data success.");
    return ret;
}

int32_t PerUserSession::SendVoicePrivateCommand(const bool isPersistence)
{
    auto data = GetRealImeData(true);
    if (data == nullptr) {
        IMSA_HILOGE("data is nullptr");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    ImeIdentification ime;
    InputTypeManager::GetInstance().GetImeByInputType(InputType::VOICEKB_INPUT, ime);
    std::unordered_map<std::string, PrivateDataValue> privateCommand
        = { {"sys_cmd", 1}, {"subName", ime.subName} };
    auto ret = RequestIme(data, RequestType::NORMAL, [&data, &privateCommand] {
        Value value(privateCommand);
        return data->core->OnSendPrivateData(value);
    });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("send voice private command failed, ret: %{public}d!", ret);
        return ret;
    }
    IMSA_HILOGI("send voice private command success.");
    return ret;
}

void PerUserSession::ClearRequestKeyboardReason(std::shared_ptr<InputClientInfo> &clientInfo)
{
    if (clientInfo == nullptr) {
        IMSA_HILOGE("clientGroup is nullptr!");
        return;
    }
    clientInfo->requestKeyboardReason = RequestKeyboardReason::NONE;
}

bool PerUserSession::IsNumkeyAutoInputApp(const std::string &bundleName)
{
    return NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(userId_, bundleName);
}

bool PerUserSession::IsPreconfiguredDefaultImeSpecified(const InputClientInfo &inputClientInfo)
{
    return ImeInfoInquirer::GetInstance().IsRestrictedDefaultImeByDisplay(
        inputClientInfo.config.inputAttribute.callingDisplayId) ||
        inputClientInfo.config.isSimpleKeyboardEnabled ||
        inputClientInfo.config.inputAttribute.IsOneTimeCodeFlag();
}

std::pair<std::string, std::string> PerUserSession::GetImeUsedBeforeScreenLocked()
{
    std::lock_guard<std::mutex> lock(imeUsedLock_);
    return imeUsedBeforeScreenLocked_;
}

void PerUserSession::SetImeUsedBeforeScreenLocked(const std::pair<std::string, std::string> &ime)
{
    std::lock_guard<std::mutex> lock(imeUsedLock_);
    imeUsedBeforeScreenLocked_ = ime;
}

bool PerUserSession::IsImeSwitchForbidden()
{
#ifdef IMF_SCREENLOCK_MGR_ENABLE
    if (IsDeviceLockAndScreenLocked()) {
        return true;
    }
#endif
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo == nullptr) {
        return false;
    }

    bool isSimpleKeyboard = (clientInfo->config.inputAttribute.IsSecurityImeFlag() ||
                                clientInfo->config.inputAttribute.IsOneTimeCodeFlag()) ?
                                false : clientInfo->config.isSimpleKeyboardEnabled;

    return ImeInfoInquirer::GetInstance().IsRestrictedDefaultImeByDisplay(
        clientInfo->config.inputAttribute.callingDisplayId) ||
        clientInfo->config.inputAttribute.IsSecurityImeFlag() || isSimpleKeyboard;
}

bool PerUserSession::IsDeviceLockAndScreenLocked()
{
    auto screenLockMgr = ScreenLock::ScreenLockManager::GetInstance();
    if (screenLockMgr == nullptr) {
        IMSA_HILOGE("ScreenLockManager is nullptr!");
        return false;
    }
    bool isDeviceLocked = false;
    int32_t retCode = screenLockMgr->IsDeviceLocked(userId_, isDeviceLocked);
    if (retCode != ScreenLock::ScreenLockError::E_SCREENLOCK_OK) {
        IMSA_HILOGE("ScreenLockManager get IsDeviceLocked error ret:%{public}d, userId:%{public}d", retCode, userId_);
    }
    bool isScreenLocked = screenLockMgr->IsScreenLocked();
    IMSA_HILOGD("isDeviceLocked is %{public}d, isScreenLocked is %{public}d", isDeviceLocked, isScreenLocked);
    return isScreenLocked && isDeviceLocked;
}

std::pair<int32_t, StartPreDefaultImeStatus> PerUserSession::StartPreconfiguredDefaultIme(
    const ImeExtendInfo &imeExtendInfo, bool isStopCurrentIme)
{
    InputTypeManager::GetInstance().Set(false);
    auto preDefaultIme = ImeInfoInquirer::GetInstance().GetDefaultIme();
    auto ime = GetRealImeData(true);
    if (ime != nullptr && (ime->ime.first == preDefaultIme.bundleName && ime->ime.second == preDefaultIme.extName)) {
        return std::make_pair(ErrorCode::NO_ERROR, StartPreDefaultImeStatus::HAS_STARTED);
    }
    preDefaultIme.imeExtendInfo = imeExtendInfo;
    auto ret = StartIme(std::make_shared<ImeNativeCfg>(preDefaultIme), isStopCurrentIme);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("start ime failed, ret: %{public}d!", ret);
        return std::make_pair(ret, StartPreDefaultImeStatus::TO_START);
    }
    std::string subName;
    auto defaultIme = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
    if (defaultIme != nullptr && defaultIme->imeId == preDefaultIme.imeId) {
        NotifyImeChangedToClients();
        subName = defaultIme->subName;
    }
    NotifySubTypeChangedToIme(preDefaultIme.bundleName, subName);
    return std::make_pair(ErrorCode::NO_ERROR, StartPreDefaultImeStatus::TO_START);
}

void PerUserSession::NotifyOnInputStopFinished()
{
    isNotifyFinished_.SetValue(true);
}

void PerUserSession::IncreaseAttachCount()
{
    std::lock_guard<std::mutex> lock(attachCountMtx_);
    if (attachingCount_ >= MAX_ATTACH_COUNT) {
        IMSA_HILOGE("attach count over:%{public}u", MAX_ATTACH_COUNT);
        return;
    }
    attachingCount_++;
}

void PerUserSession::DecreaseAttachCount()
{
    std::lock_guard<std::mutex> lock(attachCountMtx_);
    if (attachingCount_ == 0) {
        IMSA_HILOGE("attachingCount_ is 0");
        return;
    }
    attachingCount_--;
}

uint32_t PerUserSession::GetAttachCount()
{
    std::lock_guard<std::mutex> lock(attachCountMtx_);
    return attachingCount_;
}

int32_t PerUserSession::TryStartIme()
{
    if (!isBlockStartedByLowMem_.load()) {
        IMSA_HILOGI("ime is not blocked in starting by low mem, no need to deal.");
        return ErrorCode::ERROR_OPERATION_NOT_ALLOWED;
    }
    isBlockStartedByLowMem_.store(false);
    auto imeData = GetRealImeData();
    if (imeData != nullptr) {
        IMSA_HILOGI("has running ime:%{public}s, no need to deal.", imeData->ime.first.c_str());
        return ErrorCode::ERROR_IME_HAS_STARTED;
    }
    auto cfgIme = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_);
    if (cfgIme == nullptr || ImeInfoInquirer::GetInstance().GetDefaultIme().bundleName != cfgIme->bundleName) {
        IMSA_HILOGI("has no cfgIme or cfg ime is not sys preconfigured ime, can not start.");
        return ErrorCode::ERROR_OPERATION_NOT_ALLOWED;
    }
#ifndef IMF_ON_DEMAND_START_STOP_SA_ENABLE
    if (!ImeStateManagerFactory::GetInstance().GetDynamicStartIme()) {
        StartImeIfInstalled();
    }
#endif
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::TryDisconnectIme()
{
    auto imeData = GetRealImeData();
    if (imeData == nullptr) {
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    if (GetAttachCount() != 0) {
        IMSA_HILOGI("attaching, can not disconnect.");
        return ErrorCode::ERROR_OPERATION_NOT_ALLOWED;
    }
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo != nullptr) {
        IMSA_HILOGI("has current client, can not disconnect.");
        return ErrorCode::ERROR_OPERATION_NOT_ALLOWED;
    }
    auto abilityMgr = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityMgr == nullptr) {
        return ErrorCode::ERROR_IMSA_NULLPTR;
    }
    auto imeConnection = GetImeConnection();
    if (imeConnection == nullptr) {
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = abilityMgr->DisconnectAbility(imeConnection);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("disConnect %{public}s/%{public}s failed, ret:%{public}d.", imeData->ime.first.c_str(),
            imeData->ime.second.c_str(), ret);
        return ErrorCode::ERROR_IMSA_IME_DISCONNECT_FAILED;
    }
    ClearImeConnection(imeConnection);
    return ErrorCode::NO_ERROR;
}

void PerUserSession::SetImeConnection(const sptr<AAFwk::IAbilityConnection> &connection)
{
    std::lock_guard<std::mutex> lock(connectionLock_);
    connection_ = connection;
}

sptr<AAFwk::IAbilityConnection> PerUserSession::GetImeConnection()
{
    std::lock_guard<std::mutex> lock(connectionLock_);
    return connection_;
}

void PerUserSession::ClearImeConnection(const sptr<AAFwk::IAbilityConnection> &connection)
{
    std::lock_guard<std::mutex> lock(connectionLock_);
    if (connection == nullptr || connection_ == nullptr || connection->AsObject() != connection_->AsObject()) {
        return;
    }
    IMSA_HILOGI("clear imeConnection.");
    connection_ = nullptr;
}

int32_t PerUserSession::IsRequestOverLimit(TimeLimitType timeLimitType, int32_t resetTimeOut, uint32_t restartNum)
{
    std::lock_guard<std::mutex> lock(resetLock);
    auto now = time(nullptr);
    auto& manager = managers_[timeLimitType];
    if (difftime(now, manager.last) > resetTimeOut) {
        manager = {0, now};
    }
    ++manager.num;
    if (manager.num > restartNum) {
        return ErrorCode::ERROR_REQUEST_RATE_EXCEEDED;
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::PrepareImeInfos(const std::shared_ptr<ImeData> &imeData,
    std::vector<sptr<IRemoteObject>> &agents, std::vector<BindImeInfo> &imeInfos, uint64_t groupId)
{
    auto allData = GetAllReadyImeData(imeData, groupId);
    if (allData.empty()) {
        IMSA_HILOGE("allData is empty!");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }

    for (auto &data : allData) {
        if (data->agent == nullptr) {
            IMSA_HILOGE("agent is nullptr!");
            return ErrorCode::ERROR_IME_NOT_STARTED;
        }
        agents.emplace_back(data->agent);
        BindImeInfo imeInfo = { data->pid, data->ime.first };
        imeInfos.emplace_back(imeInfo);
    }
    return ErrorCode::NO_ERROR;
}

bool PerUserSession::IsEnable(const std::shared_ptr<ImeData> &data, uint64_t displayId)
{
    bool ret = false;
    if (data == nullptr || data->core == nullptr) {
        return false;
    }
    data->core->IsEnable(ret, displayId);
    return ret;
}

void PerUserSession::SetIsNeedReportQos(bool isNeedReportQos)
{
    isNeedReportQos_ = isNeedReportQos;
}
} // namespace MiscServices
} // namespace OHOS