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

namespace OHOS {
namespace MiscServices {
using namespace std::chrono;
using namespace MessageID;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Rosen;
constexpr uint32_t STOP_IME_TIME = 600;
constexpr const char *STRICT_MODE = "strictMode";
constexpr const char *ISOLATED_SANDBOX = "isolatedSandbox";
constexpr uint32_t CHECK_IME_RUNNING_RETRY_INTERVAL = 60;
constexpr uint32_t CHECK_IME_RUNNING_RETRY_TIMES = 10;
constexpr int32_t MAX_RESTART_NUM = 3;
constexpr int32_t IME_RESET_TIME_OUT = 3;
constexpr int32_t MAX_RESTART_TASKS = 2;
constexpr uint32_t MAX_ATTACH_COUNT = 100000;
constexpr const char *UNDEFINED = "undefined";
constexpr int32_t WAIT_ATTACH_FINISH_DELAY = 50;
constexpr int32_t WAIT_ATTACH_FINISH_MAX_TIMES = 20;
constexpr uint32_t MAX_SCB_START_COUNT = 2;
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

int PerUserSession::AddClientInfo(
    sptr<IRemoteObject> inputClient, const InputClientInfo &clientInfo, ClientAddEvent event)
{
    IMSA_HILOGD("PerUserSession start.");
    auto clientGroup = GetClientGroup(clientInfo.displayId);
    if (clientGroup != nullptr) {
        return clientGroup->AddClientInfo(inputClient, clientInfo, event);
    }
    clientGroup = std::make_shared<ClientGroup>(
        clientInfo.displayId, [this](const sptr<IInputClient> &remote) { this->OnClientDied(remote); });
    auto ret = clientGroup->AddClientInfo(inputClient, clientInfo, event);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to AddClientInfo: %{public}d", ret);
        return ret;
    }
    uint64_t displayGroupId = GetDisplayGroupId(clientInfo.displayId);
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    clientGroupMap_.insert(std::make_pair(displayGroupId, clientGroup));
    IMSA_HILOGI("add client group: %{public}" PRIu64 " end.", displayGroupId);
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::HideKeyboard(
    const sptr<IInputClient> &currentClient, const std::shared_ptr<ClientGroup> &clientGroup)
{
    IMSA_HILOGD("PerUserSession::HideKeyboard start.");
    if (currentClient == nullptr) {
        IMSA_HILOGE("current client is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto clientInfo = clientGroup->GetClientInfo(currentClient->AsObject());
    if (clientInfo == nullptr) {
        IMSA_HILOGE("client info is nullptr!");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    auto data = GetReadyImeData(clientInfo->bindImeType);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", clientInfo->bindImeType);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::NORMAL, [&data] { return data->core->HideKeyboard(); });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to hide keyboard, ret: %{public}d!", ret);
        return ErrorCode::ERROR_KBD_HIDE_FAILED;
    }
    bool isShowKeyboard = false;
    clientGroup->UpdateClientInfo(currentClient->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, isShowKeyboard } });
    RestoreCurrentImeSubType(clientGroup->GetDisplayGroupId());
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
    auto data = GetReadyImeData(clientInfo->bindImeType);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", clientInfo->bindImeType);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::REQUEST_SHOW, [&data, requestKeyboardReason] {
        return data->core->ShowKeyboard(requestKeyboardReason);
    });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to show keyboard, ret: %{public}d!", ret);
        return ErrorCode::ERROR_KBD_SHOW_FAILED;
    }
    bool isShowKeyboard = true;
    clientGroup->UpdateClientInfo(currentClient->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, isShowKeyboard } });
    clientGroup->NotifyInputStartToClients(clientInfo->config.windowId, requestKeyboardReason);
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
        clientGroup->NotifyInputStopToClients();
    }
    auto clientInfo = clientGroup->GetClientInfo(remote->AsObject());
    IMSA_HILOGI("userId: %{public}d.", userId_);
    if (IsSameClient(remote, clientGroup->GetCurrentClient())) {
        if (clientInfo != nullptr) {
            StopImeInput(clientInfo->bindImeType, clientInfo->channel, 0);
        }
        clientGroup->SetCurrentClient(nullptr);
        RestoreCurrentImeSubType(clientGroup->GetDisplayGroupId());
    }
    if (IsSameClient(remote, clientGroup->GetInactiveClient())) {
        if (clientInfo != nullptr) {
            StopImeInput(clientInfo->bindImeType, clientInfo->channel, 0);
        }
        clientGroup->SetInactiveClient(nullptr);
        RestoreCurrentImeSubType(clientGroup->GetDisplayGroupId());
    }
    clientGroup->RemoveClientInfo(remote->AsObject(), true);
}

/** Handle the situation that an ime died
 * It's called when an ime died
 * @param the remote object handler of the ime who died.
 */
void PerUserSession::OnImeDied(const sptr<IInputMethodCore> &remote, ImeType type)
{
    if (remote == nullptr) {
        return;
    }
    IMSA_HILOGI("type: %{public}d.", type);
    auto imeData = GetImeData(type);
    if (imeData != nullptr && imeData->imeStatus == ImeStatus::EXITING) {
        RemoveImeData(type, true);
        InputTypeManager::GetInstance().Set(false);
        NotifyImeStopFinished();
        IMSA_HILOGI("%{public}d not current imeData.", type);
        return;
    }
    RemoveImeData(type, true);
    if (!OsAccountAdapter::IsOsAccountForeground(userId_)) {
        IMSA_HILOGW("userId:%{public}d in background, no need to restart ime.", userId_);
        return;
    }
    auto clientGroup = GetClientGroup(type);
    auto clientInfo = clientGroup != nullptr ? clientGroup->GetCurrentClientInfo() : nullptr;
    if (clientInfo != nullptr && clientInfo->bindImeType == type) {
        clientGroup->NotifyInputStopToClients();
        StopClientInput(clientInfo);
        if (type == ImeType::IME) {
            StartImeInImeDied();
        }
        return;
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
    if (type == ImeType::IME && currentImeInfo->bundleName == defaultImeInfo->name &&
        !SystemParamAdapter::GetInstance().GetBoolParam(SystemParamAdapter::MEMORY_WATERMARK_KEY)) {
        StartImeInImeDied();
    }
}

int32_t PerUserSession::RemoveIme(const sptr<IInputMethodCore> &core, ImeType type)
{
    if (core == nullptr) {
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto data = GetReadyImeData(type);
    if (data == nullptr || data->core->AsObject() != core->AsObject()) {
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }

    auto clientGroup = GetClientGroup(type);
    auto clientInfo = clientGroup != nullptr ? clientGroup->GetCurrentClientInfo() : nullptr;
    if (clientInfo != nullptr && clientInfo->bindImeType == type) {
        UnBindClientWithIme(clientInfo, { .sessionId = 0 });
    }
    RemoveImeData(type, true);
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnHideCurrentInput(uint64_t displayId)
{
    auto clientGroup = GetClientGroup(displayId);
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

int32_t PerUserSession::OnShowCurrentInput(uint64_t displayId)
{
    IMSA_HILOGD("PerUserSession::OnShowCurrentInput start.");
    auto clientGroup = GetClientGroup(displayId);
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
    auto clientGroup = GetClientGroup(DEFAULT_DISPLAY_ID);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("current client is nullptr!");
        return;
    }
    sptr<IInputClient> client = clientGroup->GetCurrentClient();
    if (client == nullptr) {
        IMSA_HILOGE("current client is nullptr!");
        return;
    }
    clientGroup->UpdateClientInfo(client->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, false } });
    RestoreCurrentImeSubType(DEFAULT_DISPLAY_ID);
}

int32_t PerUserSession::OnRequestShowInput(uint64_t displayId)
{
    IMSA_HILOGD("PerUserSession::OnRequestShowInput start.");
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("no current client");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    ImeType type = GetImeType(displayId);
    auto data = GetReadyImeData(type);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d doesn't exist!", type);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::REQUEST_SHOW, [&data] {
        return data->core->ShowKeyboard(static_cast<int32_t>(RequestKeyboardReason::NONE));
    });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to show keyboard, ret: %{public}d!", ret);
        return ErrorCode::ERROR_KBD_SHOW_FAILED;
    }
    InputMethodSysEvent::GetInstance().ReportImeState(ImeState::BIND, data->pid,
        ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_)->bundleName);
    Memory::MemMgrClient::GetInstance().SetCritical(getpid(), true, INPUT_METHOD_SYSTEM_ABILITY_ID);
    auto currentClient = clientGroup->GetCurrentClient();
    if (currentClient != nullptr) {
        clientGroup->UpdateClientInfo(currentClient->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, true } });
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnRequestHideInput(int32_t callingPid, uint64_t displayId)
{
    IMSA_HILOGD("PerUserSession::OnRequestHideInput start.");
    auto data = GetReadyImeData(GetImeType(displayId));
    if (data != nullptr) {
        auto ret = RequestIme(data, RequestType::REQUEST_HIDE, [&data] { return data->core->HideKeyboard(); });
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("failed to hide keyboard, ret: %{public}d!", ret);
            return ErrorCode::ERROR_KBD_HIDE_FAILED;
        }
    }

    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        RestoreCurrentImeSubType(displayId);
        return ErrorCode::NO_ERROR;
    }
    auto currentClient = clientGroup->GetCurrentClient();
    auto currentClientInfo = clientGroup->GetCurrentClientInfo();
    if (currentClient != nullptr && currentClientInfo != nullptr) {
        clientGroup->UpdateClientInfo(currentClient->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, false } });
    }
    auto inactiveClient = clientGroup->GetInactiveClient();
    if (inactiveClient != nullptr) {
        DetachOptions options = { .sessionId = 0, .isUnbindFromClient = false, .isInactiveClient = true };
        RemoveClient(inactiveClient, clientGroup, options);
    }
    RestoreCurrentImeSubType(displayId);
    clientGroup->NotifyInputStopToClients();
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnPrepareInput(const InputClientInfo &clientInfo)
{
    IMSA_HILOGD("PerUserSession::OnPrepareInput start");
    if (clientInfo.client == nullptr) {
        IMSA_HILOGE("client is nullptr");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return AddClientInfo(clientInfo.client->AsObject(), clientInfo, PREPARE_INPUT);
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
        clientGroup->NotifyInputStopToClients();
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
        RestoreCurrentImeSubType(clientGroup->GetDisplayGroupId());
        StopClientInput(clientInfo, false, options.isNotifyClientAsync);
    }
    if (IsSameClient(client, clientGroup->GetInactiveClient())) {
        clientGroup->SetInactiveClient(nullptr);
        StopClientInput(clientInfo, options.isInactiveClient);
    }
    clientGroup->RemoveClientInfo(client->AsObject());
    return ErrorCode::NO_ERROR;
}

void PerUserSession::DeactivateClient(const sptr<IInputClient> &client)
{
    if (client == nullptr) {
        IMSA_HILOGD("client is nullptr.");
        return;
    }
    auto clientGroup = GetClientGroup(client->AsObject());
    if (clientGroup == nullptr) {
        IMSA_HILOGD("client group not found");
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
    auto data = GetReadyImeData(clientInfo->bindImeType);
    if (data == nullptr) {
        IMSA_HILOGE("ime %{public}d doesn't exist!", clientInfo->bindImeType);
        return;
    }
    RequestIme(data, RequestType::NORMAL, [&data, &clientInfo] {
        data->core->OnClientInactive(clientInfo->channel);
        return ErrorCode::NO_ERROR;
    });
    InputMethodSysEvent::GetInstance().ReportImeState(ImeState::UNBIND, data->pid,
        ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_)->bundleName);
    Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, INPUT_METHOD_SYSTEM_ABILITY_ID);
}

bool PerUserSession::IsProxyImeEnable()
{
    auto data = GetReadyImeData(ImeType::PROXY_IME);
    bool ret = false;
    if (data == nullptr || data->core == nullptr) {
        return false;
    }
    data->core->IsEnable(ret);
    return ret;
}

int32_t PerUserSession::OnStartInput(
    const InputClientInfo &inputClientInfo, sptr<IRemoteObject> &agent, std::pair<int64_t, std::string> &imeInfo)
{
    const sptr<IInputClient> &client = inputClientInfo.client;
    if (client == nullptr) {
        IMSA_HILOGE("client is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    auto clientGroup = GetClientGroup(inputClientInfo.displayId);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("client group not found");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    auto clientInfo = clientGroup->GetClientInfo(client->AsObject());
    if (clientInfo == nullptr) {
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    IMSA_HILOGD("start input with keyboard[%{public}d].", inputClientInfo.isShowKeyboard);
    InputClientInfo infoTemp = *clientInfo;
    infoTemp.isNotifyInputStart = inputClientInfo.isNotifyInputStart;
    ImeType imeType = GetImeType(inputClientInfo.displayId);
    if (GetDisplayGroupId(inputClientInfo.displayId) == DEFAULT_DISPLAY_ID) {
        HandleImeBindTypeChanged(infoTemp, clientGroup);
        imeType = IsProxyImeEnable() ? ImeType::PROXY_IME : ImeType::IME;
    }
    infoTemp.isShowKeyboard = inputClientInfo.isShowKeyboard;
    infoTemp.needHide = inputClientInfo.needHide;
    infoTemp.requestKeyboardReason = inputClientInfo.requestKeyboardReason;
    infoTemp.config.requestKeyboardReason = inputClientInfo.requestKeyboardReason;
    int32_t ret =
        BindClientWithIme(std::make_shared<InputClientInfo>(infoTemp), imeType, true, inputClientInfo.displayId);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("bind failed, ret: %{public}d!", ret);
        return ret;
    }
    auto data = GetReadyImeData(imeType);
    if (data == nullptr || data->agent == nullptr) {
        IMSA_HILOGE("data or agent is nullptr!");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    agent = data->agent;
    imeInfo = { data->pid, data->ime.first };
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::BindClientWithIme(
    const std::shared_ptr<InputClientInfo> &clientInfo, ImeType type, bool isBindFromClient, uint64_t displayId)
{
    if (clientInfo == nullptr) {
        IMSA_HILOGE("clientInfo is nullptr!");
        return ErrorCode::ERROR_IMSA_NULLPTR;
    }
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("not found group");
        return ErrorCode::ERROR_IMSA_NULLPTR;
    }
    IMSA_HILOGD("imeType: %{public}d, isShowKeyboard: %{public}d, isBindFromClient: %{public}d.", type,
        clientInfo->isShowKeyboard, isBindFromClient);
    auto data = GetValidIme(type);
    if (data == nullptr) {
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    if (!data->imeExtendInfo.privateCommand.empty()) {
        auto ret = SendPrivateData(data->imeExtendInfo.privateCommand);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("before start input notify send private data failed, ret: %{public}d!", ret);
            return ret;
        }
    }
    auto ret = RequestIme(data, RequestType::START_INPUT,
        [&data, &clientInfo, isBindFromClient]() {
            InputClientInfoInner inputClientInfoInner =
                InputMethodTools::GetInstance().InputClientInfoToInner(const_cast<InputClientInfo &>(*clientInfo));
            return data->core->StartInput(inputClientInfoInner, isBindFromClient);
    });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("start input failed, ret: %{public}d!", ret);
        return ErrorCode::ERROR_IME_START_INPUT_FAILED;
    }
    if (type == ImeType::IME) {
        InputMethodSysEvent::GetInstance().ReportImeState(ImeState::BIND, data->pid,
            ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_)->bundleName);
        Memory::MemMgrClient::GetInstance().SetCritical(getpid(), true, INPUT_METHOD_SYSTEM_ABILITY_ID);
    }
    if (!isBindFromClient) {
        ret = clientInfo->client->OnInputReady(data->agent, data->pid, data->ime.first);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("start client input failed, ret: %{public}d!", ret);
            return ErrorCode::ERROR_IMSA_CLIENT_INPUT_READY_FAILED;
        }
    }
    clientGroup->UpdateClientInfo(clientInfo->client->AsObject(), { { UpdateFlag::BINDIMETYPE, type },
        { UpdateFlag::ISSHOWKEYBOARD, clientInfo->isShowKeyboard }, { UpdateFlag::STATE, ClientState::ACTIVE } });
    ReplaceCurrentClient(clientInfo->client, clientGroup);
    if (clientInfo->isShowKeyboard) {
        clientGroup->NotifyInputStartToClients(
            clientInfo->config.windowId, static_cast<int32_t>(clientInfo->requestKeyboardReason));
    }
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
        StopClientInput(currentClientInfo, options.isNotifyClientAsync);
    }
    StopImeInput(currentClientInfo->bindImeType, currentClientInfo->channel, options.sessionId);
}

void PerUserSession::StopClientInput(
    const std::shared_ptr<InputClientInfo> &clientInfo, bool isStopInactiveClient, bool isAsync)
{
    if (clientInfo == nullptr || clientInfo->client == nullptr) {
        return;
    }
    int32_t ret;
    if (isAsync == true) {
        ret = clientInfo->client->OnInputStopAsync(isStopInactiveClient);
    } else {
        auto onInputStopObject = new (std::nothrow) OnInputStopNotifyServiceImpl();
        if (onInputStopObject == nullptr) {
            IMSA_HILOGE("Failed to create onInputStopObject.");
            return;
        }
        std::lock_guard<std::mutex> lock(isNotifyFinishedLock_);
        isNotifyFinished_.Clear(false);
        ret = clientInfo->client->OnInputStop(isStopInactiveClient, onInputStopObject);
        if (!isNotifyFinished_.GetValue()) {
            IMSA_HILOGE("OnInputStop is not finished!");
        }
    }
    IMSA_HILOGI("isStopInactiveClient: %{public}d, client pid: %{public}d, ret: %{public}d.", isStopInactiveClient,
        clientInfo->pid, ret);
}

void PerUserSession::StopImeInput(ImeType currentType, const sptr<IRemoteObject> &currentChannel, uint32_t sessionId)
{
    auto data = GetReadyImeData(currentType);
    if (data == nullptr) {
        return;
    }
    auto ret = RequestIme(data, RequestType::STOP_INPUT, [&data, &currentChannel, sessionId]() {
        return data->core->StopInput(currentChannel, sessionId);
    });
    IMSA_HILOGI("stop ime input, ret: %{public}d.", ret);
    if (ret == ErrorCode::NO_ERROR && currentType == ImeType::IME) {
        InputMethodSysEvent::GetInstance().ReportImeState(ImeState::UNBIND, data->pid,
            ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_)->bundleName);
        Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, INPUT_METHOD_SYSTEM_ABILITY_ID);
    }
    if (currentType == ImeType::IME) {
        RestoreCurrentImeSubType(DEFAULT_DISPLAY_ID);
    }
}

void PerUserSession::OnSecurityChange(int32_t security)
{
    auto data = GetReadyImeData(ImeType::IME);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return;
    }
    auto ret =
        RequestIme(data, RequestType::NORMAL, [&data, security] { return data->core->OnSecurityChange(security); });
    IMSA_HILOGD("on security change, ret: %{public}d.", ret);
}

int32_t PerUserSession::OnSetCoreAndAgent(const sptr<IInputMethodCore> &core, const sptr<IRemoteObject> &agent)
{
    IMSA_HILOGI("start.");
    auto ret = UpdateImeData(core, agent, IPCSkeleton::GetCallingPid());
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    auto action = GetImeAction(ImeEvent::SET_CORE_AND_AGENT);
    if (action == ImeAction::DO_NOTHING) {
        return ErrorCode::NO_ERROR;
    }
    if (action != ImeAction::DO_SET_CORE_AND_AGENT) {
        return ErrorCode::ERROR_IME;
    }
    ret = InitInputControlChannel();
    IMSA_HILOGI("init input control channel ret: %{public}d.", ret);
    auto imeType = ImeType::IME;
    auto clientInfo = GetCurrentClientInfo();
    if (clientInfo != nullptr && IsImeStartInBind(clientInfo->bindImeType, imeType)) {
        ClearRequestKeyboardReason(clientInfo);
        BindClientWithIme(clientInfo, imeType);
        SetInputType();
    }
    bool isStarted = true;
    isImeStarted_.SetValue(isStarted);
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnRegisterProxyIme(const sptr<IInputMethodCore> &core, const sptr<IRemoteObject> &agent)
{
    IMSA_HILOGD("start.");
    auto imeType = ImeType::PROXY_IME;
    auto ret = AddImeData(imeType, core, agent, IPCSkeleton::GetCallingPid());
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    auto clientInfo = GetCurrentClientInfo();
    if (clientInfo != nullptr) {
        if (IsProxyImeStartInBind(clientInfo->bindImeType, imeType)) {
            BindClientWithIme(clientInfo, imeType);
        }
        if (IsProxyImeStartInImeBind(clientInfo->bindImeType, imeType)) {
            UnBindClientWithIme(clientInfo, { .sessionId = 0 });
            BindClientWithIme(clientInfo, imeType);
        }
    }
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

int32_t PerUserSession::OnRegisterProxyIme(
    uint64_t displayId, const sptr<IInputMethodCore> &core, const sptr<IRemoteObject> &agent)
{
    IMSA_HILOGI("start. displayId: %{public}" PRIu64 "", displayId);
    auto imeType = ImeType::PROXY_AGENT_IME;
    auto ret = AddImeData(imeType, core, agent, IPCSkeleton::GetCallingPid());
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(virtualDisplayLock_);
        virtualScreenDisplayId_.emplace(displayId);
    }
    agentDisplayId_.store(displayId);
    auto clientInfo = GetCurrentClientInfo(displayId);
    if (clientInfo != nullptr) {
        BindClientWithIme(clientInfo, imeType);
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnUnregisterProxyIme(uint64_t displayId)
{
    IMSA_HILOGD("start. displayId: %{public}" PRIu64 "", displayId);
    if (displayId != agentDisplayId_.load()) {
        return false;
    }
    RemoveImeData(ImeType::PROXY_AGENT_IME, false);
    {
        std::lock_guard<std::mutex> lock(virtualDisplayLock_);
        virtualScreenDisplayId_.erase(displayId);
    }
    auto clientInfo = GetCurrentClientInfo(displayId);
    if (clientInfo == nullptr) {
        IMSA_HILOGD("no current client");
        return ErrorCode::NO_ERROR;
    }
    UnBindClientWithIme(clientInfo, { .sessionId = 0 });
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnUnRegisteredProxyIme(UnRegisteredType type, const sptr<IInputMethodCore> &core)
{
    IMSA_HILOGD("proxy unregister type: %{public}d.", type);
    // 0: stop proxy  1: switch to ima
    if (type == UnRegisteredType::REMOVE_PROXY_IME) {
        RemoveIme(core, ImeType::PROXY_IME);
        return ErrorCode::NO_ERROR;
    }
    if (type == UnRegisteredType::SWITCH_PROXY_IME_TO_IME) {
        auto clientInfo = GetCurrentClientInfo();
        if (clientInfo == nullptr) {
            IMSA_HILOGE("not found current client!");
            return ErrorCode::ERROR_CLIENT_NOT_BOUND;
        }
        if (clientInfo->bindImeType == ImeType::PROXY_IME) {
            UnBindClientWithIme(clientInfo, { .sessionId = 0 });
        }
        InputClientInfo infoTemp;
        infoTemp.isShowKeyboard = true;
        infoTemp.client = clientInfo->client;
        infoTemp.channel = clientInfo->channel;
        return BindClientWithIme(std::make_shared<InputClientInfo>(infoTemp), ImeType::IME);
    }
    return ErrorCode::ERROR_BAD_PARAMETERS;
}

int32_t PerUserSession::InitInputControlChannel()
{
    IMSA_HILOGD("PerUserSession::InitInputControlChannel start.");
    sptr<IInputControlChannel> inputControlChannel = new (std::nothrow) InputControlChannelServiceImpl(userId_);
    if (inputControlChannel == nullptr) {
        IMSA_HILOGE("new inputControlChannel failed!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto data = GetReadyImeData(ImeType::IME);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(data, RequestType::NORMAL,
        [&data, &inputControlChannel] { return data->core->InitInputControlChannel(inputControlChannel); });
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
        std::lock_guard<std::mutex> lock(resetLock);
        auto now = time(nullptr);
        if (difftime(now, manager.last) > IME_RESET_TIME_OUT) {
            manager = { 0, now };
        }
        ++manager.num;
        if (manager.num > MAX_RESTART_NUM) {
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
    StartImeIfInstalled();
}

void PerUserSession::StartImeIfInstalled()
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
    StartCurrentIme();
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
            RemoveClient(replacedClient, clientGroup, { .sessionId = 0 });
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
    IMSA_HILOGD("start.");
    auto clientGroup = GetClientGroup(DEFAULT_DISPLAY_ID);
    if (clientGroup == nullptr) {
        IMSA_HILOGD("no client need to notify");
        return;
    }
    clientGroup->NotifyImeChangeToClients(property, subProperty);
}

int32_t PerUserSession::AddImeData(ImeType type, sptr<IInputMethodCore> core, sptr<IRemoteObject> agent, pid_t pid)
{
    if (core == nullptr || agent == nullptr) {
        IMSA_HILOGE("core or agent is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    sptr<InputDeathRecipient> deathRecipient = new (std::nothrow) InputDeathRecipient();
    if (deathRecipient == nullptr) {
        IMSA_HILOGE("failed to new deathRecipient!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    deathRecipient->SetDeathRecipient([this, core, type](const wptr<IRemoteObject> &) { this->OnImeDied(core, type); });
    auto coreObject = core->AsObject();
    if (coreObject == nullptr || (coreObject->IsProxyObject() && !coreObject->AddDeathRecipient(deathRecipient))) {
        IMSA_HILOGE("failed to add death recipient!");
        return ErrorCode::ERROR_ADD_DEATH_RECIPIENT_FAILED;
    }
    std::lock_guard<std::mutex> lock(imeDataLock_);
    auto imeData = std::make_shared<ImeData>(core, agent, deathRecipient, pid);
    imeData->imeStatus = ImeStatus::READY;
    imeData->ime.first = "proxyIme";
    imeData->imeStateManager = ImeStateManagerFactory::GetInstance().CreateImeStateManager(pid, [this] {
        StopCurrentIme();
    });
    if (type == ImeType::PROXY_IME) {
        imeData->ime.first.append(GET_NAME(_PROXY_IME));
    } else if (type == ImeType::PROXY_AGENT_IME) {
        imeData->ime.first.append(GET_NAME(_PROXY_AGENT_IME));
    }
    imeData_.insert_or_assign(type, imeData);
    IMSA_HILOGI("add imeData with type: %{public}d name: %{public}s end", type, imeData->ime.first.c_str());
    return ErrorCode::NO_ERROR;
}

std::shared_ptr<ImeData> PerUserSession::GetReadyImeData(ImeType type)
{
    std::lock_guard<std::mutex> lock(imeDataLock_);
    auto it = imeData_.find(type);
    if (it == imeData_.end()) {
        return nullptr;
    }
    if (it->second->imeStatus != ImeStatus::READY) {
        return nullptr;
    }
    return it->second;
}

std::shared_ptr<ImeData> PerUserSession::GetValidIme(ImeType type)
{
    auto data = GetReadyImeData(type);
    if (data != nullptr || type != ImeType::IME) {
        return data;
    }
    IMSA_HILOGI("current ime is empty, try to restart it.");
    StartCurrentIme();
    return GetReadyImeData(type);
}

void PerUserSession::RemoveImeData(ImeType type, bool isImeDied)
{
    std::lock_guard<std::mutex> lock(imeDataLock_);
    auto it = imeData_.find(type);
    if (it == imeData_.end()) {
        IMSA_HILOGD("imeData not found.");
        return;
    }
    auto data = it->second;
    if (isImeDied && data->core != nullptr && data->core->AsObject() != nullptr) {
        data->core->AsObject()->RemoveDeathRecipient(data->deathRecipient);
    }
    imeData_.erase(type);
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
    DeactivateClient(client);
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
    auto imeData = GetImeData(ImeType::IME);
    if (imeData != nullptr && imeData->ime == GetImeUsedBeforeScreenLocked()) {
        IMSA_HILOGD("no need to switch");
        return;
    }
    IMSA_HILOGI("user %{public}d unlocked, start current ime", userId_);
#ifndef IMF_ON_DEMAND_START_STOP_SA_ENABLE
    if (!ImeStateManagerFactory::GetInstance().GetDynamicStartIme()) {
        AddRestartIme();
    }
#endif
}

void PerUserSession::OnScreenLock()
{
    auto imeData = GetImeData(ImeType::IME);
    if (imeData == nullptr) {
        IMSA_HILOGD("imeData is nullptr");
        std::pair<std::string, std::string> ime{ "", "" };
        SetImeUsedBeforeScreenLocked(ime);
        return;
    }
    SetImeUsedBeforeScreenLocked(imeData->ime);
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
    auto clientGroup = GetClientGroup(ImeType::IME);
    auto clientInfo = clientGroup != nullptr ? clientGroup->GetCurrentClientInfo() : nullptr;
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
    auto screenLockMgr = ScreenLock::ScreenLockManager::GetInstance();
    if (screenLockMgr != nullptr && screenLockMgr->IsScreenLocked()) {
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

int32_t PerUserSession::StartCurrentIme(bool isStopCurrentIme)
{
    IMSA_HILOGD("enter");
    auto imeToStart = GetRealCurrentIme(true);
    if (imeToStart == nullptr) {
        IMSA_HILOGE("imeToStart is nullptr!");
        return ErrorCode::ERROR_IMSA_IME_TO_START_NULLPTR;
    }
    IMSA_HILOGI("ime info:%{public}s/%{public}s.", imeToStart->bundleName.c_str(), imeToStart->subName.c_str());
    auto ret = StartIme(imeToStart, isStopCurrentIme);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to start ime!");
        InputMethodSysEvent::GetInstance().InputmethodFaultReporter(ret, imeToStart->imeId, "start ime failed!");
        return ret;
    }
    auto readyIme = GetReadyImeData(ImeType::IME);
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
    if (!ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked()) {
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
    if (ImeEnabledInfoManager::GetInstance().IsDefaultFullMode(userId_, ime->bundleName)) {
        status = EnabledStatus::FULL_EXPERIENCE_MODE;
        isolatedSandBox = false;
    } else {
        auto ret = ImeEnabledInfoManager::GetInstance().GetEnabledState(userId_, ime->bundleName, status);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("%{public}d/%{public}s GetEnabledState failed.", userId_, ime->imeId.c_str());
        }
    }
    AAFwk::Want want;
    want.SetElementName(ime->bundleName, ime->extName);
    want.SetParam(STRICT_MODE, !(status == EnabledStatus::FULL_EXPERIENCE_MODE));
    want.SetParam(ISOLATED_SANDBOX, isolatedSandBox);
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
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    InitImeData({ imeToStart->bundleName, imeToStart->extName }, ime);
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

int32_t PerUserSession::OnPanelStatusChange(
    const InputWindowStatus &status, const ImeWindowInfo &info, uint64_t displayId)
{
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        IMSA_HILOGD("client nullptr");
        return ErrorCode::NO_ERROR;
    }
    return clientGroup->NotifyPanelStatusChange(status, info);
}

int32_t PerUserSession::OnUpdateListenEventFlag(const InputClientInfo &clientInfo)
{
    auto remoteClient = clientInfo.client->AsObject();
    auto ret = AddClientInfo(remoteClient, clientInfo, START_LISTENING);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to AddClientInfo!");
        return ret;
    }
    auto clientGroup = GetClientGroup(remoteClient);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("group is nullptr");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    auto info = clientGroup->GetClientInfo(remoteClient);
    if (info == nullptr) {
        IMSA_HILOGE("info is nullptr!");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    if (info->eventFlag == NO_EVENT_ON && info->bindImeType == ImeType::NONE) {
        clientGroup->RemoveClientInfo(remoteClient, false);
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnSetCallingWindow(uint32_t callingWindowId,
    uint64_t callingDisplayId, sptr<IInputClient> client)
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
    if (clientInfo->config.windowId == callingWindowId) {
        return ErrorCode::NO_ERROR;
    }
    IMSA_HILOGD("windowId changed, refresh windowId info and notify clients input start.");
    clientInfo->config.windowId = callingWindowId;
    clientInfo->config.privateCommand.insert_or_assign(
        "displayId", PrivateDataValue(static_cast<int32_t>(callingDisplayId)));
    clientGroup->NotifyInputStartToClients(callingWindowId, static_cast<int32_t>(clientInfo->requestKeyboardReason));

    if (callingWindowId != INVALID_WINDOW_ID) {
        auto callingWindowInfo = GetCallingWindowInfo(*clientInfo);
        clientInfo->config.inputAttribute.windowId = callingWindowInfo.windowId;
        bool isNotifyDisplayChanged =
            clientInfo->config.inputAttribute.callingDisplayId != callingWindowInfo.displayId &&
            SceneBoardJudgement::IsSceneBoardEnabled();
        clientInfo->config.inputAttribute.callingDisplayId = callingWindowInfo.displayId;
        if (isNotifyDisplayChanged) {
            NotifyCallingDisplayChanged(callingWindowInfo.displayId);
        }
    }
    return ErrorCode::NO_ERROR;
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

bool PerUserSession::IsImeStartInBind(ImeType bindImeType, ImeType startImeType)
{
    return startImeType == ImeType::IME && bindImeType == ImeType::IME;
}

bool PerUserSession::IsProxyImeStartInBind(ImeType bindImeType, ImeType startImeType)
{
    return startImeType == ImeType::PROXY_IME && bindImeType == ImeType::PROXY_IME;
}

bool PerUserSession::IsProxyImeStartInImeBind(ImeType bindImeType, ImeType startImeType)
{
    return startImeType == ImeType::PROXY_IME && bindImeType == ImeType::IME;
}

bool PerUserSession::IsImeBindTypeChanged(ImeType bindImeType)
{
    return (bindImeType == ImeType::IME && IsProxyImeEnable()) ||
           (bindImeType == ImeType::PROXY_IME && !IsProxyImeEnable());
}

int32_t PerUserSession::SwitchSubtype(const SubProperty &subProperty)
{
    auto data = GetValidIme(ImeType::IME);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(data, RequestType::NORMAL, [&data, &subProperty] { return data->core->SetSubtype(subProperty); });
}

int32_t PerUserSession::SwitchSubtypeWithoutStartIme(const SubProperty &subProperty)
{
    auto data = GetReadyImeData(ImeType::IME);
    if (data == nullptr || data->core == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist, or core is nullptr.", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(data, RequestType::NORMAL,
        [&data, &subProperty] { return data->core->SetSubtype(subProperty); });
}

int32_t PerUserSession::SetInputType()
{
    InputType inputType = InputTypeManager::GetInstance().GetCurrentInputType();
    auto data = GetValidIme(ImeType::IME);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(data, RequestType::NORMAL,
        [&data, &inputType] { return data->core->OnSetInputType(static_cast<int32_t>(inputType)); });
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

int32_t PerUserSession::RestoreCurrentImeSubType(uint64_t callingDisplayId)
{
    if (!IsDefaultDisplayGroup(callingDisplayId)) {
        IMSA_HILOGI("only need restore in default display, calling display: %{public}" PRIu64 "", callingDisplayId);
        return ErrorCode::NO_ERROR;
    }
    if (!InputTypeManager::GetInstance().IsStarted()) {
        IMSA_HILOGD("already exit.");
        return ErrorCode::NO_ERROR;
    }
    auto typeIme = InputTypeManager::GetInstance().GetCurrentIme();
    InputTypeManager::GetInstance().Set(false);
    auto imeData = GetReadyImeData(ImeType::IME);
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
    auto imeData = GetImeData(ImeType::IME);
    if (imeData == nullptr) {
        IMSA_HILOGE("ime not started!");
        return false;
    }
    IMSA_HILOGD("userId: %{public}d, pid: %{public}d, current pid: %{public}d.", userId_, pid, imeData->pid);
    return imeData->pid == pid;
}

int32_t PerUserSession::IsPanelShown(const PanelInfo &panelInfo, bool &isShown)
{
    auto clientGroup = GetClientGroup(DEFAULT_DISPLAY_ID);
    if (clientGroup == nullptr || clientGroup->GetCurrentClient() == nullptr) {
        IMSA_HILOGD("not in bound state.");
        isShown = false;
        return ErrorCode::NO_ERROR;
    }
    auto ime = GetReadyImeData(ImeType::IME);
    if (ime == nullptr) {
        IMSA_HILOGE("ime not started!");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(ime, RequestType::NORMAL,
        [&ime, &panelInfo, &isShown] { return ime->core->IsPanelShown(panelInfo, isShown); });
}

bool PerUserSession::CheckSecurityMode()
{
    auto clientInfo = GetCurrentClientInfo();
    if (clientInfo != nullptr) {
        return clientInfo->config.inputAttribute.GetSecurityFlag();
    }
    return false;
}

int32_t PerUserSession::RequestIme(const std::shared_ptr<ImeData> &data, RequestType type, const IpcExec &exec)
{
    if (IsProxyImeEnable()) {
        IMSA_HILOGD("proxy enable.");
        return exec();
    }
    if (data == nullptr || data->imeStateManager == nullptr) {
        IMSA_HILOGE("data is nullptr!");
        return ErrorCode::NO_ERROR;
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

int32_t PerUserSession::OnConnectSystemCmd(const sptr<IRemoteObject> &channel, sptr<IRemoteObject> &agent)
{
    auto data = GetReadyImeData(ImeType::IME);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::NORMAL,
        [&data, &channel, &agent] { return data->core->OnConnectSystemCmd(channel, agent); });
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
        clientGroupObject->NotifyInputStopToClients();
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

int32_t PerUserSession::InitImeData(
    const std::pair<std::string, std::string> &ime, const std::shared_ptr<ImeNativeCfg> &imeNativeCfg)
{
    std::lock_guard<std::mutex> lock(imeDataLock_);
    auto it = imeData_.find(ImeType::IME);
    if (it != imeData_.end()) {
        return ErrorCode::NO_ERROR;
    }
    auto imeData = std::make_shared<ImeData>(nullptr, nullptr, nullptr, -1);
    imeData->startTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    imeData->ime = ime;
    imeData->imeStateManager = ImeStateManagerFactory::GetInstance().CreateImeStateManager(-1, [this] {
        StopCurrentIme();
    });
    if (imeNativeCfg != nullptr && !imeNativeCfg->imeExtendInfo.privateCommand.empty()) {
        imeData->imeExtendInfo.privateCommand = imeNativeCfg->imeExtendInfo.privateCommand;
    }
    imeData_.insert({ ImeType::IME, imeData });
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::UpdateImeData(sptr<IInputMethodCore> core, sptr<IRemoteObject> agent, pid_t pid)
{
    if (core == nullptr || agent == nullptr) {
        IMSA_HILOGE("core or agent is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    std::lock_guard<std::mutex> lock(imeDataLock_);
    auto it = imeData_.find(ImeType::IME);
    if (it == imeData_.end()) {
        return ErrorCode::ERROR_NULL_POINTER;
    }
    it->second->core = core;
    it->second->agent = agent;
    it->second->pid = pid;
    it->second->imeStateManager = ImeStateManagerFactory::GetInstance().CreateImeStateManager(pid, [this] {
        StopCurrentIme();
    });
    sptr<InputDeathRecipient> deathRecipient = new (std::nothrow) InputDeathRecipient();
    if (deathRecipient == nullptr) {
        IMSA_HILOGE("failed to new deathRecipient!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto type = ImeType::IME;
    deathRecipient->SetDeathRecipient([this, core, type](const wptr<IRemoteObject> &) { this->OnImeDied(core, type); });
    auto coreObject = core->AsObject();
    if (coreObject == nullptr || (coreObject->IsProxyObject() && !coreObject->AddDeathRecipient(deathRecipient))) {
        IMSA_HILOGE("failed to add death recipient!");
        return ErrorCode::ERROR_ADD_DEATH_RECIPIENT_FAILED;
    }
    it->second->deathRecipient = deathRecipient;
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::InitConnect(pid_t pid)
{
    std::lock_guard<std::mutex> lock(imeDataLock_);
    auto it = imeData_.find(ImeType::IME);
    if (it == imeData_.end()) {
        return ErrorCode::ERROR_NULL_POINTER;
    }
    it->second->pid = pid;
    return ErrorCode::NO_ERROR;
}

std::shared_ptr<ImeData> PerUserSession::GetImeData(ImeType type)
{
    std::lock_guard<std::mutex> lock(imeDataLock_);
    auto it = imeData_.find(type);
    if (it == imeData_.end()) {
        return nullptr;
    }
    return it->second;
}

int32_t PerUserSession::StartIme(const std::shared_ptr<ImeNativeCfg> &ime, bool isStopCurrentIme)
{
    std::unique_lock<std::mutex> lock(imeStartLock_, std::defer_lock);
    if (!lock.try_lock()) {
        IMSA_HILOGW("try_lock failed!");
        return ErrorCode::ERROR_IME_START_INPUT_FAILED;
    }
    if (ime == nullptr) {
        return ErrorCode::ERROR_IMSA_IME_TO_START_NULLPTR;
    }
    auto imeData = GetImeData(ImeType::IME);
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
    std::lock_guard<std::mutex> lock(imeDataLock_);
    auto it = imeData_.find(ImeType::IME);
    if (it == imeData_.end()) {
        return ImeAction::DO_ACTION_IN_NULL_IME_DATA;
    }
    auto iter = imeEventConverter_.find({ it->second->imeStatus, action });
    if (iter == imeEventConverter_.end()) {
        IMSA_HILOGE("abnormal!");
        return ImeAction::DO_ACTION_IN_IME_EVENT_CONVERT_FAILED;
    }
    it->second->imeStatus = iter->second.first;
    return iter->second.second;
}

int32_t PerUserSession::StartCurrentIme(const std::shared_ptr<ImeNativeCfg> &ime)
{
    auto imeData = GetImeData(ImeType::IME);
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
    auto clientInfo = GetCurrentClientInfo();
    if (clientInfo != nullptr && clientInfo->bindImeType == ImeType::IME) {
        StopClientInput(clientInfo);
    }
    auto imeData = GetImeData(ImeType::IME);
    if (imeData == nullptr) {
        return ErrorCode::NO_ERROR;
    }
    if (imeData->core == nullptr) {
        IMSA_HILOGE("core is nullptr!");
        return ForceStopCurrentIme();
    }
    auto ret = RequestIme(imeData, RequestType::NORMAL, [&imeData] {
        // failed when register onInputStop after SetCoreAndAgent
        return imeData->core->StopInputService(true);
    });
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
    auto imeData = GetImeData(ImeType::IME);
    if (imeData == nullptr) {
        return ErrorCode::NO_ERROR;
    }
    if (!ImeInfoInquirer::GetInstance().IsRunningIme(userId_, imeData->ime.first)) {
        IMSA_HILOGW("[%{public}s, %{public}s] already stop.", imeData->ime.first.c_str(), imeData->ime.second.c_str());
        RemoveImeData(ImeType::IME, true);
        return ErrorCode::NO_ERROR;
    }
    auto clientInfo = GetCurrentClientInfo();
    if (clientInfo != nullptr && clientInfo->bindImeType == ImeType::IME) {
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
    RemoveImeData(ImeType::IME, true);
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

int32_t PerUserSession::StartUserSpecifiedIme(uint64_t callingDisplayId)
{
    InputMethodSyncTrace tracer("StartUserSpecifiedIme trace.");
    if (!IsDefaultDisplayGroup(callingDisplayId)) {
        IMSA_HILOGI("only need restore in default display, calling display: %{public}" PRIu64 "", callingDisplayId);
        return ErrorCode::NO_ERROR;
    }
    InputTypeManager::GetInstance().Set(false);
    auto cfgIme = ImeInfoInquirer::GetInstance().GetImeToStart(userId_);
    auto imeData = GetReadyImeData(ImeType::IME);
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
        IMSA_HILOGI("new input pattern is pwd.");
        return !exClientInfo->config.inputAttribute.GetSecurityFlag();
    }
    IMSA_HILOGI("new input pattern is normal.");
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

void PerUserSession::HandleImeBindTypeChanged(
    InputClientInfo &newClientInfo, const std::shared_ptr<ClientGroup> &clientGroup)
{
    /* isClientInactive: true: represent the oldClientInfo is inactiveClient's
                         false: represent the oldClientInfo is currentClient's */
    std::shared_ptr<InputClientInfo> oldClientInfo = nullptr;
    bool isClientInactive = false;
    {
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
        if (!IsImeBindTypeChanged(oldClientInfo->bindImeType)) {
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
    if (IsSameClient(newClientInfo.client, oldClientInfo->client)) {
        newClientInfo.isNotifyInputStart = true;
    }
    if (isClientInactive) {
        StopImeInput(oldClientInfo->bindImeType, oldClientInfo->channel, 0);
        return;
    }
    UnBindClientWithIme(oldClientInfo, { .sessionId = 0 });
}

void PerUserSession::TryUnloadSystemAbility()
{
    auto data = GetReadyImeData(ImeType::IME);
    if (data != nullptr && data->imeStateManager != nullptr) {
        if (data->imeStateManager->IsImeInUse()) {
            return;
        }
    }

    auto onDemandStartStopSa = std::make_shared<OnDemandStartStopSa>();
    onDemandStartStopSa->UnloadInputMethodSystemAbility();
}

uint64_t PerUserSession::GetDisplayGroupId(uint64_t displayId)
{
    std::lock_guard<std::mutex> lock(virtualDisplayLock_);
    IMSA_HILOGD("displayId: %{public}" PRIu64 "", displayId);
    if (displayId == DEFAULT_DISPLAY_ID || virtualScreenDisplayId_.empty()) {
        return DEFAULT_DISPLAY_ID;
    }
    if (virtualScreenDisplayId_.find(displayId) != virtualScreenDisplayId_.end()) {
        return displayId;
    }
    return DEFAULT_DISPLAY_ID;
}

std::shared_ptr<ClientGroup> PerUserSession::GetClientGroup(uint64_t displayId)
{
    uint64_t displayGroupId = GetDisplayGroupId(displayId);
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    auto iter = clientGroupMap_.find(displayGroupId);
    if (iter == clientGroupMap_.end()) {
        IMSA_HILOGD("not found client group with displayId: %{public}" PRIu64 "", displayId);
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

std::shared_ptr<ClientGroup> PerUserSession::GetClientGroup(ImeType type)
{
    if (type == ImeType::IME || type == ImeType::PROXY_IME) {
        return GetClientGroup(DEFAULT_DISPLAY_ID);
    }
    auto agentDisplayId = agentDisplayId_.load();
    if (type == ImeType::PROXY_AGENT_IME && agentDisplayId != DEFAULT_DISPLAY_ID) {
        return GetClientGroup(agentDisplayId);
    }
    IMSA_HILOGE("invalid ime type: %{public}d", static_cast<int32_t>(type));
    return nullptr;
}

ImeType PerUserSession::GetImeType(uint64_t displayId)
{
    displayId = GetDisplayGroupId(displayId);
    if (displayId == DEFAULT_DISPLAY_ID) {
        return ImeType::IME;
    }
    if (displayId == agentDisplayId_.load()) {
        return ImeType::PROXY_AGENT_IME;
    }
    return ImeType::NONE;
}

void PerUserSession::OnCallingDisplayIdChanged(
    const int32_t windowId, const int32_t callingPid, const uint64_t displayId)
{
    IMSA_HILOGD("enter!windowId:%{public}d,callingPid:%{public}d,displayId:%{public}" PRIu64 "", windowId,
        callingPid, displayId);
    auto clientGroup = GetClientGroup(displayId);
    if (clientGroup == nullptr) {
        IMSA_HILOGD("client group not found");
        return;
    }
    auto clientInfo = clientGroup->GetCurrentClientInfo();
    if (clientInfo == nullptr) {
        IMSA_HILOGD("clientInfo is null");
        return;
    }
    IMSA_HILOGD("userId:%{public}d, windowId:%{public}d", userId_, clientInfo->config.windowId);
    if (clientInfo->config.windowId != static_cast<uint32_t>(windowId)) {
        return;
    }
    uint64_t curDisplay = clientInfo->config.inputAttribute.callingDisplayId;
    if (curDisplay == displayId) {
        return;
    }
    clientInfo->config.inputAttribute.callingDisplayId = displayId;
    NotifyCallingDisplayChanged(displayId);
}

int32_t PerUserSession::NotifyCallingDisplayChanged(uint64_t displayId)
{
    IMSA_HILOGD("enter displayId:%{public}" PRIu64 "", displayId);
    if (GetImeType(displayId) != ImeType::IME) {
        IMSA_HILOGD("not default display");
        return ErrorCode::NO_ERROR;
    }
    auto data = GetValidIme(ImeType::IME);
    if (data == nullptr) {
        IMSA_HILOGE("ime is nullptr!");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto callBack = [&data, displayId]() -> int32_t {
        data->core->OnCallingDisplayIdChanged(displayId);
        return ErrorCode::NO_ERROR;
    };
    auto ret = RequestIme(data, RequestType::NORMAL, callBack);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("notify calling window display changed failed, ret: %{public}d!", ret);
    }
    return ret;
}

ImfCallingWindowInfo PerUserSession::GetCallingWindowInfo(const InputClientInfo &clientInfo)
{
    InputMethodSyncTrace tracer("GetCallingWindowInfo trace");
    auto finalWindowId = clientInfo.config.windowId;
    ImfCallingWindowInfo finalWindowInfo{ finalWindowId, 0 };
    if (!SceneBoardJudgement::IsSceneBoardEnabled()) {
        return finalWindowInfo;
    }
    CallingWindowInfo callingWindowInfo;
    if (GetCallingWindowInfo(clientInfo, callingWindowInfo)) {
        finalWindowInfo.displayId = callingWindowInfo.displayId_;
        return finalWindowInfo;
    }
    FocusChangeInfo focusInfo;
    WindowAdapter::GetFocusInfo(focusInfo);
    if (!WindowAdapter::GetCallingWindowInfo(focusInfo.windowId_, userId_, callingWindowInfo)) {
        IMSA_HILOGE("GetCallingWindowInfo error!");
        return finalWindowInfo;
    }
    if (finalWindowId == INVALID_WINDOW_ID) {
        finalWindowId = static_cast<uint32_t>(focusInfo.windowId_);
    }
    return { finalWindowId, callingWindowInfo.displayId_ };
}

bool PerUserSession::GetCallingWindowInfo(const InputClientInfo &clientInfo, CallingWindowInfo &callingWindowInfo)
{
    auto windowId = clientInfo.config.windowId;
    if (windowId == INVALID_WINDOW_ID) {
        return false;
    }
    return WindowAdapter::GetCallingWindowInfo(windowId, userId_, callingWindowInfo);
}

bool PerUserSession::SpecialScenarioCheck()
{
    auto clientInfo = GetCurrentClientInfo();
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
    if (clientInfo->bindImeType == ImeType::PROXY_IME) {
        IMSA_HILOGE("send failed, is collaborative input!");
        return false;
    }
    if (ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked()) {
        IMSA_HILOGE("send failed, is screen locked");
        return false;
    }
    return true;
}

std::pair<int32_t, int32_t> PerUserSession::GetCurrentInputPattern()
{
    auto clientInfo = GetCurrentClientInfo();
    if (clientInfo == nullptr) {
        IMSA_HILOGE("clientInfo is nullptr!");
        return { ErrorCode::ERROR_NULL_POINTER, static_cast<int32_t>(InputType::NONE) };
    }
    return { ErrorCode::NO_ERROR, clientInfo->config.inputAttribute.inputPattern };
}

int32_t PerUserSession::SpecialSendPrivateData(const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    ImeExtendInfo imeExtendInfo;
    imeExtendInfo.privateCommand = privateCommand;
    auto [ret, status] = StartPreconfiguredDefaultIme(DEFAULT_DISPLAY_ID, imeExtendInfo, true);
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
    auto data = GetReadyImeData(ImeType::IME);
    if (data == nullptr) {
        IMSA_HILOGE("data is nullptr");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::NORMAL,
        [&data, &privateCommand] {
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

bool PerUserSession::IsDefaultDisplayGroup(uint64_t displayId)
{
    return GetDisplayGroupId(displayId) == DEFAULT_DISPLAY_ID;
}

void PerUserSession::ClearRequestKeyboardReason(std::shared_ptr<InputClientInfo> &clientInfo)
{
    clientInfo->requestKeyboardReason = RequestKeyboardReason::NONE;
}

bool PerUserSession::IsNumkeyAutoInputApp(const std::string &bundleName)
{
    return NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(userId_, bundleName);
}

bool PerUserSession::IsPreconfiguredDefaultImeSpecified(const InputClientInfo &inputClientInfo)
{
    auto callingWindowInfo = GetCallingWindowInfo(inputClientInfo);
    return ImeInfoInquirer::GetInstance().IsRestrictedDefaultImeByDisplay(callingWindowInfo.displayId) ||
        inputClientInfo.config.isSimpleKeyboardEnabled || inputClientInfo.config.inputAttribute.IsOneTimeCodeFlag();
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
    auto screenLockMgr = ScreenLock::ScreenLockManager::GetInstance();
    if (screenLockMgr != nullptr && screenLockMgr->IsScreenLocked()) {
        return true;
    }
#endif
    auto clientInfo = GetCurrentClientInfo();
    if (clientInfo == nullptr) {
        return false;
    }

    bool isSimpleKeyboard = (clientInfo->config.inputAttribute.IsSecurityImeFlag() ||
                                clientInfo->config.inputAttribute.IsOneTimeCodeFlag()) ?
        false :
        clientInfo->config.isSimpleKeyboardEnabled;

    auto callingWindowInfo = GetCallingWindowInfo(*clientInfo);
    return ImeInfoInquirer::GetInstance().IsRestrictedDefaultImeByDisplay(callingWindowInfo.displayId) ||
        clientInfo->config.inputAttribute.IsSecurityImeFlag() || isSimpleKeyboard;
}

std::pair<int32_t, StartPreDefaultImeStatus> PerUserSession::StartPreconfiguredDefaultIme(
    uint64_t callingDisplayId, const ImeExtendInfo &imeExtendInfo, bool isStopCurrentIme)
{
    if (!IsDefaultDisplayGroup(callingDisplayId)) {
        IMSA_HILOGI("only start in default display, calling display: %{public}" PRIu64 "", callingDisplayId);
        return std::make_pair(ErrorCode::NO_ERROR, StartPreDefaultImeStatus::NO_NEED);
    }
    InputTypeManager::GetInstance().Set(false);
    auto preDefaultIme = ImeInfoInquirer::GetInstance().GetDefaultIme();
    auto ime = GetReadyImeData(ImeType::IME);
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
    auto imeData = GetImeData(ImeType::IME);
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
        AddRestartIme();
    }
#endif
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::TryDisconnectIme()
{
    auto imeData = GetImeData(ImeType::IME);
    if (imeData == nullptr) {
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    if (GetAttachCount() != 0) {
        IMSA_HILOGI("attaching, can not disconnect.");
        return ErrorCode::ERROR_OPERATION_NOT_ALLOWED;
    }
    auto clientInfo = GetCurrentClientInfo();
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
} // namespace MiscServices
} // namespace OHOS