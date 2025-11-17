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

int PerUserSession::AddClientInfo(
    sptr<IRemoteObject> inputClient, const InputClientInfo &clientInfo, ClientAddEvent event)
{
    IMSA_HILOGD("PerUserSession start.");
    uint64_t clientGroupId = clientInfo.clientGroupId;
    auto clientGroup = GetClientGroupByGroupId(clientGroupId);
    if (clientGroup != nullptr) {
        return clientGroup->AddClientInfo(inputClient, clientInfo, event);
    }
    clientGroup = std::make_shared<ClientGroup>(
        clientGroupId, [this](const sptr<IInputClient> &remote) { this->OnClientDied(remote); });
    auto ret = clientGroup->AddClientInfo(inputClient, clientInfo, event);
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
    if (currentClient == nullptr) {
        IMSA_HILOGE("current client is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto clientInfo = clientGroup->GetClientInfo(currentClient->AsObject());
    if (clientInfo == nullptr) {
        IMSA_HILOGE("client info is nullptr!");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    auto data = clientInfo->bindImeData;
    if (data == nullptr) {
        IMSA_HILOGE("%{public}d ime is not exist!", clientInfo->pid);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::NORMAL, [&data] {
        return data->core->HideKeyboard();
    });
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to hide keyboard, ret: %{public}d!", ret);
        return ErrorCode::ERROR_KBD_HIDE_FAILED;
    }
    bool isShowKeyboard = false;
    clientGroup->UpdateClientInfo(currentClient->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, isShowKeyboard } });
    if (data->IsRealIme()) {
        RestoreCurrentImeSubType();
    }
    clientGroup->NotifyInputStopToClients();
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
    auto data = clientInfo->bindImeData;
    if (data == nullptr) {
        IMSA_HILOGE("%{public}d ime is not exist!", clientInfo->pid);
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
            StopImeInput(clientInfo->bindImeData, clientInfo->channel, 0);
        }
        clientGroup->SetCurrentClient(nullptr);
        if (clientInfo->bindImeData != nullptr && clientInfo->bindImeData->IsRealIme()) {
            RestoreCurrentImeSubType();
        }
    }
    if (IsSameClient(remote, clientGroup->GetInactiveClient())) {
        if (clientInfo != nullptr) {
            StopImeInput(clientInfo->bindImeData, clientInfo->channel, 0);
        }
        clientGroup->SetInactiveClient(nullptr);
        if (clientInfo->bindImeData != nullptr && clientInfo->bindImeData->IsRealIme()) {
            RestoreCurrentImeSubType();
        }
    }
    clientGroup->RemoveClientInfo(remote->AsObject(), true);
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
    if (type == ImeType::IME) {
        auto imeData = GetRealImeData();
        if (imeData != nullptr && imeData->imeStatus == ImeStatus::EXITING && pid == imeData->pid) {
            ClearRealImeData();
            InputTypeManager::GetInstance().Set(false);
            NotifyImeStopFinished();
            IMSA_HILOGI("%{public}d not current imeData.", type);
            return;
        }
    }
    RemoveImeData(pid);
    if (!OsAccountAdapter::IsOsAccountForeground(userId_)) {
        IMSA_HILOGW("userId:%{public}d in background, no need to restart ime.", userId_);
        return;
    }
    auto [clientGroup, clientInfo] = GetClientBoundImeByBindIme(pid);
    if (clientGroup != nullptr && clientInfo != nullptr) {
        auto currentClient = clientGroup->GetCurrentClient();
        if (IsSameClient(currentClient, clientInfo->client)) {
            clientGroup->NotifyInputStopToClients();
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

int32_t PerUserSession::OnRequestHideInput(int32_t callingPid, uint64_t clientGroupId)
{
    IMSA_HILOGD("PerUserSession::OnRequestHideInput start.");
    // todo HideKeyboard为啥加到开头
    //    auto data = GetReadyImeData(GetImeType(displayId));
    //    if (data != nullptr) {
    //        auto ret = RequestIme(data, RequestType::REQUEST_HIDE, [&data] {
    //            return data->core->HideKeyboard();
    //        });
    //        if (ret != ErrorCode::NO_ERROR) {
    //            IMSA_HILOGE("failed to hide keyboard, ret: %{public}d!", ret);
    //            return ErrorCode::ERROR_KBD_HIDE_FAILED;
    //        }
    //    }
    auto clientGroup = GetClientGroupByGroupId(clientGroupId);
    if (clientGroup == nullptr) {
        return ErrorCode::NO_ERROR;
    }
    std::shared_ptr<InputClientInfo> clientInfo = nullptr;
    auto currentClient = clientGroup->GetCurrentClient();
    if (currentClient != nullptr) {
        clientInfo = clientGroup->GetClientInfo(currentClient->AsObject());
        clientGroup->UpdateClientInfo(currentClient->AsObject(), { { UpdateFlag::ISSHOWKEYBOARD, false } });  // todo 是否置空绑定ime
    }
    auto inactiveClient = clientGroup->GetInactiveClient();
    if (inactiveClient != nullptr) {
        clientInfo = clientGroup->GetClientInfo(inactiveClient->AsObject());
        DetachOptions options = { .sessionId = 0, .isUnbindFromClient = false, .isInactiveClient = true };
        RemoveClient(inactiveClient, clientGroup, options);
    }
    if (clientInfo != nullptr && clientInfo->bindImeData != nullptr) {
        auto data = clientInfo->bindImeData;
        auto ret = RequestIme(data, RequestType::REQUEST_HIDE, [&data] { return data->core->HideKeyboard(); });
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("failed to hide keyboard, ret: %{public}d!", ret);
        }
        if (clientInfo->bindImeData->IsRealIme()) {
            RestoreCurrentImeSubType();
        }
    }
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
        if (clientInfo->bindImeData != nullptr && clientInfo->bindImeData->IsRealIme()) {
            RestoreCurrentImeSubType();
        }
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
    auto data = clientInfo->bindImeData;
    if (data == nullptr) {
        IMSA_HILOGE("ime %{public}d doesn't exist!", clientInfo->bindImePid);
        return;
    }
    RequestAllIme(data, RequestType::NORMAL, [&clientInfo](const sptr<IInputMethodCore> &core) {
        core->OnClientInactive(clientInfo->channel);
        return ErrorCode::NO_ERROR;
    });
    InputMethodSysEvent::GetInstance().ReportImeState(
        ImeState::UNBIND, data->pid, ImeCfgManager::GetInstance().GetCurrentImeCfg(userId_)->bundleName);
    Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, INPUT_METHOD_SYSTEM_ABILITY_ID);
}

int32_t PerUserSession::OnStartInput(const InputClientInfo &inputClientInfo, std::vector<sptr<IRemoteObject>> &agents,
    std::vector<BindImeInfo> &imeInfos)
{
    IMSA_HILOGD("start input with keyboard[%{public}d].", inputClientInfo.isShowKeyboard);
    auto data = GetReadyImeDataToBind(inputClientInfo.config.inputAttribute.displayId);
    if (data == nullptr || data->agent == nullptr) {
        IMSA_HILOGE("data or agent is nullptr!");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto clientGroup = GetClientGroupByGroupId(inputClientInfo.clientGroupId);
    if (clientGroup == nullptr) {
        IMSA_HILOGE("client group not found");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    // HandleBindImeChanged(inputClientInfo, data, clientGroup);
    int32_t ret = BindClientWithIme(std::make_shared<InputClientInfo>(inputClientInfo), data, true);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("bind failed, ret: %{public}d!", ret);
        return ret;
    }
    return PrepareImeInfos(data, agents, imeInfos);
}

std::shared_ptr<ImeData> PerUserSession::GetRealImeData(bool isReady)
{
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

std::shared_ptr<ImeData> PerUserSession::ClearRealImeData()
{
    return realImeData_ = nullptr;
}

std::shared_ptr<ImeData> PerUserSession::GetReadyImeDataToBind(uint64_t displayId)
{
    auto proxyIme = GetProxyImeData(displayId);
    if (proxyIme != nullptr && IsEnable(proxyIme)) {
        return proxyIme;
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

int32_t PerUserSession::SendAllReadyImeToClient(
    std::shared_ptr<ImeData> data, const std::shared_ptr<InputClientInfo> &clientInfo)
{
    if (data == nullptr) {
        IMSA_HILOGW("no need to send");
        return ErrorCode::NO_ERROR;
    }

    std::vector<std::shared_ptr<ImeData>> imeDatas = { data };
    if (!data->IsImeMirror()) {
        if (mirrorImeData_ != nullptr) {
            imeDatas.push_back(mirrorImeData_);
        }
    }

    int32_t finalResult = ErrorCode::NO_ERROR;
    int32_t ret;
    for (const auto &dataItem : imeDatas) {
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

int32_t PerUserSession::BindClientWithIme(const std::shared_ptr<InputClientInfo> &clientInfo,
    const std::shared_ptr<ImeData> &imeData, bool isBindFromClient)
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
    HandleBindImeChanged(clientInfo, imeData, clientGroup);
    HandleSameClientPreemptInMultiGroup(clientInfo, imeData);
    HandleImePreemptInMultiGroup(clientInfo, imeData);
    IMSA_HILOGD("imePid: %{public}d, isShowKeyboard: %{public}d, isBindFromClient: %{public}d.", imeData->pid,
        clientInfo->isShowKeyboard, isBindFromClient);
    if (!imeData->imeExtendInfo.privateCommand.empty()) {
        auto ret = SendPrivateData(imeData->imeExtendInfo.privateCommand);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("before start input notify send private data failed, ret: %{public}d!", ret);
        }
    }
    InputClientInfoInner inputClientInfoInner =
        InputMethodTools::GetInstance().InputClientInfoToInner(*clientInfo);
    auto ret = RequestAllIme(
        data, RequestType::START_INPUT, [&inputClientInfoInner, isBindFromClient](const sptr<IInputMethodCore> &core) {
            return core->StartInput(inputClientInfoInner, isBindFromClient);
        });
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

    clientGroup->UpdateClientInfo(clientInfo->client->AsObject(),
        { { UpdateFlag::ISSHOWKEYBOARD, clientInfo->isShowKeyboard }, { UpdateFlag::STATE, ClientState::ACTIVE },
            { UpdateFlag::BIND_IME_DATA, imeData } });
    ReplaceCurrentClient(clientInfo->client, clientGroup);
    if (clientInfo->isShowKeyboard) {
        clientGroup->NotifyInputStartToClients(
            clientInfo->config.windowId, static_cast<int32_t>(clientInfo->requestKeyboardReason));
    }
    return ErrorCode::NO_ERROR;
}

void PerUserSession::HandleSameClientPreemptInMultiGroup(
    const std::shared_ptr<InputClientInfo> &newClientInfo, const std::shared_ptr<ImeData> &newImeData)
{
    if (newClientInfo == nullptr || newImeData == nullptr) {
        return;
    }
    // TODO 返回值可以改成列表，循环处理，防止异常情况出现多个
    auto [oldClientGroup, oldClientInfo] = GetClientBoundImeByClientPid(newClientInfo->pid);
    if (oldClientGroup == nullptr || oldClientInfo == nullptr || oldClientInfo->client == nullptr
        || oldClientInfo->bindImeData == nullptr) {
        return;
    }
    oldClientGroup->UpdateClientInfo(oldClientInfo->client->AsObject(),
        { { UpdateFlag::ISSHOWKEYBOARD, false }, { UpdateFlag::BIND_IME_DATA, nullptr } });
    // 相同客户端在同一group里，不论输入法是否相同(只能是类型不同)，都不需要隐藏输入法，HandleBindImeChanged 函数已处理
    if (IsSameClientGroup(oldClientInfo->clientGroupId, newClientInfo->clientGroupId)) {
        return;
    }
    // todo needHIde
    newClientInfo->isNotifyInputStart = true;
    // todo 相同客户端在不同group里:是否需要移除信息老group中的客戶端
    if (IsSameClient(oldClientInfo->client, oldClientGroup->GetCurrentClient())) {
        oldClientGroup->SetCurrentClient(nullptr);
    }
    if (IsSameClient(oldClientInfo->client, oldClientGroup->GetInactiveClient())) {
        oldClientGroup->SetInactiveClient(nullptr);
    }
//    if (oldClientInfo->bindImeData->IsRealIme()) {
//        RestoreCurrentImeSubType();  // todo 放哪里合适
//    }
    oldClientGroup->RemoveClientInfo(oldClientInfo->client->AsObject());

    // 相同客户端在不同group里,绑定的是同一输入法，只需要置空老group中的输入法,不能隐藏（如果两次显示在同一屏幕，会出现先隐藏再显示）
    if (oldClientInfo->bindImeData->pid == newImeData->pid) {
        return;
    }
    // 相同客户端在不同group里, 且绑定的不是同一输入法
    StopImeInput(oldClientInfo->bindImeData, oldClientInfo->channel, 0);
}

void PerUserSession::HandleImePreemptInMultiGroup(
    const std::shared_ptr<InputClientInfo> &newClientInfo, const std::shared_ptr<ImeData> &newImeData)
{
    if (newClientInfo == nullptr || newImeData == nullptr) {
        return;
    }
    // HandleClientPreemptInMultiGroup的处理会使oldClientInfo和newClientInfo不会相同

    if (newImeData->IsRealIme()) {
        auto [oldClientGroup, oldClientInfo] = GetClientBoundRealIme();
        // 场景：默认group拉起讯飞， 点击group1需要拉起小艺
        // 不同客户端在同一group里，绑定正式输入法，ReplaceCurrentClient 会处理
        if (oldClientGroup != nullptr && oldClientInfo != nullptr && !IsSameIme(oldClientInfo->bindImeData, newImeData)
            && !IsSameClientGroup(oldClientInfo->clientGroupId, newClientInfo->clientGroupId)) {
            oldClientGroup->UpdateClientInfo(oldClientInfo->client->AsObject(),
                { { UpdateFlag::ISSHOWKEYBOARD, false }, { UpdateFlag::BIND_IME_DATA, nullptr } });
            StopClientInput(oldClientInfo, IsSameClient(oldClientInfo->client, oldClientGroup->GetInactiveClient));
            newClientInfo->isNotifyInputStart = true;
        }
    }
    // TODO 返回值可以改成列表，循环处理，防止异常情况出现多个
    auto [oldClientGroup, oldClientInfo] = GetClientBoundImeByBindIme(newImeData->pid);
    if (oldClientGroup == nullptr || oldClientInfo == nullptr || oldClientInfo->client == nullptr
        || oldClientInfo->bindImeData == nullptr) {
        return;
    }
    //    if (oldClientInfo->bindImeData->IsRealIme()) {
    //        RestoreCurrentImeSubType(); // todo 放哪里合适
    //    }
    oldClientGroup->UpdateClientInfo(oldClientInfo->client->AsObject(),
        { { UpdateFlag::ISSHOWKEYBOARD, false }, { UpdateFlag::BIND_IME_DATA, nullptr } });
    // 不同客户端在同一group里，绑定同一输入法, ReplaceCurrentClient会处理
    if (IsSameClientGroup(oldClientInfo->clientGroupId, newClientInfo->clientGroupId)) {
        return;
    }
    // todo needHIde
    newClientInfo->isNotifyInputStart = true;
    // 不同客户端在不同group里，绑定同一输入法
    StopClientInput(oldClientInfo, IsSameClient(oldClientInfo->client, oldClientGroup->GetInactiveClient);
}

bool PerUserSession::IsSameClientGroup(uint64_t newGroupId, uint64_t oldGroupId)
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
        StopClientInput(currentClientInfo, options.isNotifyClientAsync);
    }
    StopImeInput(currentClientInfo->bindImeData, currentClientInfo->channel, options.sessionId);
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
        auto onInputStopObject = new (std::nothrow) OnInputStopNotifyServiceImpl(clientInfo->pid);
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

void PerUserSession::StopImeInput(
    const std::shared_ptr<ImeData> &imeData, const sptr<IRemoteObject> &currentChannel, uint32_t sessionId)
{
    if (imeData == nullptr) {
        return;
    }
    auto ret = RequestAllIme(
        imeData, RequestType::STOP_INPUT, [&currentChannel, sessionId](const sptr<IInputMethodCore> &core) {
            return core->StopInput(currentChannel, sessionId);
        });
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
    auto pid = IPCSkeleton::GetCallingPid();
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
    // todo 默认group拉起讯飞， 点击group1需要拉起小艺，此处如果不限定会导致小艺先显示在默认group，后续又显示在group1上
    if (GetAttachCount() != 0) {
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
        auto currentClientInfo = group->GetCurrentClientInfo();
        if (currentClientInfo == nullptr) {
            continue;
        }
        auto bindImeData = currentClientInfo->bindImeData;
        if (bindImeData == nullptr) {
            continue;
        }
        if (bindImeData->IsRealIme()) {
            return { group, currentClientInfo };
        }
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

std::pair<std::shared_ptr<ClientGroup>, std::shared_ptr<InputClientInfo>> PerUserSession::GetClientByWindowId(
    uiuint32_t windowId)
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    for (const auto &[groupId, group] : clientGroupMap_) {
        if (group == nullptr) {
            continue;
        }
        auto clientInfo = group->GetClientByWindowId(windowId);
        if (clientInfo != nullptr) {
            return { group, clientInfo };
        }
    }
    return { nullptr, nullptr };
}

std::pair<std::shared_ptr<ClientGroup>, std::shared_ptr<InputClientInfo>> PerUserSession::GetClientBoundImeByClientPid(
    pid_t clientPid)
{
    std::lock_guard<std::mutex> lock(clientGroupLock_);
    for (const auto &[groupId, group] : clientGroupMap_) {
        if (group == nullptr) {
            continue;
        }
        auto clientInfo = group->GetClientInfo(clientPid);
        if (clientInfo != nullptr && clientInfo->bindImeData != nullptr) {
            return { group, clientInfo };
        }
    }
    return { nullptr, nullptr };
}

std::pair<std::shared_ptr<ClientGroup>, std::shared_ptr<InputClientInfo>> PerUserSession::GetClientBoundImeByBindIme(
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
    auto result =
        IsRequestOverLimit(TimeLimitType::PROXY_IME_LIMIT, PROXY_REGISTERATION_TIME_INTERVAL, MAX_REGISTRATIONS_NUM);
    if (result != ErrorCode::NO_ERROR) {
        IMSA_HILOGI("frequent calls, service is busy.");
        return result;
    }
    auto lastImeData = GetProxyImeData(displayId);
    if (lastImeData != nullptr && lastImeData->core != nullptr && lastImeData->core->AsObject() != core->AsObject()) {
        lastImeData->core->NotifyPreemption();
    }
    auto newImeData = AddProxyImeData(displayId, core, agent, pid);
    if (newImeData == nullptr) {
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    auto clientInfo = GetCurrentClientInfo(displayId);
    if (clientInfo != nullptr) {
        if (!IsSameIme(clientInfo->bindImeData, newImeData)) {
            UnBindClientWithIme(clientInfo, { .sessionId = 0 });
            BindClientWithIme(clientInfo, newImeData);
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

int32_t PerUserSession::OnUnregisterProxyIme(uint64_t displayId, int32_t pid)
{
    IMSA_HILOGD("proxy unregister.");
    auto clientGroup = GetClientGroup(displayId);
    auto clientInfo = clientGroup != nullptr ? clientGroup->GetCurrentClientInfo() : nullptr;
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
        IMSA_HILOGD("displayId %{public}lu not found, no ImeData to remove", displayId);
        return ErrorCode::NO_ERROR;
    }
    auto &imeDataList = iter->second;
    auto vecIter =
        std::find_if(imeDataList.begin(), imeDataList.end(), [pid](const std::shared_ptr<ImeData> &existingImeData) {
            return existingImeData != nullptr && pid == existingImeData->pid;
        });
    if (vecIter != imeDataList.end()) {
        imeDataList.erase(vecIter);
    }
    if (imeDataList.empty()) {
        proxyImeData_.erase(iter);
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnBindImeMirror(const sptr<IInputMethodCore> &core, const sptr<IRemoteObject> &agent)
{
    IMSA_HILOGI("[ImeMirrorTag]star");
    auto pid = IPCSkeleton::GetCallingPid();
    {
        std::lock_guard<std::mutex> lock(mirrorImeDataLock_);
        mirrorImeData_ = std::make_shared<ImeData>(nullptr, nullptr, nullptr, -1);
        auto ret = FillImeData(core, agent, pid, ImeType::IME_MIRROR, mirrorImeData_);
        if (ret != ErrorCode::NO_ERROR) {
            return ret;
        }
    }

    auto clientInfo = GetCurrentClientInfo();  // todo
    if (clientInfo != nullptr) {
        BindClientWithIme(clientInfo, mirrorImeData_);
    }
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::OnUnbindImeMirror()
{
    IMSA_HILOGD("[ImeMirrorTag]start");
    auto pid = IPCSkeleton::GetCallingPid();
    if (mirrorImeData_ == nullptr || mirrorImeData_->pid != pid) {
        return ErrorCode::NO_ERROR;
    }
    auto clientInfo = GetCurrentClientInfo();  //todo
    if (clientInfo == nullptr) {
        {
            std::lock_guard<std::mutex> lock(mirrorImeDataLock_);
            mirrorImeData_ = nullptr;
        }
        IMSA_HILOGD("[ImeMirrorTag]no current client");
        return ErrorCode::NO_ERROR;
    }
    clientInfo->client->OnImeMirrorStop(mirrorImeData_->agent);
    StopImeInput(mirrorImeData_, clientInfo->channel, 0);
    {
        std::lock_guard<std::mutex> lock(mirrorImeDataLock_);
        mirrorImeData_ = nullptr;
    }
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

void PerUserSession::StartImeIfInstalled(StartReason startReasaon)
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
    StartCurrentIme(false, startReasaon);
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

std::shared_ptr<ImeData> PerUserSession::AddProxyImeData(
    uint64_t displayId, sptr<IInputMethodCore> core, sptr<IRemoteObject> agent, pid_t pid)
{
    if (core == nullptr || agent == nullptr) {
        IMSA_HILOGE("core or agent is nullptr!");
        return nullptr;
    }
    auto type = ImeType::PROXY_IME;
    std::lock_guard<std::mutex> lock(proxyImeDataLock_);
    auto &imeDataList = proxyImeData_[displayId];
    auto iter = std::find_if(
        imeDataList.begin(), imeDataList.end(), [&core, this](const std::shared_ptr<ImeData> &existingImeData) {
            return existingImeData != nullptr && core->AsObject() == existingImeData->core->AsObject();
        });
    if (iter != imeDataList.end()) {
        auto imeData = *iter;
        imeDataList.erase(iter);
        IMSA_HILOGI("%{public}s preempt again!", imeData->ime.first.c_str());
        imeDataList.push_back(imeData);
        return imeData;
    }
    auto imeData = std::make_shared<ImeData>(nullptr, nullptr, nullptr, -1);
    FillImeData(core, agent, pid, ImeType::IME, imeData);
    AddProxyImeData(imeDataList, imeData); // todo 啥意思
    IMSA_HILOGI("add imeData with type: %{public}d name: %{public}s end", type, imeData->ime.first.c_str());
    return imeData;
}

void PerUserSession::AddProxyImeData(
    std::vector<std::shared_ptr<ImeData>> &imeDataList, const std::shared_ptr<ImeData> &imeData)
{
    if (imeDataList.empty()) {
        imeDataList.push_back(imeData);
        return;
    }
    if (!isFirstPreemption_) {
        isFirstPreemption_ = true;
        const auto &lastImeData = imeDataList.back();
        if (IsEnable(lastImeData) && !IsEnable(imeData)) {
            imeDataList.insert(imeDataList.begin(), imeData);
            return;
        }
    }
    imeDataList.push_back(imeData);
}

std::vector<std::shared_ptr<ImeData>> PerUserSession::GetAllReadyImeData(const std::shared_ptr<ImeData> &bindImeData)
{
    if (bindImeData == nullptr) {
        return {};
    }

    if (bindImeData->IsImeMirror()) {
        return { bindImeData };
    }

    if (mirrorImeData_ == nullptr) {
        return { bindImeData };
    }

    return { bindImeData, mirrorImeData_ };
}

void PerUserSession::RemoveImeData(pid_t pid)
{
    {
        std::lock_guard<std::mutex> lock(realImeDataLock_);
        if (realImeData_ != nullptr && realImeData_->pid == pid) {
            realImeData_ = nullptr;
        }
    }
    {
        std::lock_guard<std::mutex> lock(mirrorImeDataLock_);
        if (mirrorImeData_ != nullptr && mirrorImeData_->pid == pid) {
            mirrorImeData_ = nullptr;
        }
    }
    {
        std::lock_guard<std::mutex> lock(proxyImeDataLock_);
        for (auto iter = proxyImeData_.begin(); iter != proxyImeData_.end();) {
            auto &imeDataVec = iter->second;
            auto newEnd = std::remove_if(imeDataVec.begin(), imeDataVec.end(),
                [pid](const std::shared_ptr<ImeData> &data) { return data != nullptr && data->pid == pid; });
            imeDataVec.erase(newEnd, imeDataVec.end());
            if (imeDataVec.empty()) {
                iter = proxyImeData_.erase(iter);
            } else {
                ++iter;
            }
        }
    }
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
    auto clientGroup = GetClientGroup(WindowAdapter::GetDisplayIdByWindowId(windowId));
    auto clientInfo = clientGroup != nullptr ? clientGroup->GetCurrentClientInfo() : nullptr;
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

// TODO 注册者都注册到了group0里，之前都是一个group,现在会导致其他group屏幕操作（之前的屏幕在group0里）收不到
int32_t PerUserSession::OnUpdateListenEventFlag(const InputClientInfo &clientInfo)
{
    if (clientInfo.client == nullptr) {
        IMSA_HILOGE("clientInfo is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
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
    auto clientClient = clientGroup->GetCurrentClient();
    if (info->eventFlag == NO_EVENT_ON
        && (clientClient == nullptr || clientClient->AsObject() != clientInfo.client->AsObject())) {
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
    IMSA_HILOGD("windowId changed, refresh windowId info and notify clients input start.");
    clientInfo->config.windowId = callingWindowId;
    clientInfo->config.privateCommand.insert_or_assign(
        "displayId", PrivateDataValue(static_cast<int32_t>(callingDisplayId)));
    clientGroup->NotifyInputStartToClients(callingWindowId, static_cast<int32_t>(clientInfo->requestKeyboardReason));
    HandleWindowIdChanged(callingWindowId, clientInfo);
    return ErrorCode::NO_ERROR;
}

void PerUserSession::HandleWindowIdChanged(
    uint32_t callingWindowId, const std::shared_ptr<InputClientInfo> &currentClientInfo)
{
    if (callingWindowId == INVALID_WINDOW_ID) {
        return;
    }
    auto newDisplayId = WindowAdapter::GetDisplayIdByWindowId(callingWindowId);
    auto newDisplayGroupId = WindowAdapter::GetDisplayGroupId(newDisplayId);
    auto oldDisplayGroupId = currentClientInfo->clientGroupId;
    if (!IsSameClientGroup(oldDisplayGroupId, newDisplayGroupId)) {
        return;
    }
    uint64_t oldDisplayId = clientInfo->config.inputAttribute.callingDisplayId;
    clientInfo->config.inputAttribute.callingDisplayId = newDisplayId;
    if (!DisplayAdapter::IsImeShowable(newDisplayId)) {
        clientInfo->config.inputAttribute.callingDisplayId = DEFAULT_DISPLAY_ID;
        clientInfo->config.inputAttribute.isSpecifyMainDisplay = true;
    }
    newDisplayId = clientInfo->config.inputAttribute.callingDisplayId;
    if (oldDisplayId == newDisplayId) {
        return;
    }
    NotifyCallingDisplayChanged(newDisplayId, currentClientInfo->bindImeData);
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

bool PerUserSession::IsSameIme(const std::shared_ptr<ImeData> &oldIme, const std::shared_ptr<ImeData> &newIme)
{
    if (oldIme == nullptr) {
        return false;
    }
    if (newIme == nullptr) {
        return false;
    }
    return oldIme->pid == newIme->pid;
}

bool PerUserSession::IsSameImeType(const std::shared_ptr<ImeData> &oldIme, const std::shared_ptr<ImeData> &newIme)
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

int32_t PerUserSession::IsPanelShown(const PanelInfo &panelInfo, bool &isShown)
{
    auto clientGroup = GetClientGroup(DEFAULT_DISPLAY_ID);  // todo
    if (clientGroup == nullptr || clientGroup->GetCurrentClient() == nullptr) {
        IMSA_HILOGD("not in bound state.");
        isShown = false;
        return ErrorCode::NO_ERROR;
    }
    auto ime = GetRealImeData(true);
    if (ime == nullptr) {
        IMSA_HILOGE("ime not started!");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    return RequestIme(ime, RequestType::NORMAL, [&ime, &panelInfo, &isShown] {
        return ime->core->IsPanelShown(panelInfo, isShown);
    });
}

int32_t PerUserSession::RequestIme(const std::shared_ptr<ImeData> &data, RequestType type, const IpcExec &exec)
{
    if (data->type != ImeType::IME) {
        IMSA_HILOGD("proxy enable.");
        return exec();
    }
    if (data == nullptr || data->core == nullptr || data->imeStateManager == nullptr) {
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

int32_t PerUserSession::RequestAllIme(
    const std::shared_ptr<ImeData> &data, RequestType reqType, const CoreMethod &method)
{
    if (data == nullptr) {
        IMSA_HILOGW("no need to request, type:%{public}d}", reqType);
        return ErrorCode::NO_ERROR;
    }

    std::vector<std::shared_ptr<ImeData>> dataArray = { data };

    if (!data->IsImeMirror()) {
        if (mirrorImeData_ != nullptr) {
            dataArray.push_back(mirrorImeData_);
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
    auto data = GetRealImeData(true);
    if (data == nullptr) {
        IMSA_HILOGE("ime: %{public}d is not exist!", ImeType::IME);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto ret = RequestIme(data, RequestType::NORMAL, [&data, &channel, &agent] {
        return data->core->OnConnectSystemCmd(channel, agent);
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
    return realImeData_;
}

int32_t PerUserSession::FillImeData(
    sptr<IInputMethodCore> core, sptr<IRemoteObject> agent, pid_t pid, ImeType type, std::shared_ptr<ImeData> &imeData)
{
    if (core == nullptr || agent == nullptr) {
        IMSA_HILOGE("core or agent is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    imeData->imeStatus = ImeStatus::READY;
    imeData->type = type;
    imeData->core = core;
    imeData->agent = agent;
    imeData->pid = pid;
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
    return ErrorCode::NO_ERROR;
}

int32_t PerUserSession::InitConnect(pid_t pid)
{
    std::lock_guard<std::mutex> lock(realImeDataLock_);
    if (realImeData_ == nullptr) {
        return ErrorCode::ERROR_NULL_POINTER;
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
    auto [clientGroup, clientInfo] = GetCurrentClientBoundRealIme();
    if (clientInfo != nullptr) {
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
    auto imeData = GetRealImeData();
    if (imeData == nullptr) {
        return ErrorCode::NO_ERROR;
    }
    if (!ImeInfoInquirer::GetInstance().IsRunningIme(userId_, imeData->ime.first)) {
        IMSA_HILOGW("[%{public}s, %{public}s] already stop.", imeData->ime.first.c_str(), imeData->ime.second.c_str());
        ClearRealImeData();
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
    ClearRealImeData();
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

void PerUserSession::HandleBindImeChanged(const std::shared_ptr<InputClientInfo> &newClientInfo,
    const std::shared_ptr<ImeData> &newImeData, const std::shared_ptr<ClientGroup> &clientGroup)
{
    /* isClientInactive: true: represent the oldClientInfo is inactiveClient's
                         false: represent the oldClientInfo is currentClient's */
    std::shared_ptr<InputClientInfo> oldClientInfo = nullptr;
    if (clientGroup == nullptr || newClientInfo == nullptr) {
        IMSA_HILOGE("clientGroup is nullptr!");
        return;
    }
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
        if (IsSameClient(newClientInfo->client, oldClientInfo->client)
            && !IsSameIme(oldClientInfo->bindImeData, newImeData)) {
            newClientInfo->isNotifyInputStart = true;
        }
        if (IsSameImeType(oldClientInfo->bindImeData, newImeData)) {
            return;
        }
        // has current client, but new client is not current client
        if (!isClientInactive && !IsSameClient(newClientInfo->client, oldClientInfo->client)) {
            clientGroup->SetCurrentClient(nullptr);
            if (oldClientInfo->client != nullptr) {
                clientGroup->RemoveClientInfo(oldClientInfo->client->AsObject());
            }
        }
    }
    IMSA_HILOGD("isClientInactive: %{public}d!", isClientInactive);
    if (isClientInactive) {
        StopImeInput(oldClientInfo->bindImeData, oldClientInfo->channel, 0);
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

uint64_t PerUserSession::GetDisplayGroupId(uint64_t displayId)
{
    IMSA_HILOGD("displayId: %{public}" PRIu64 "", displayId);
    if (displayId == DEFAULT_DISPLAY_ID) {
        return DEFAULT_DISPLAY_ID;
    }
    return 10001; // todo
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
    auto [clientGroup, clientInfo] = GetClientByWindowId(windowId);
    if (clientGroup == nullptr || clientInfo == nullptr) {
        return;
    }
    auto oldGroupId = clientInfo->clientGroupId;
    auto newGroupId = WindowAdapter::GetDisplayGroupId(displayId);
    // 跨group的, 由attach处理
    if (!IsSameClientGroup(oldGroupId, newGroupId)) {
        return;
    }
    uint64_t oldDisplayId = clientInfo->config.inputAttribute.callingDisplayId;
    clientInfo->config.inputAttribute.callingDisplayId = displayId;
    if (!DisplayAdapter::IsImeShowable(displayId)) {
        clientInfo->config.inputAttribute.callingDisplayId = DEFAULT_DISPLAY_ID;
        clientInfo->config.inputAttribute.isSpecifyMainDisplay = true;
    }
    auto newDisplayId = clientInfo->config.inputAttribute.callingDisplayId;
    if (oldDisplayId == newDisplayId) {
        return;
    }
    NotifyCallingDisplayChanged(newDisplayId, clientInfo->bindImeData);
}

int32_t PerUserSession::NotifyCallingDisplayChanged(uint64_t displayId, const std::shared_ptr<ImeData> &bindImeData)
{
    IMSA_HILOGD("enter displayId:%{public}" PRIu64 "", displayId);
    if (bindImeData == nullptr || !bindImeData->IsRealIme()) {
        IMSA_HILOGD("bind ime not real ime");
        ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto callBack = [&bindImeData, displayId]() -> int32_t {
        bindImeData->core->OnCallingDisplayIdChanged(displayId);
        return ErrorCode::NO_ERROR;
    };
    auto ret = RequestIme(bindImeData, RequestType::NORMAL, callBack);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("notify calling window display changed failed, ret: %{public}d!", ret);
    }
    return ret;
}

ImfCallingWindowInfo PerUserSession::GetFinalCallingWindowInfo(const InputClientInfo &clientInfo)
{
    auto windowInfo = GetCallingWindowInfo(clientInfo);
    windowInfo.displayId = DisplayAdapter::GetFinalDisplayId(windowInfo.displayId);
    return windowInfo;
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
        false :
        clientInfo->config.isSimpleKeyboardEnabled;

    auto callingWindowInfo = GetCallingWindowInfo(*clientInfo);
    return ImeInfoInquirer::GetInstance().IsRestrictedDefaultImeByDisplay(callingWindowInfo.displayId) ||
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

int32_t PerUserSession::PrepareImeInfos(const std::shared_ptr<ImeData> &bindImeData,
    std::vector<sptr<IRemoteObject>> &agents, std::vector<BindImeInfo> &imeInfos)
{
    auto allData = GetAllReadyImeData(bindImeData);
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

bool PerUserSession::IsEnable(const std::shared_ptr<ImeData> &data)
{
    bool ret = false;
    if (data == nullptr || data->core == nullptr) {
        return false;
    }
    data->core->IsEnable(ret);
    return ret;
}
} // namespace MiscServices
} // namespace OHOS