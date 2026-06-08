/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ime_event_listener_manager.h"

#include <cinttypes>

#include "event_status_manager.h"
#include "global.h"
#include "input_client_info.h"
#include "window_adapter.h"

namespace OHOS {
namespace MiscServices {

ImeEventListenerManager &ImeEventListenerManager::GetInstance()
{
    static ImeEventListenerManager imeEventListenerManager;
    return imeEventListenerManager;
}

int32_t ImeEventListenerManager::UpdateListenerInfo(int32_t userId, const ImeEventListenerInfo &info)
{
    ImeEventListenerInfo imeListenerInfo = info;
    std::lock_guard<std::mutex> lock(imeEventListenersLock_);
    auto &listenerVec = imeEventListeners_[userId];
    IMSA_HILOGI("ImeEventListenerManager, pid/eventFlag: %{public}" PRId64 "/%{public}u", imeListenerInfo.pid,
        imeListenerInfo.eventFlag);
    auto iter = std::find_if(
        listenerVec.begin(), listenerVec.end(), [&imeListenerInfo](const ImeEventListenerInfo &listenerInfo) {
            return (listenerInfo.pid == imeListenerInfo.pid);
        });
    if (iter == listenerVec.end()) {
        AddDeathRecipient(userId, imeListenerInfo);
        listenerVec.push_back(imeListenerInfo);
        return ErrorCode::NO_ERROR;
    }
    iter->eventFlag = imeListenerInfo.eventFlag;
    if (iter->eventFlag == ImeEventListenerInfo::NO_EVENT_ON) {
        listenerVec.erase(iter);
    }
    if (listenerVec.empty()) {
        imeEventListeners_.erase(userId);
    }
    return ErrorCode::NO_ERROR;
}

std::vector<ImeEventListenerInfo> ImeEventListenerManager::GetListenerInfo(int32_t userId)
{
    std::lock_guard<std::mutex> lock(imeEventListenersLock_);
    std::vector<ImeEventListenerInfo> allListenerInfos;
    auto it = imeEventListeners_.find(userId);
    if (it != imeEventListeners_.end()) {
        allListenerInfos = it->second;
    }
    // 0 present user 0
    if (userId == 0) {
        return allListenerInfos;
    }
    auto iter = imeEventListeners_.find(0);
    if (iter == imeEventListeners_.end()) {
        return allListenerInfos;
    }
    allListenerInfos.insert(allListenerInfos.end(), iter->second.begin(), iter->second.end());
    return allListenerInfos;
}

int32_t ImeEventListenerManager::AddDeathRecipient(int32_t userId, ImeEventListenerInfo &listenerInfo)
{
    IMSA_HILOGI("enter.");
    if (listenerInfo.client == nullptr) {
        IMSA_HILOGE("listenerInfo.client is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    listenerInfo.deathRecipient = new (std::nothrow) InputDeathRecipient();
    if (listenerInfo.deathRecipient == nullptr) {
        IMSA_HILOGE("failed to new deathRecipient!");
        return ErrorCode::ERROR_IMSA_MALLOC_FAILED;
    }
    listenerInfo.deathRecipient->SetDeathRecipient(
        [this, client = listenerInfo.client, userId](
            const wptr<IRemoteObject> &object) { OnListenerDied(userId, client); });
    auto obj = listenerInfo.client->AsObject();
    if (obj == nullptr) {
        IMSA_HILOGE("client obj is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    if (obj->IsProxyObject() && !obj->AddDeathRecipient(listenerInfo.deathRecipient)) {
        IMSA_HILOGE("failed to add client death recipient!");
        return ErrorCode::ERROR_ADD_DEATH_RECIPIENT_FAILED;
    }
    return ErrorCode::NO_ERROR;
}
// LCOV_EXCL_START
void ImeEventListenerManager::OnListenerDied(int32_t userId, const sptr<IInputClient> &remote)
{
    if (remote == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(imeEventListenersLock_);
    auto it = imeEventListeners_.find(userId);
    if (it == imeEventListeners_.end()) {
        return;
    }
    auto &listenerVec = it->second;
    auto iter = std::find_if(listenerVec.begin(), listenerVec.end(), [remote](const ImeEventListenerInfo &info) {
        return (info.client != nullptr && remote != nullptr && info.client->AsObject() == remote->AsObject());
    });
    if (iter == listenerVec.end()) {
        return;
    }
    IMSA_HILOGI("%{public}" PRIu64 " died.", iter->pid);
    if (iter->deathRecipient != nullptr) {
        auto object = remote->AsObject();
        if (object != nullptr) {
            IMSA_HILOGD("deathRecipient remove.");
            object->RemoveDeathRecipient(iter->deathRecipient);
        }
    }
    listenerVec.erase(iter);
    if (listenerVec.empty()) {
        imeEventListeners_.erase(userId);
    }
}

int32_t ImeEventListenerManager::NotifySoftKeyBoardInfoChanged(
    int32_t userId, const BoundImeInfo &oldImeInfo, const BoundImeInfo &newImeInfo)
{
    IMSA_HILOGD("userId/oldInfo/newInfo: %{public}d/%{public}s/%{public}s.", userId, oldImeInfo.ToString().c_str(),
        newImeInfo.ToString().c_str());
    auto listenerInfos = GetListenerInfo(userId);
    for (const auto &listenerInfo : listenerInfos) {
        if (listenerInfo.client == nullptr) {
            IMSA_HILOGD("client nullptr or no need to notify.");
            continue;
        }
        if (!EventStatusManager::IsSoftKeyboardInfoChangedOn(listenerInfo.eventFlag)) {
            continue;
        }
        int32_t ret = listenerInfo.client->NotifySoftKeyBoardInfoChanged(userId, oldImeInfo, newImeInfo);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("failed to NotifySoftKeyBoardInfoChanged, ret: %{public}d", ret);
            continue;
        }
    }
    return ErrorCode::NO_ERROR;
}

int32_t ImeEventListenerManager::NotifyInputStart(int32_t userId, const InputStartInfo &inputStartInfo)
{
    IMSA_HILOGD("inputStartInfo: %{public}s.", inputStartInfo.ToString().c_str());
    auto listenerInfos = GetListenerInfo(userId);
    for (const auto &listenerInfo : listenerInfos) {
        if (listenerInfo.client == nullptr || !EventStatusManager::IsInputStatusChangedOn(listenerInfo.eventFlag)) {
            IMSA_HILOGD("nullptr listenerInfo or no need to notify");
            continue;
        }
        IMSA_HILOGD("pid/eventFlag: %{public}" PRId64 "/%{public}u", listenerInfo.pid, listenerInfo.eventFlag);
        int32_t ret = listenerInfo.client->NotifyInputStart(inputStartInfo);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("failed to notify OnInputStart, errorCode: %{public}d", ret);
            continue;
        }
    }
    return ErrorCode::NO_ERROR;
}

int32_t ImeEventListenerManager::NotifyInputStop(int32_t userId, const InputStopInfo &inputStopInfo)
{
    IMSA_HILOGD("inputStopInfo: %{public}s.", inputStopInfo.ToString().c_str());
    auto listenerInfos = GetListenerInfo(userId);
    for (const auto &listenerInfo : listenerInfos) {
        if (listenerInfo.client == nullptr || !EventStatusManager::IsInputStatusChangedOn(listenerInfo.eventFlag)) {
            IMSA_HILOGD("nullptr clientInfo or no need to notify");
            continue;
        }
        IMSA_HILOGD("pid/eventFlag: %{public}" PRId64 "/%{public}u", listenerInfo.pid, listenerInfo.eventFlag);
        int32_t ret = listenerInfo.client->NotifyInputStop(inputStopInfo);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("failed to notify OnInputStop, errorCode: %{public}d", ret);
            continue;
        }
    }
    return ErrorCode::NO_ERROR;
}

int32_t ImeEventListenerManager::NotifyPanelStatusChange(
    int32_t userId, const InputWindowStatus &status, const ImeWindowInfo &info)
{
    auto listenerInfos = GetListenerInfo(userId);
    for (const auto &listenerInfo : listenerInfos) {
        if (listenerInfo.client == nullptr) {
            IMSA_HILOGD("client nullptr or no need to notify.");
            continue;
        }
        if (status == InputWindowStatus::SHOW && !EventStatusManager::IsImeShowOn(listenerInfo.eventFlag)) {
            IMSA_HILOGD("has not imeShow callback");
            continue;
        }
        if (status == InputWindowStatus::HIDE && !EventStatusManager::IsImeHideOn(listenerInfo.eventFlag)) {
            IMSA_HILOGD("has not imeHide callback");
            continue;
        }
        ImeWindowInfo updatedInfo = info;
        updatedInfo.windowInfo.userId = userId;
        int32_t ret = listenerInfo.client->OnPanelStatusChange(static_cast<uint32_t>(status), updatedInfo);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("failed to NotifyPanelStatusChange, ret: %{public}d", ret);
            continue;
        }
    }
    return ErrorCode::NO_ERROR;
}

int32_t ImeEventListenerManager::NotifyImeChange(
    int32_t userId, const Property &property, const SubProperty &subProperty)
{
    IMSA_HILOGI("enter.");
    auto listenerInfos = GetListenerInfo(userId);
    for (const auto &listenerInfo : listenerInfos) {
        if (listenerInfo.client == nullptr || !EventStatusManager::IsImeChangeOn(listenerInfo.eventFlag)) {
            IMSA_HILOGD("client nullptr or no need to notify.");
            continue;
        }
        IMSA_HILOGI("pid/eventFlag: %{public}" PRId64 "/%{public}u", listenerInfo.pid, listenerInfo.eventFlag);
        int32_t ret = listenerInfo.client->OnSwitchInput(property, subProperty, userId);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("notify failed, ret: %{public}d, pid: %{public}" PRId64 "!", ret, listenerInfo.pid);
            continue;
        }
    }
    return ErrorCode::NO_ERROR;
}
// LCOV_EXCL_STOP
} // namespace MiscServices
} // namespace OHOS
