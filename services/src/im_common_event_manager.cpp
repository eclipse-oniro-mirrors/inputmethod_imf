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

#include "im_common_event_manager.h"

#include <utility>

#include "global.h"
#include "ime_info_inquirer.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "itypes_util.h"
#include "message_handler.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace MiscServices {
using namespace MessageID;
sptr<ImCommonEventManager> ImCommonEventManager::instance_;
std::mutex ImCommonEventManager::instanceLock_;
using namespace OHOS::EventFwk;
constexpr const char *COMMON_EVENT_INPUT_PANEL_STATUS_CHANGED = "usual.event.imf.input_panel_status_changed";
constexpr const char *COMMON_EVENT_PARAM_PANEL_STATE = "panelState";
constexpr const char *COMMON_EVENT_PARAM_PANEL_RECT = "panelRect";
ImCommonEventManager::ImCommonEventManager()
{
}

ImCommonEventManager::~ImCommonEventManager()
{
}

sptr<ImCommonEventManager> ImCommonEventManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            IMSA_HILOGI("ImCommonEventManager::GetInstance instance_ is nullptr");
            instance_ = new ImCommonEventManager();
        }
    }
    return instance_;
}

bool ImCommonEventManager::SubscribeEvents()
{
    sptr<ISystemAbilityStatusChange> listener = new (std::nothrow) SystemAbilityStatusChangeListener([](bool isAdd) {
        if (isAdd) {
            EventFwk::MatchingSkills matchingSkills;
            matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
            matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_REMOVED);
            matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
            matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
            matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
            EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
            auto subscriber = std::make_shared<EventSubscriber>(subscriberInfo);
            bool ret = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber);
            IMSA_HILOGI("SubscribeCommonEvent ret = %{public}d", ret);
        }
    });
    if (listener == nullptr) {
        IMSA_HILOGE("listener is nullptr");
        return false;
    }
    return SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, listener);
}

bool ImCommonEventManager::SubscribeService(int32_t saId, const SaHandler &handler)
{
    sptr<ISystemAbilityStatusChange> listener = new (std::nothrow)
        SystemAbilityStatusChangeListener([handler](bool isAdd) {
            if (handler != nullptr) {
                handler(isAdd);
            }
        });
    if (listener == nullptr) {
        IMSA_HILOGE("failed to create sa %{public}d listener", saId);
        return false;
    }
    return SubscribeSystemAbility(saId, listener);
}

bool ImCommonEventManager::SubscribeSystemAbility(int32_t saId, const sptr<ISystemAbilityStatusChange> &listener)
{
    auto abilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (abilityManager == nullptr) {
        IMSA_HILOGE("abilityManager is nullptr");
        return false;
    }
    int32_t ret = abilityManager->SubscribeSystemAbility(saId, listener);
    if (ret != ERR_OK) {
        IMSA_HILOGE("subscribe sa %{public}d failed, ret = %{public}d", saId, ret);
        return false;
    }
    return true;
}

bool ImCommonEventManager::UnsubscribeEvent()
{
    return true;
}

ImCommonEventManager::EventSubscriber::EventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{
    EventManagerFunc_[CommonEventSupport::COMMON_EVENT_USER_SWITCHED] = &EventSubscriber::StartUser;
    EventManagerFunc_[CommonEventSupport::COMMON_EVENT_USER_REMOVED] = &EventSubscriber::RemoveUser;
    EventManagerFunc_[CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED] = &EventSubscriber::RemovePackage;
    EventManagerFunc_[CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED] = &EventSubscriber::OnBundleScanFinished;
    EventManagerFunc_[CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED] = &EventSubscriber::OnBootCompleted;
}

void ImCommonEventManager::EventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto const &want = data.GetWant();
    std::string action = want.GetAction();
    IMSA_HILOGI("ImCommonEventManager::action = %{public}s!", action.c_str());
    auto iter = EventManagerFunc_.find(action);
    if (iter == EventManagerFunc_.end()) {
        return;
    }
    auto EventListenerFunc = iter->second;
    if (EventListenerFunc != nullptr) {
        (this->*EventListenerFunc)(data);
    }
}

void ImCommonEventManager::EventSubscriber::StartUser(const CommonEventData &data)
{
    auto newUserId = data.GetCode();
    IMSA_HILOGI("ImCommonEventManager::StartUser, userId = %{public}d", newUserId);
    MessageParcel *parcel = new MessageParcel();
    parcel->WriteInt32(newUserId);
    Message *msg = new Message(MessageID::MSG_ID_USER_START, parcel);
    MessageHandler::Instance()->SendMessage(msg);
}

void ImCommonEventManager::EventSubscriber::OnBundleScanFinished(const EventFwk::CommonEventData &data)
{
    IMSA_HILOGI("ImCommonEventManager in");
    auto parcel = new (std::nothrow) MessageParcel();
    if (parcel == nullptr) {
        IMSA_HILOGE("failed to create MessageParcel");
        return;
    }
    auto msg = new (std::nothrow) Message(MessageID::MSG_ID_BUNDLE_SCAN_FINISHED, parcel);
    if (msg == nullptr) {
        IMSA_HILOGE("failed to create Message");
        delete parcel;
        return;
    }
    MessageHandler::Instance()->SendMessage(msg);
}

void ImCommonEventManager::EventSubscriber::OnBootCompleted(const EventFwk::CommonEventData &data)
{
    IMSA_HILOGI("ImCommonEventManager in");
    auto parcel = new (std::nothrow) MessageParcel();
    if (parcel == nullptr) {
        IMSA_HILOGE("failed to create MessageParcel");
        return;
    }
    auto msg = new (std::nothrow) Message(MessageID::MSG_ID_BOOT_COMPLETED, parcel);
    if (msg == nullptr) {
        IMSA_HILOGE("failed to create Message");
        delete parcel;
        return;
    }
    MessageHandler::Instance()->SendMessage(msg);
}

void ImCommonEventManager::EventSubscriber::RemoveUser(const CommonEventData &data)
{
    auto userId = data.GetCode();
    IMSA_HILOGI("ImCommonEventManager::RemoveUser, userId = %{public}d", userId);
    MessageParcel *parcel = new MessageParcel();
    parcel->WriteInt32(userId);
    Message *msg = new Message(MessageID::MSG_ID_USER_REMOVED, parcel);
    MessageHandler::Instance()->SendMessage(msg);
}

void ImCommonEventManager::EventSubscriber::RemovePackage(const CommonEventData &data)
{
    auto const &want = data.GetWant();
    auto element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    int32_t userId = want.GetIntParam("userId", 0);
    IMSA_HILOGD("ImCommonEventManager::RemovePackage, bundleName = %{public}s, userId = %{public}d",
        bundleName.c_str(), userId);
    MessageParcel *parcel = new (std::nothrow) MessageParcel();
    if (parcel == nullptr) {
        IMSA_HILOGE("parcel is nullptr");
        return;
    }
    if (!ITypesUtil::Marshal(*parcel, userId, bundleName)) {
        IMSA_HILOGE("Failed to write message parcel");
        delete parcel;
        return;
    }
    Message *msg = new Message(MessageID::MSG_ID_PACKAGE_REMOVED, parcel);
    MessageHandler::Instance()->SendMessage(msg);
}

ImCommonEventManager::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(SaHandler func)
    : func_(std::move(func))
{
}

void ImCommonEventManager::SystemAbilityStatusChangeListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    IMSA_HILOGD("systemAbilityId: %{public}d", systemAbilityId);
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID && systemAbilityId != MULTIMODAL_INPUT_SERVICE_ID &&
        systemAbilityId != WINDOW_MANAGER_SERVICE_ID && systemAbilityId != SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN &&
        systemAbilityId != MEMORY_MANAGER_SA_ID) {
        return;
    }
    if (func_ != nullptr) {
        func_(true);
    }
}

void ImCommonEventManager::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    IMSA_HILOGD("systemAbilityId: %{public}d", systemAbilityId);
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID && systemAbilityId != MULTIMODAL_INPUT_SERVICE_ID &&
        systemAbilityId != WINDOW_MANAGER_SERVICE_ID && systemAbilityId != SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN &&
        systemAbilityId != MEMORY_MANAGER_SA_ID) {
        return;
    }
    if (func_ != nullptr) {
        func_(false);
    }
}

int32_t ImCommonEventManager::PublishPanelStatusChangeEvent(const InputWindowStatus &status, const ImeWindowInfo &info)
{
    EventFwk::CommonEventPublishInfo publicInfo;
    publicInfo.SetOrdered(false);
    AAFwk::Want want;
    want.SetAction(COMMON_EVENT_INPUT_PANEL_STATUS_CHANGED);
    bool visible = (status == InputWindowStatus::SHOW);
    std::vector<int32_t> panelRect = { info.windowInfo.left, info.windowInfo.top,
        static_cast<int32_t>(info.windowInfo.width), static_cast<int32_t>(info.windowInfo.height) };
    want.SetParam(COMMON_EVENT_PARAM_PANEL_STATE, visible);
    want.SetParam(COMMON_EVENT_PARAM_PANEL_RECT, panelRect);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    return EventFwk::CommonEventManager::NewPublishCommonEvent(data, publicInfo);
}
} // namespace MiscServices
} // namespace OHOS
