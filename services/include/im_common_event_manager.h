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

#ifndef SERVICES_INCLUDE_IM_COMMON_EVENT_MANAGER_H
#define SERVICES_INCLUDE_IM_COMMON_EVENT_MANAGER_H

#include <functional>
#include <mutex>
#include <vector>

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "focus_monitor_manager.h"
#include "input_window_info.h"
#include "keyboard_event.h"
#include "matching_skills.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace MiscServices {
using Handler = std::function<void()>;
using SaHandler = std::function<void(bool)>;
class ImCommonEventManager : public RefBase {
public:
    static sptr<ImCommonEventManager> GetInstance();
    bool SubscribeEvents();
    bool SubscribeService(int32_t saId, const SaHandler &handler);
    bool SubscribeKeyboardEvent(KeyHandle handle);
    bool SubscribeWindowManagerService(FocusHandle handle, SaHandler inputHandler);
    bool UnsubscribeEvent();
    // only public the status change of softKeyboard in FLG_FIXED or FLG_FLOATING
    int32_t PublishPanelStatusChangeEvent(const InputWindowStatus &status, const ImeWindowInfo &info);
    class EventSubscriber : public EventFwk::CommonEventSubscriber {
    public:
        EventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo);
        void OnReceiveEvent(const EventFwk::CommonEventData &data);
        void RemovePackage(const EventFwk::CommonEventData &data);
        void StartUser(const EventFwk::CommonEventData &data);
        void RemoveUser(const EventFwk::CommonEventData &data);
        void OnBundleScanFinished(const EventFwk::CommonEventData &data);
        void OnBootCompleted(const EventFwk::CommonEventData &data);

    private:
        using EventListenerFunc = void (EventSubscriber::*)(const EventFwk::CommonEventData &data);
        std::map<std::string, EventListenerFunc> EventManagerFunc_;
    };

private:
    class SystemAbilityStatusChangeListener : public SystemAbilityStatusChangeStub {
    public:
        explicit SystemAbilityStatusChangeListener(SaHandler func);
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

    private:
        SaHandler func_ = nullptr;
    };

private:
    ImCommonEventManager();
    ~ImCommonEventManager();
    bool SubscribeSystemAbility(int32_t saId, const sptr<ISystemAbilityStatusChange> &listener);
    static std::mutex instanceLock_;
    static sptr<ImCommonEventManager> instance_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_IM_COMMON_EVENT_MANAGER_H
