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

#include "../adapter/keyboard/keyboard_event.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "matching_skills.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace MiscServices {
class ImCommonEventManager : public RefBase {
public:
    ImCommonEventManager();
    ~ImCommonEventManager();
    static sptr<ImCommonEventManager> GetInstance();
    bool SubscribeEvent(const std::string &event);
    bool SubscribeKeyboardEvent(const std::vector<KeyboardEventHandler> &handlers);

    bool UnsubscribeEvent();
    class EventSubscriber : public EventFwk::CommonEventSubscriber {
    public:
        EventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
            : EventFwk::CommonEventSubscriber(subscribeInfo)
        {
        }
        void OnReceiveEvent(const EventFwk::CommonEventData &data);
        void DealWithRemoveEvent(const AAFwk::Want &want, const std::string action);
        void startUser(int32_t newUserId);
    };

private:
    class SystemAbilityStatusChangeListener : public SystemAbilityStatusChangeStub {
    public:
        explicit SystemAbilityStatusChangeListener(std::function<void()>);
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

    private:
        std::function<void()> func_ = nullptr;
    };

private:
    static std::mutex instanceLock_;

    static sptr<ImCommonEventManager> instance_;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
    sptr<ISystemAbilityStatusChange> keyboardEventListener_ = nullptr;
};
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_IM_COMMON_EVENT_MANAGER_H
