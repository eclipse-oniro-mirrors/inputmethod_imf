/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_IME_EVENT_MONITOR_MANAGER_IMPL_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_IME_EVENT_MONITOR_MANAGER_IMPL_H

#include <map>
#include <set>

#include "ime_event_listener.h"
#include "visibility.h"

namespace OHOS {
namespace MiscServices {
class ImeEventMonitorManagerImpl {
public:
    IMF_API static ImeEventMonitorManagerImpl &GetInstance();
    IMF_API int32_t RegisterImeEventListener(uint32_t eventFlag, const std::shared_ptr<ImeEventListener> &listener);
    IMF_API int32_t UnRegisterImeEventListener(uint32_t eventFlag, const std::shared_ptr<ImeEventListener> &listener);
    int32_t OnImeChange(const Property &property, const SubProperty &subProperty);
    int32_t OnPanelStatusChange(const InputWindowStatus &status, const ImeWindowInfo &info);

private:
    ImeEventMonitorManagerImpl();
    ~ImeEventMonitorManagerImpl();
    static constexpr uint32_t MAX_EVENT_NUM = 3;
    int32_t OnImeShow(const ImeWindowInfo &info);
    int32_t OnImeHide(const ImeWindowInfo &info);
    std::set<std::shared_ptr<ImeEventListener>> GetListeners(uint32_t eventMask);
    std::mutex lock_;
    std::map<uint32_t, std::set<std::shared_ptr<ImeEventListener>>> listeners_{};
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_IME_EVENT_MONITOR_MANAGER_IMPL_H