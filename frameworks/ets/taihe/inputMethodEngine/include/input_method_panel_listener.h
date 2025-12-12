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

#ifndef INPUTMETHOD_PANEL_LISTENER_H
#define INPUTMETHOD_PANEL_LISTENER_H

#include <mutex>
#include <thread>
#include <tuple>
#include <uv.h>
#include <shared_mutex>

#include "ani_common_engine.h"
#include "concurrent_map.h"
#include "panel_status_listener.h"
#include "panel_common.h"
#include "event_handler.h"
namespace OHOS {
namespace MiscServices {
class InputMethodPanelListener : public PanelStatusListener {
public:
    static std::shared_ptr<InputMethodPanelListener> GetInstance();
    ~InputMethodPanelListener();
    void OnPanelStatus(uint32_t windowId, bool isShow) override;
    void OnSizeChange(uint32_t windowId, const WindowSize &size) override;
    void OnSizeChange(uint32_t windowId, const WindowSize &size, const PanelAdjustInfo &keyboardArea,
        const std::string &event) override;
    void Subscribe(uint32_t windowId, const std::string &type, callbackTypes &&cb, uintptr_t opq);
    void RemoveInfo(uint32_t windowId, const std::string &type);
    void SetEventHandler(std::shared_ptr<AppExecFwk::EventHandler> handler);

private:
    std::shared_ptr<CallbackObjects> GetCallback(uint32_t windowId, const std::string &type);
    std::mutex mutex_;
    ConcurrentMap<uint32_t, std::map<std::string, std::shared_ptr<CallbackObjects>>> jsCbMap_;
    static std::mutex listenerMutex_;
    static std::shared_ptr<InputMethodPanelListener> instance_;
    mutable std::shared_mutex eventHandlerMutex_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
};
} // namespace MiscServices
} // namespace OHOS

#endif //INPUTMETHOD_PANEL_LISTENER_H