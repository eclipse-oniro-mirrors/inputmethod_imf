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
#ifndef TAIHE_PROXY_KEYBOARD_DELEGATE_IMPL_H
#define TAIHE_PROXY_KEYBOARD_DELEGATE_IMPL_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ani_common_engine.h"
#include "event_handler.h"
#include "event_runner.h"
#include "input_method_ability.h"
#include "key_event_consumer_proxy.h"
#include "keyboard_listener.h"
#include "ohos.inputMethodEngine.impl.hpp"
#include "ohos.inputMethodEngine.proj.hpp"
#include "proxy_listener_base.h"

namespace OHOS {
namespace MiscServices {
class ProxyKeyboardDelegateImpl : public KeyboardListener, public ProxyListenerBase {
public:
    static std::shared_ptr<ProxyKeyboardDelegateImpl> GetInstance();
    void OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height) override;
    void OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd) override;
    void OnTextChange(const std::string &text) override;
    void OnEditorAttributeChange(const InputAttribute &inputAttribute) override;
    bool OnDealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId,
        const sptr<IRemoteObject> &channelObject) override;
    void RegisterListenerEvent(std::string const &type,
        taihe::callback_view<bool(KeyEvent_t const &event)> callback);
    void UnRegisterListenerEvent(std::string const &type,
        taihe::optional_view<taihe::callback<bool(KeyEvent_t const &event)>> callback);

protected:
    static void DealKeyEvent(std::vector<taihe::callback<bool(KeyEvent_t const &event)>> eventCallbacks,
        const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId, const sptr<IRemoteObject> &channelObject);

private:
    static std::shared_ptr<AppExecFwk::EventHandler> GetHandler();
    static std::mutex keyboardMutex_;
    static std::mutex handlerMutex_;
    static std::shared_ptr<ProxyKeyboardDelegateImpl> keyboardDelegate_;
    static std::shared_ptr<AppExecFwk::EventHandler> handler_;
    static std::mutex eventMutex_;
    static std::map<std::string, std::vector<taihe::callback<bool(KeyEvent_t const &event)>>> eventCbMap_;
};

class IMFProxyKeyboardDelegateImpl {
public:
    IMFProxyKeyboardDelegateImpl()
    {
        InputMethodAbility::GetInstance().SetKdListener(ProxyKeyboardDelegateImpl::GetInstance());
    }

    void OnKeyEvent(taihe::callback_view<bool(KeyEvent_t const &event)> callback)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->RegisterListenerEvent("keyEvent", callback);
    }

    void OffKeyEvent(taihe::optional_view<taihe::callback<bool(KeyEvent_t const &event)>> callback)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->UnRegisterListenerEvent("keyEvent", callback);
    }

    void OnCursorContextChange(taihe::callback_view<void(double, double, double)> callback, uintptr_t opq)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->RegisterListener("cursorContextChange", callback, opq);
    }

    void OffCursorContextChange(taihe::optional_view<uintptr_t> opq)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->UnRegisterListener("cursorContextChange", opq);
    }

    void OnSelectionChange(taihe::callback_view<void(int32_t, int32_t, int32_t, int32_t)> callback, uintptr_t opq)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->RegisterListener("selectionChange", callback, opq);
    }

    void OffSelectionChange(taihe::optional_view<uintptr_t> opq)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->UnRegisterListener("selectionChange", opq);
    }

    void OnTextChange(taihe::callback_view<void(taihe::string_view)> callback, uintptr_t opq)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->RegisterListener("textChange", callback, opq);
    }

    void OffTextChange(taihe::optional_view<uintptr_t> opq)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->UnRegisterListener("textChange", opq);
    }

    void OnEditorAttributeChanged(taihe::callback_view<void(EditorAttribute_t const &)> callback, uintptr_t opq)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->RegisterListener("editorAttributeChanged", callback, opq);
    }

    void OffEditorAttributeChanged(taihe::optional_view<uintptr_t> opq)
    {
        ProxyKeyboardDelegateImpl::GetInstance()->UnRegisterListener("editorAttributeChanged", opq);
    }
};
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_PROXY_KEYBOARD_DELEGATE_IMPL_H
