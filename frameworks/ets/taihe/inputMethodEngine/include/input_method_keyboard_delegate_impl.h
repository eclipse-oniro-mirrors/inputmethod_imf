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
#ifndef TAIHE_INPUT_METHOD_KEYBOARD_DELEGATE_IMPL_H
#define TAIHE_INPUT_METHOD_KEYBOARD_DELEGATE_IMPL_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ani_common_engine.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "key_event_consumer_proxy.h"
#include "keyboard_listener.h"
#include "input_method_ability.h"
#include "event_handler.h"
#include "event_runner.h"

namespace OHOS {
namespace MiscServices {
class KeyboardDelegateImpl : public KeyboardListener {
public:
    static std::shared_ptr<KeyboardDelegateImpl> GetInstance();
    static ani_ref GetKeyboardDelegateInstance(ani_env *env);
    void RegisterListener(std::string const &type, callbackTypes &&cb, uintptr_t opq);
    void UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq);
    void RegisterListenerEvent(std::string const &type,
        taihe::callback_view<bool(::ohos::multimodalInput::keyEvent::KeyEvent const& event)> callback);
    void UnRegisterListenerEvent(std::string const &type, 
        taihe::optional_view<taihe::callback<bool(::ohos::multimodalInput::keyEvent::KeyEvent const& event)>> callback);
    bool OnKeyEvent(int32_t keyCode, int32_t keyStatus, sptr<KeyEventConsumerProxy> &consumer) override;
    bool OnKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, sptr<KeyEventConsumerProxy> &consumer) override;
    void OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height) override;
    void OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd) override;
    void OnTextChange(const std::string &text) override;
    void OnEditorAttributeChange(const InputAttribute &inputAttribute) override;
    bool OnDealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId,
        const sptr<IRemoteObject> &channelObject) override;
    void OnKeyEventConsumeResult(bool isConsumed, sptr<KeyEventConsumerProxy> consumer);
    void OnKeyCodeConsumeResult(bool isConsumed, sptr<KeyEventConsumerProxy> consumer);
private:
    static std::mutex mutex_;
    static std::map<std::string, std::vector<std::unique_ptr<CallbackObjects>>> jsCbMap_;

    static std::map<std::string, std::vector<taihe::callback_view<bool(KeyEvent_t const& event)>>> eventCbMap_;
    static std::mutex keyboardMutex_;
    static ani_ref KCERef_;
    static std::shared_ptr<KeyboardDelegateImpl> keyboardDelegate_;
    static ani_vm* GetAniVm(ani_env* env);
    static ani_env* GetAniEnv(ani_vm* vm);
    static ani_env* AttachAniEnv(ani_vm* vm);
    static ani_env* env_;
    static ani_vm* vm_;
    static std::shared_ptr<AppExecFwk::EventHandler> handler_;
    static void DealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent,
        uint64_t cbId, const sptr<IRemoteObject> &channelObject);

    bool keyEventConsume_ = false;
    bool keyCodeConsume_ = false;
    bool keyEventResult_ = false;
    bool keyCodeResult_ = false;
};

class IMFKeyboardDelegateImpl {
    public:
    IMFKeyboardDelegateImpl()
    {
        InputMethodAbility::GetInstance().SetKdListener(KeyboardDelegateImpl::GetInstance());
    }

    void OnKeyDown(taihe::callback_view<bool(KeyEventType_t const&)> callback, uintptr_t opq)
    {
        KeyboardDelegateImpl::GetInstance()->RegisterListener("keyDown", callback, opq);
    }

    void OffKeyDown(taihe::optional_view<uintptr_t> opq)
    {
        KeyboardDelegateImpl::GetInstance()->UnRegisterListener("keyDown", opq);
    }

    void OnKeyUp(taihe::callback_view<bool(KeyEventType_t const&)> callback, uintptr_t opq)
    {
        KeyboardDelegateImpl::GetInstance()->RegisterListener("keyUp", callback, opq);
    }

    void OffKeyUp(taihe::optional_view<uintptr_t> opq)
    {
        KeyboardDelegateImpl::GetInstance()->UnRegisterListener("keyUp", opq);
    }

    void OnKeyEvent(taihe::callback_view<bool(KeyEvent_t const& event)> callback)
    {
        KeyboardDelegateImpl::GetInstance()->RegisterListenerEvent("keyEvent", callback);
    }

    void OffKeyEvent(
        taihe::optional_view<taihe::callback<bool(KeyEvent_t const& event)>> callback)
    {
        KeyboardDelegateImpl::GetInstance()-> UnRegisterListenerEvent("keyEvent", callback);
    }

    void OnCursorContextChange(taihe::callback_view<void(int32_t, int32_t, int32_t)> callback, uintptr_t opq)
    {
        KeyboardDelegateImpl::GetInstance()->RegisterListener("cursorContextChange", callback, opq);
    }

    void OffCursorContextChange(taihe::optional_view<uintptr_t> opq)
    {
        KeyboardDelegateImpl::GetInstance()->UnRegisterListener("cursorContextChange", opq);
    }

    void OnSelectionChange(taihe::callback_view<void(int32_t, int32_t, int32_t, int32_t)> callback, uintptr_t opq)
    {
        KeyboardDelegateImpl::GetInstance()->RegisterListener("selectionChange", callback, opq);
    }

    void OffSelectionChange(taihe::optional_view<uintptr_t> opq)
    {
        KeyboardDelegateImpl::GetInstance()->UnRegisterListener("selectionChange", opq);
    }

    void OnTextChange(taihe::callback_view<void(taihe::string_view)> callback, uintptr_t opq)
    {
        KeyboardDelegateImpl::GetInstance()->RegisterListener("textChange", callback, opq);
    }

    void OffTextChange(taihe::optional_view<uintptr_t> opq)
    {
        KeyboardDelegateImpl::GetInstance()->UnRegisterListener("textChange", opq);
    }

    void OnEditorAttributeChanged(taihe::callback_view<void(EditorAttribute_t const&)> callback, uintptr_t opq)
    {
        KeyboardDelegateImpl::GetInstance()->RegisterListener("editorAttributeChanged", callback, opq);
    }

    void OffEditorAttributeChanged(taihe::optional_view<uintptr_t> opq)
    {
        KeyboardDelegateImpl::GetInstance()->UnRegisterListener("editorAttributeChanged", opq);
    }
};
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_INPUT_METHOD_KEYBOARD_DELEGATE_IMPL_H