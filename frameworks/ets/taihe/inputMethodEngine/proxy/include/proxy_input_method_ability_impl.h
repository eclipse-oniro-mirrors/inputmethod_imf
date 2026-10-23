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
#ifndef TAIHE_PROXY_INPUT_METHOD_ABILITY_IMPL_H
#define TAIHE_PROXY_INPUT_METHOD_ABILITY_IMPL_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ani_common_engine.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "input_method_engine_listener.h"
#include "input_method_ability.h"
#include "event_handler.h"
#include "event_runner.h"
#include "proxy_keyboard_controller_impl.h"
#include "proxy_text_input_client_impl.h"
#include "proxy_listener_base.h"

namespace OHOS {
namespace MiscServices {
class ProxyInputMethodAbilityImpl : public InputMethodEngineListener, public ProxyListenerBase {
public:
    static std::shared_ptr<ProxyInputMethodAbilityImpl> GetInstance();
    void OnKeyboardStatus(bool isShow) override;
    void OnInputStart() override;
    void OnUnregister() override;

private:
    static std::mutex engineMutex_;
    static std::shared_ptr<ProxyInputMethodAbilityImpl> instance_;
};

class IMFProxyInputMethodAbilityImpl {
public:
    IMFProxyInputMethodAbilityImpl()
    {
        InputMethodAbility::GetInstance().SetImeListener(ProxyInputMethodAbilityImpl::GetInstance());
    }

    void OnInputStart(taihe::callback_view<void(ProxyTextInputClient_t, ProxyKeyboardController_t)> callback,
        uintptr_t opq)
    {
        ProxyInputMethodAbilityImpl::GetInstance()->RegisterListener("inputStart", callback, opq);
    }

    void OffInputStart(taihe::optional_view<uintptr_t> opq)
    {
        ProxyInputMethodAbilityImpl::GetInstance()->UnRegisterListener("inputStart", opq);
    }

    void OnKeyboardShow(taihe::callback_view<void(UndefinedType_t const&)> callback, uintptr_t opq)
    {
        ProxyInputMethodAbilityImpl::GetInstance()->RegisterListener("keyboardShow", callback, opq);
    }

    void OffKeyboardShow(taihe::optional_view<uintptr_t> opq)
    {
        ProxyInputMethodAbilityImpl::GetInstance()->UnRegisterListener("keyboardShow", opq);
    }

    void OnKeyboardHide(taihe::callback_view<void(UndefinedType_t const&)> callback, uintptr_t opq)
    {
        ProxyInputMethodAbilityImpl::GetInstance()->RegisterListener("keyboardHide", callback, opq);
    }

    void OffKeyboardHide(taihe::optional_view<uintptr_t> opq)
    {
        ProxyInputMethodAbilityImpl::GetInstance()->UnRegisterListener("keyboardHide", opq);
    }

    void OnUnregister(taihe::callback_view<void(UndefinedType_t const&)> callback, uintptr_t opq)
    {
        ProxyInputMethodAbilityImpl::GetInstance()->RegisterListener("unregister", callback, opq);
    }

    void OffUnregister(taihe::optional_view<uintptr_t> opq)
    {
        ProxyInputMethodAbilityImpl::GetInstance()->UnRegisterListener("unregister", opq);
    }
};
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_PROXY_INPUT_METHOD_ABILITY_IMPL_H
