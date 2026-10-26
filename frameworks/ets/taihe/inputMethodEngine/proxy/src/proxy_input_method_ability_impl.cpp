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
#include "proxy_input_method_ability_impl.h"
#include "js_utils.h"

namespace OHOS {
namespace MiscServices {
using namespace taihe;
std::mutex ProxyInputMethodAbilityImpl::engineMutex_;
std::shared_ptr<ProxyInputMethodAbilityImpl> ProxyInputMethodAbilityImpl::instance_ = nullptr;

std::shared_ptr<ProxyInputMethodAbilityImpl> ProxyInputMethodAbilityImpl::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(engineMutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<ProxyInputMethodAbilityImpl>();
        }
    }
    return instance_;
}

void ProxyInputMethodAbilityImpl::OnKeyboardStatus(bool isShow)
{
    std::string type = isShow ? "keyboardShow" : "keyboardHide";
    IMSA_HILOGI("OnKeyboardStatus: %{public}s.", type.c_str());
    auto callbacks = GetCallbacks(type);
    if (callbacks.empty()) {
        return;
    }
    for (auto &item : callbacks) {
        if (item) {
            std::get<taihe::callback<void(UndefinedType_t const&)>>(item->callback)(
                UndefinedType_t::make_undefined());
        }
    }
}

void ProxyInputMethodAbilityImpl::OnInputStart()
{
    IMSA_HILOGI("OnInputStart.");
    auto callbacks = GetCallbacks("inputStart");
    if (callbacks.empty()) {
        return;
    }
    auto keyboardController = taihe::make_holder<IMFProxyKeyboardControllerImpl,
        ohos::inputMethodEngine::ProxyKeyboardController>();
    auto textInputClient = taihe::make_holder<IMFProxyTextInputClientImpl,
        ohos::inputMethodEngine::ProxyTextInputClient>();
    for (auto &item : callbacks) {
        if (item) {
            std::get<taihe::callback<void(ProxyTextInputClient_t, ProxyKeyboardController_t)>>(
                item->callback)(textInputClient, keyboardController);
        }
    }
}

void ProxyInputMethodAbilityImpl::OnUnregister()
{
    IMSA_HILOGI("OnUnregister.");
    auto callbacks = GetCallbacks("unregister");
    if (callbacks.empty()) {
        return;
    }
    for (auto &item : callbacks) {
        if (item) {
            std::get<taihe::callback<void(UndefinedType_t const&)>>(item->callback)(
                UndefinedType_t::make_undefined());
        }
    }
}
} // namespace MiscServices
} // namespace OHOS
