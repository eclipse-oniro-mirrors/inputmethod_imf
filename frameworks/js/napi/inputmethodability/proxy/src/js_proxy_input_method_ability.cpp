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

#include "js_proxy_input_method_ability.h"

#include "input_method_ability.h"
#include "input_method_property.h"
#include "input_method_utils.h"
#include "js_callback_handler.h"
#include "js_proxy_keyboard_controller.h"
#include "js_proxy_text_input_client.h"
#include "js_runtime_utils.h"
#include "js_util.h"
#include "js_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace MiscServices {
const std::string JsProxyInputMethodAbility::PIMAS_CLASS_NAME = "ProxyInputMethodAbility";
thread_local napi_ref JsProxyInputMethodAbility::PIMASRef_ = nullptr;
std::mutex JsProxyInputMethodAbility::instanceMutex_;
std::shared_ptr<JsProxyInputMethodAbility> JsProxyInputMethodAbility::instance_ = nullptr;

std::shared_ptr<JsProxyInputMethodAbility> JsProxyInputMethodAbility::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<JsProxyInputMethodAbility>();
        }
    }
    return instance_;
}

napi_value JsProxyInputMethodAbility::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onInputStart", SubscribeInputStart),
        DECLARE_NAPI_FUNCTION("offInputStart", UnsubscribeInputStart),
        DECLARE_NAPI_FUNCTION("onKeyboardShow", SubscribeKeyboardShow),
        DECLARE_NAPI_FUNCTION("offKeyboardShow", UnsubscribeKeyboardShow),
        DECLARE_NAPI_FUNCTION("onKeyboardHide", SubscribeKeyboardHide),
        DECLARE_NAPI_FUNCTION("offKeyboardHide", UnsubscribeKeyboardHide),
        DECLARE_NAPI_FUNCTION("onUnregister", SubscribeUnregister),
        DECLARE_NAPI_FUNCTION("offUnregister", UnsubscribeUnregister),
    };
    napi_value cons = nullptr;
    IMF_CALL(napi_define_class(env, PIMAS_CLASS_NAME.c_str(), PIMAS_CLASS_NAME.size(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));
    IMF_CALL(napi_create_reference(env, cons, 1, &PIMASRef_));
    IMF_CALL(napi_set_named_property(env, exports, PIMAS_CLASS_NAME.c_str(), cons));
    return exports;
}

napi_value JsProxyInputMethodAbility::JsConstructor(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    napi_get_null(env, &thisVar);
    IMF_CALL(napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr));
    auto listener = GetInstance();
    if (listener == nullptr || !InitProxyInputMethodAbility()) {
        IMSA_HILOGE("failed to get listener.");
        return thisVar;
    }
    napi_status status = napi_wrap(
        env, thisVar, listener.get(), [](napi_env env, void *nativeObject, void *hint) {}, nullptr, nullptr);
    if (status != napi_ok) {
        IMSA_HILOGE("JsProxyInputMethodAbility napi_wrap failed: %{public}d", status);
        return thisVar;
    }
    return thisVar;
};

bool JsProxyInputMethodAbility::InitProxyInputMethodAbility()
{
    if (InputMethodAbility::GetInstance().IsImeExtension()) {
        IMSA_HILOGE("ime ext is not allowed.");
        return false;
    }
    auto listener = GetInstance();
    if (listener == nullptr) {
        return false;
    }
    InputMethodAbility::GetInstance().SetImeListener(listener);
    return true;
}

napi_value JsProxyInputMethodAbility::SubscribeInputStart(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::SubscribeByType(env, info, "inputStart");
}

napi_value JsProxyInputMethodAbility::UnsubscribeInputStart(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::UnsubscribeByType(env, info, "inputStart");
}

napi_value JsProxyInputMethodAbility::SubscribeKeyboardShow(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::SubscribeByType(env, info, "keyboardShow");
}

napi_value JsProxyInputMethodAbility::UnsubscribeKeyboardShow(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::UnsubscribeByType(env, info, "keyboardShow");
}

napi_value JsProxyInputMethodAbility::SubscribeKeyboardHide(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::SubscribeByType(env, info, "keyboardHide");
}

napi_value JsProxyInputMethodAbility::UnsubscribeKeyboardHide(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::UnsubscribeByType(env, info, "keyboardHide");
}

napi_value JsProxyInputMethodAbility::SubscribeUnregister(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::SubscribeByType(env, info, "unregister");
}

napi_value JsProxyInputMethodAbility::UnsubscribeUnregister(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::UnsubscribeByType(env, info, "unregister");
}

void JsProxyInputMethodAbility::OnInputStart()
{
    IMSA_HILOGI("OnInputStart start.");
    auto callbacks = GetCallbacks("inputStart");
    for (auto &cb : callbacks) {
        if (cb == nullptr || cb->jsHandler_ == nullptr) {
            continue;
        }
        auto task = [cb]() {
            IMSA_HILOGI("OnInputStart task start!");
            DealInputStart(cb);
            IMSA_HILOGI("OnInputStart task end!");
        };
        cb->jsHandler_->PostTask(task, "inputStart", 0, AppExecFwk::EventQueue::Priority::VIP);
    }
}

void JsProxyInputMethodAbility::DealInputStart(const std::shared_ptr<JSCallbackObject> &callback)
{
    auto paramGetter = [](napi_env env, napi_value *args, uint8_t argc) -> bool {
        if (argc < 2) {
            IMSA_HILOGE("the num:%{public}u of params in OnInputStart is abnormal!", argc);
            return false;
        }
        napi_value proxyClient = JsProxyTextInputClient::GetProxyTextInputClientInstance(env);
        napi_value keyboardController = JsProxyKeyboardController::GetProxyKeyboardControllerInstance(env);
        if (proxyClient == nullptr || keyboardController == nullptr) {
            IMSA_HILOGE("instance is nullptr!");
            return false;
        }
        args[0] = proxyClient;
        args[1] = keyboardController;
        return true;
    };
    JsCallbackHandler::Traverse({ callback }, { 2, paramGetter });
}

void JsProxyInputMethodAbility::OnUnregister()
{
    IMSA_HILOGI("OnUnregister start.");
    auto callbacks = GetCallbacks("unregister");
    for (auto &cb : callbacks) {
        if (cb == nullptr || cb->jsHandler_ == nullptr) {
            continue;
        }
        auto task = [cb]() { JsCallbackHandler::Traverse({ cb }); };
        cb->jsHandler_->PostTask(task, "unregister", 0, AppExecFwk::EventQueue::Priority::VIP);
    }
}

napi_value JsProxyInputMethodAbility::GetProxyInputMethodAbility(napi_env env, napi_callback_info info)
{
    napi_value instance = nullptr;
    napi_get_null(env, &instance);
    if (InputMethodAbility::GetInstance().IsImeExtension()) {
        IMSA_HILOGE("IME extension not allowed");
        JsUtils::ThrowException(env, IMFErrorCode::EXCEPTION_IME_EXTENSION_NOT_ALLOWED,
            "the caller is an input method extension", TYPE_NONE);
        return instance;
    }
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, PIMASRef_, &cons) != napi_ok) {
        IMSA_HILOGE("failed to get proxy ability constructor");
        return instance;
    }
    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        IMSA_HILOGE("failed to create proxy ability instance");
        return instance;
    }
    return instance;
}

void JsProxyInputMethodAbility::OnKeyboardStatus(bool isShow)
{
    std::string type = isShow ? "keyboardShow" : "keyboardHide";
    auto callbacks = GetCallbacks(type);
    for (auto &cb : callbacks) {
        if (cb == nullptr || cb->jsHandler_ == nullptr) {
            continue;
        }
        auto task = [cb]() { JsCallbackHandler::Traverse({ cb }); };
        cb->jsHandler_->PostTask(task, type, 0, AppExecFwk::EventQueue::Priority::VIP);
    }
}
} // namespace MiscServices
} // namespace OHOS
