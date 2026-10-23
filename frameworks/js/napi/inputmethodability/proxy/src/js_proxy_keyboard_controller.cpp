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

#include "js_proxy_keyboard_controller.h"

#include "async_call.h"
#include "input_method_ability.h"
#include "js_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "global.h"

namespace OHOS {
namespace MiscServices {
const std::string JsProxyKeyboardController::PKC_CLASS_NAME = "ProxyKeyboardController";
thread_local napi_ref JsProxyKeyboardController::PKCRef_ = nullptr;

napi_value JsProxyKeyboardController::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("hideSelf", HideSelf),
    };
    napi_value cons = nullptr;
    IMF_CALL(napi_define_class(env, PKC_CLASS_NAME.c_str(), PKC_CLASS_NAME.size(), JsConstructor, nullptr,
                               sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));
    IMF_CALL(napi_create_reference(env, cons, 1, &PKCRef_));
    IMF_CALL(napi_set_named_property(env, exports, PKC_CLASS_NAME.c_str(), cons));
    return exports;
}

napi_value JsProxyKeyboardController::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

napi_value JsProxyKeyboardController::HideSelf(napi_env env, napi_callback_info info)
{
    IMSA_HILOGI("HideSelf start");
    auto ctxt = std::make_shared<HideSelfContext>();
    auto input = [](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        return napi_ok;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx) {
        int32_t status = InputMethodAbility::GetInstance().HideCustomKeyboardSelf();
        ctxt->SetErrorCode(status);
        CHECK_RETURN_VOID(status == ErrorCode::NO_ERROR, "hideSelf return error!");
        ctxt->SetState(napi_ok);
    };
    ctxt->SetAction(std::move(input));
    AsyncCall asyncCall(env, info, ctxt, 0);
    return asyncCall.Call(env, exec, "hideSelf");
}

napi_value JsProxyKeyboardController::GetProxyKeyboardControllerInstance(napi_env env)
{
    napi_value instance = nullptr;
    napi_get_null(env, &instance);
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, PKCRef_, &cons) != napi_ok) {
        IMSA_HILOGE("failed to get proxy keyboard controller constructor");
        return instance;
    }
    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        IMSA_HILOGE("failed to create proxy keyboard controller instance");
        return instance;
    }
    return instance;
}
} // namespace MiscServices
} // namespace OHOS
