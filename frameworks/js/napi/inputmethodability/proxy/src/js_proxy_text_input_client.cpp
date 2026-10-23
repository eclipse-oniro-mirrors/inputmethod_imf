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

#include "js_proxy_text_input_client.h"

#include "input_method_ability.h"
#include "input_method_utils.h"
#include "js_text_input_client_engine.h"
#include "js_util.h"
#include "js_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "global.h"

namespace OHOS {
namespace MiscServices {
const std::string JsProxyTextInputClient::PIC_CLASS_NAME = "ProxyTextInputClient";
thread_local napi_ref JsProxyTextInputClient::PICRef_ = nullptr;

napi_value JsProxyTextInputClient::Init(napi_env env, napi_value exports)
{
    IMSA_HILOGD("JsProxyTextInputClient init");
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("sendKeyFunction", SendKeyFunction),
        DECLARE_NAPI_FUNCTION("deleteForward", DeleteForward),
        DECLARE_NAPI_FUNCTION("deleteBackward", DeleteBackward),
        DECLARE_NAPI_FUNCTION("insertText", InsertText),
        DECLARE_NAPI_FUNCTION("getForward", JsTextInputClientEngine::GetForward),
        DECLARE_NAPI_FUNCTION("getBackward", JsTextInputClientEngine::GetBackward),
        DECLARE_NAPI_FUNCTION("getEditorAttribute", JsTextInputClientEngine::GetEditorAttribute),
        DECLARE_NAPI_FUNCTION("moveCursor", JsTextInputClientEngine::MoveCursor),
        DECLARE_NAPI_FUNCTION("selectByRange", JsTextInputClientEngine::SelectByRange),
        DECLARE_NAPI_FUNCTION("selectByMovement", JsTextInputClientEngine::SelectByMovement),
        DECLARE_NAPI_FUNCTION("getTextIndexAtCursor", JsTextInputClientEngine::GetTextIndexAtCursor),
        DECLARE_NAPI_FUNCTION("sendExtendAction", JsTextInputClientEngine::SendExtendAction),
    };
    napi_value cons = nullptr;
    IMF_CALL(napi_define_class(env, PIC_CLASS_NAME.c_str(), PIC_CLASS_NAME.size(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));
    IMF_CALL(napi_create_reference(env, cons, 1, &PICRef_));
    IMF_CALL(napi_set_named_property(env, exports, PIC_CLASS_NAME.c_str(), cons));
    return exports;
}

napi_value JsProxyTextInputClient::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

napi_value JsProxyTextInputClient::GetProxyTextInputClientInstance(napi_env env)
{
    napi_value instance = nullptr;
    napi_get_null(env, &instance);
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, PICRef_, &cons) != napi_ok) {
        IMSA_HILOGE("failed to get reference value!");
        return instance;
    }
    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        IMSA_HILOGE("failed to new instance!");
        return instance;
    }
    return instance;
}

napi_value JsProxyTextInputClient::SendKeyFunction(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<JsProxyTextInputClient::ProxySendKeyFunctionContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        napi_status ret = JsUtils::GetValue(env, argv[0], ctxt->action);
        PARAM_CHECK_RETURN(env, ret == napi_ok, "action type must be number!", TYPE_NONE, napi_generic_failure);
        return napi_ok;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx, AsyncCall::Context::CallBackAction completeFunc) {
        auto rspCallBack = [ctxt, completeFunc](int32_t code, const ResponseData &data) -> void {
            if (code == ErrorCode::NO_ERROR) {
                ctxt->status = napi_ok;
                ctxt->SetState(ctxt->status);
            } else {
                ctxt->SetErrorCode(code);
            }
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        };
        int32_t code = InputMethodAbility::GetInstance().SendFunctionKey(ctxt->action, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::DeleteForward(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<JsProxyTextInputClient::ProxyDeleteContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, JsUtil::GetType(env, argv[0]) == napi_number, "length type must be number!", TYPE_NONE,
            napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->length);
        return status;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx, AsyncCall::Context::CallBackAction completeFunc) {
        auto rspCallBack = [ctxt, completeFunc](int32_t code, const ResponseData &data) -> void {
            if (code == ErrorCode::NO_ERROR) {
                ctxt->status = napi_ok;
                ctxt->SetState(ctxt->status);
            } else {
                ctxt->SetErrorCode(code);
            }
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        };
        int32_t code = InputMethodAbility::GetInstance().DeleteForward(ctxt->length, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::DeleteBackward(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<JsProxyTextInputClient::ProxyDeleteContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, JsUtil::GetType(env, argv[0]) == napi_number, "param length type must be number!",
            TYPE_NONE, napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->length);
        return status;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx, AsyncCall::Context::CallBackAction completeFunc) {
        auto rspCallBack = [ctxt, completeFunc](int32_t code, const ResponseData &data) -> void {
            if (code == ErrorCode::NO_ERROR) {
                ctxt->status = napi_ok;
                ctxt->SetState(ctxt->status);
            } else {
                ctxt->SetErrorCode(code);
            }
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        };
        int32_t code = InputMethodAbility::GetInstance().DeleteBackward(ctxt->length, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::InsertText(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<JsProxyTextInputClient::ProxyInsertTextContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, JsUtil::GetType(env, argv[0]) == napi_string, "text type must be string", TYPE_NONE,
            napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->text);
        return status;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx, AsyncCall::Context::CallBackAction completeFunc) {
        auto rspCallBack = [ctxt, completeFunc](int32_t code, const ResponseData &data) -> void {
            if (code == ErrorCode::NO_ERROR) {
                ctxt->status = napi_ok;
                ctxt->SetState(ctxt->status);
            } else {
                ctxt->SetErrorCode(code);
            }
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        };
        int32_t code = InputMethodAbility::GetInstance().InsertText(ctxt->text, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}
} // namespace MiscServices
} // namespace OHOS
