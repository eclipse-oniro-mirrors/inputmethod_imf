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

#include "js_proxy_text_input_client.h"

#include "global.h"
#include "input_method_ability.h"
#include "input_method_utils.h"
#include "js_text_input_client_engine.h"
#include "js_util.h"
#include "js_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "variant_util.h"

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
        DECLARE_NAPI_FUNCTION("getForward", GetForward),
        DECLARE_NAPI_FUNCTION("getBackward", GetBackward),
        DECLARE_NAPI_FUNCTION("getEditorAttribute", GetEditorAttribute),
        DECLARE_NAPI_FUNCTION("moveCursor", MoveCursor),
        DECLARE_NAPI_FUNCTION("selectByRange", SelectByRange),
        DECLARE_NAPI_FUNCTION("selectByMovement", SelectByMovement),
        DECLARE_NAPI_FUNCTION("getTextIndexAtCursor", GetTextIndexAtCursor),
        DECLARE_NAPI_FUNCTION("sendExtendAction", SendExtendAction),
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
        PARAM_CHECK_RETURN(env, OHOS::MiscServices::IsValidEnterKeyType(ctxt->action), "action is out of valid range!",
            TYPE_NONE, napi_generic_failure);
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
    // 1 means JsAPI:SendKeyFunction has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::DeleteForward(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<JsProxyTextInputClient::ProxyDeleteContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->length);
        PARAM_CHECK_RETURN(env, status == napi_ok, "length type must be number!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, ctxt->length >= 0, "length cannot be less than 0!", TYPE_NONE, napi_generic_failure);
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
        int32_t code = InputMethodAbility::GetInstance().DeleteForward(ctxt->length, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    // 1 means JsAPI:DeleteForward has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::DeleteBackward(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<JsProxyTextInputClient::ProxyDeleteContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->length);
        PARAM_CHECK_RETURN(env, status == napi_ok, "length type must be number!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, ctxt->length >= 0, "length cannot be less than 0!", TYPE_NONE, napi_generic_failure);
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
        int32_t code = InputMethodAbility::GetInstance().DeleteBackward(ctxt->length, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    // 1 means JsAPI:DeleteBackward has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::InsertText(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<JsProxyTextInputClient::ProxyInsertTextContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->text);
        PARAM_CHECK_RETURN(env, status == napi_ok, "text type must be string", TYPE_NONE, napi_generic_failure);
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
    // 1 means JsAPI:InsertText has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::GetForward(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<GetForwardContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->length);
        PARAM_CHECK_RETURN(env, status == napi_ok, "length type must be number!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, ctxt->length >= 0, "length cannot be less than 0!", TYPE_NONE, napi_generic_failure);
        return napi_ok;
    };
    auto output = [ctxt](napi_env env, napi_value *result) -> napi_status {
        napi_value jsText = JsUtil::GetValue(env, ctxt->text);
        *result = jsText;
        return napi_ok;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx, AsyncCall::Context::CallBackAction completeFunc) {
        auto rspCallBack = [ctxt, completeFunc](int32_t code, const ResponseData &data) -> void {
            if (code == ErrorCode::NO_ERROR) {
                VariantUtil::GetValue(data, ctxt->text);
                ctxt->status = napi_ok;
                ctxt->SetState(ctxt->status);
            } else {
                ctxt->SetErrorCode(code);
            }
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        };
        std::u16string temp;
        int32_t code = InputMethodAbility::GetInstance().GetTextBeforeCursor(ctxt->length, temp, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input), std::move(output));
    // 1 means JsAPI:GetForward has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::GetBackward(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<GetBackwardContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->length);
        PARAM_CHECK_RETURN(env, status == napi_ok, "length type must be number!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, ctxt->length >= 0, "length cannot be less than 0!", TYPE_NONE, napi_generic_failure);
        return napi_ok;
    };
    auto output = [ctxt](napi_env env, napi_value *result) -> napi_status {
        napi_value jsText = JsUtil::GetValue(env, ctxt->text);
        *result = jsText;
        return napi_ok;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx, AsyncCall::Context::CallBackAction completeFunc) {
        auto rspCallBack = [ctxt, completeFunc](int32_t code, const ResponseData &data) -> void {
            if (code == ErrorCode::NO_ERROR) {
                VariantUtil::GetValue(data, ctxt->text);
                ctxt->status = napi_ok;
                ctxt->SetState(ctxt->status);
            } else {
                ctxt->SetErrorCode(code);
            }
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        };
        std::u16string temp;
        int32_t code = InputMethodAbility::GetInstance().GetTextAfterCursor(ctxt->length, temp, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input), std::move(output));
    // 1 means JsAPI:GetBackward has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::MoveCursor(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<MoveCursorContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->num);
        PARAM_CHECK_RETURN(
            env, status == napi_ok, "direction type must be Direction!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, OHOS::MiscServices::IsValidCursorDirection(ctxt->num),
            "direction is out of valid range!", TYPE_NONE, napi_generic_failure);
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
        int32_t code = InputMethodAbility::GetInstance().MoveCursor(ctxt->num, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    // 1 means JsAPI:MoveCursor has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::SendExtendAction(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<SendExtendActionContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        auto status = JsUtils::GetValue(env, argv[0], ctxt->action);
        PARAM_CHECK_RETURN(
            env, status == napi_ok, "action type must be ExtendAction!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, OHOS::MiscServices::IsValidExtendAction(ctxt->action), "action is out of valid range!",
            TYPE_NONE, napi_generic_failure);
        return napi_ok;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx, AsyncCall::Context::CallBackAction completeFunc) {
        auto rspCallBack = [ctxt, completeFunc](int32_t code, const ResponseData &data) -> void {
            if (code == ErrorCode::NO_ERROR) {
                ctxt->SetState(napi_ok);
            } else {
                ctxt->SetErrorCode(code);
            }
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        };
        int32_t code = InputMethodAbility::GetInstance().SendExtendAction(ctxt->action, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    // 1 means JsAPI:SendExtendAction has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::SelectByRange(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<SelectContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        return JsUtils::GetSelectRange(env, argv[0], ctxt->start, ctxt->end);
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
        int32_t code = InputMethodAbility::GetInstance().SelectByRange(ctxt->start, ctxt->end, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    // 1 means JsAPI:SelectByRange has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::SelectByMovement(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<SelectContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        return JsUtils::GetSelectMovement(env, argv[0], ctxt->direction);
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
        int32_t code = InputMethodAbility::GetInstance().SelectByMovement(ctxt->direction, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(std::move(input));
    // 1 means JsAPI:SelectByMovement has 1 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, __FUNCTION__);
}

napi_value JsProxyTextInputClient::GetEditorAttribute(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<GetEditorAttributeContext>();
    auto output = [ctxt](napi_env env, napi_value *result) -> napi_status {
        *result = JsInputAttribute::Write(env, ctxt->inputAttribute);
        return napi_ok;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx) {
        TextTotalConfig config;
        int32_t ret = InputMethodAbility::GetInstance().GetTextConfig(config);
        ctxt->SetErrorCode(ret);
        CHECK_RETURN_VOID(ret == ErrorCode::NO_ERROR, "failed to get text config!");
        ctxt->inputAttribute = config.inputAttribute;
        ctxt->SetState(napi_ok);
    };
    ctxt->SetAction(nullptr, std::move(output));
    // 0 means JsAPI:GetEditorAttribute has 0 param at most.
    AsyncCall asyncCall(env, info, ctxt, 0);
    return asyncCall.Call(env, exec, "GetEditorAttribute");
}

napi_value JsProxyTextInputClient::GetTextIndexAtCursor(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<GetTextIndexAtCursorContext>();
    auto output = [ctxt](napi_env env, napi_value *result) -> napi_status {
        return napi_create_int32(env, ctxt->index, result);
    };
    auto exec = [ctxt](AsyncCall::Context *ctx, AsyncCall::Context::CallBackAction completeFunc) {
        auto rspCallBack = [ctxt, completeFunc](int32_t code, const ResponseData &data) -> void {
            if (code == ErrorCode::NO_ERROR) {
                VariantUtil::GetValue(data, ctxt->index);
                ctxt->status = napi_ok;
                ctxt->SetState(ctxt->status);
            } else {
                ctxt->SetErrorCode(code);
            }
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        };
        int32_t code = InputMethodAbility::GetInstance().GetTextIndexAtCursor(ctxt->index, rspCallBack);
        if (code != ErrorCode::NO_ERROR) {
            ctxt->SetErrorCode(code);
            completeFunc != nullptr ? completeFunc() : IMSA_HILOGE("completeFunc is nullptr");
        }
    };
    ctxt->SetAction(nullptr, std::move(output));
    // 0 means JsAPI:GetTextIndexAtCursor has 0 param at most.
    EditAsyncCall asyncCall(env, info, ctxt, 0);
    return asyncCall.Call(env, exec, __FUNCTION__);
}
} // namespace MiscServices
} // namespace OHOS
