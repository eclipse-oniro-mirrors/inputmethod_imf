/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "js_input_method.h"

#include "event_handler.h"
#include "event_runner.h"
#include "input_method_controller.h"
#include "input_method_property.h"
#include "inputmethod_trace.h"
#include "js_callback_handler.h"
#include "js_util.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "string_ex.h"

namespace OHOS {
namespace MiscServices {
std::mutex JsInputMethod::jsCbsLock_;
std::unordered_map<std::string, std::vector<std::shared_ptr<JSCallbackObject>>> JsInputMethod::jsCbs_;
napi_value JsInputMethod::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("switchInputMethod", SwitchInputMethod),
        DECLARE_NAPI_FUNCTION("getCurrentInputMethod", GetCurrentInputMethod),
        DECLARE_NAPI_FUNCTION("getCurrentInputMethodSubtype", GetCurrentInputMethodSubtype),
        DECLARE_NAPI_FUNCTION("getDefaultInputMethod", GetDefaultInputMethod),
        DECLARE_NAPI_FUNCTION("getSystemInputMethodConfigAbility", GetSystemInputMethodConfigAbility),
        DECLARE_NAPI_FUNCTION("switchCurrentInputMethodSubtype", SwitchCurrentInputMethodSubtype),
        DECLARE_NAPI_FUNCTION("switchCurrentInputMethodAndSubtype", SwitchCurrentInputMethodAndSubtype),
        DECLARE_NAPI_FUNCTION("setSimpleKeyboardEnabled", SetSimpleKeyboardEnabled),
        DECLARE_NAPI_FUNCTION("onAttachmentDidFail", OnAttachmentDidFail),
        DECLARE_NAPI_FUNCTION("offAttachmentDidFail", OffAttachmentDidFail),
        DECLARE_NAPI_STATIC_PROPERTY("AttachFailureReason", GetJsAttachFailureReasonProperty(env)),
    };
    IMF_CALL(
        napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));
    return exports;
};

napi_status JsInputMethod::GetInputMethodProperty(napi_env env, napi_value argv,
    std::shared_ptr<SwitchInputMethodContext> ctxt)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_generic_failure;
    napi_typeof(env, argv, &valueType);
    if (valueType != napi_object) {
        IMSA_HILOGE("type is not object!");
        return status;
    }
    napi_value result = nullptr;
    napi_get_named_property(env, argv, "name", &result);
    if (ctxt == nullptr) {
        IMSA_HILOGE("ctxt is nullptr!");
        return status;
    }
    status = JsUtils::GetValue(env, result, ctxt->packageName);
    CHECK_RETURN(status == napi_ok, "get name failed!", status);
    result = nullptr;
    napi_get_named_property(env, argv, "id", &result);
    status = JsUtils::GetValue(env, result, ctxt->methodId);
    CHECK_RETURN(status == napi_ok, "get id failed!", status);
    if (ctxt->packageName.empty() || ctxt->methodId.empty()) {
        result = nullptr;
        napi_get_named_property(env, argv, "packageName", &result);
        status = JsUtils::GetValue(env, result, ctxt->packageName);
        CHECK_RETURN(status == napi_ok, "get packageName failed!", status);

        result = nullptr;
        napi_get_named_property(env, argv, "methodId", &result);
        status = JsUtils::GetValue(env, result, ctxt->methodId);
        CHECK_RETURN(status == napi_ok, "get methodId failed!", status);
    }
    PARAM_CHECK_RETURN(env, (!ctxt->packageName.empty() && !ctxt->methodId.empty()),
        "packageName and methodId is empty", TYPE_NONE, napi_invalid_arg);
    IMSA_HILOGD("methodId: %{public}s, packageName: %{public}s.", ctxt->methodId.c_str(), ctxt->packageName.c_str());
    return napi_ok;
}

napi_status JsInputMethod::GetInputMethodSubProperty(napi_env env, napi_value argv,
    std::shared_ptr<SwitchInputMethodContext> ctxt)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_generic_failure;
    status = napi_typeof(env, argv, &valueType);
    if (valueType == napi_object) {
        napi_value result = nullptr;
        status = napi_get_named_property(env, argv, "name", &result);
        PARAM_CHECK_RETURN(env, status == napi_ok, " name ", TYPE_STRING, status);
        if (ctxt == nullptr) {
            IMSA_HILOGE("ctxt is nullptr!");
            return status;
        }
        status = JsUtils::GetValue(env, result, ctxt->name);
        CHECK_RETURN(status == napi_ok, "get name failed!", status);
        result = nullptr;
        status = napi_get_named_property(env, argv, "id", &result);
        PARAM_CHECK_RETURN(env, status == napi_ok, " id ", TYPE_STRING, status);
        status = JsUtils::GetValue(env, result, ctxt->id);
        CHECK_RETURN(status == napi_ok, "get id failed!", status);
        IMSA_HILOGD("name: %{public}s and id: %{public}s.", ctxt->name.c_str(), ctxt->id.c_str());
    }
    return status;
}

napi_value JsInputMethod::GetJsInputMethodProperty(napi_env env, const Property &property)
{
    napi_value prop = nullptr;
    napi_create_object(env, &prop);

    napi_value packageName = nullptr;
    napi_create_string_utf8(env, property.name.c_str(), NAPI_AUTO_LENGTH, &packageName);
    napi_set_named_property(env, prop, "packageName", packageName);
    napi_set_named_property(env, prop, "name", packageName);

    napi_value methodId = nullptr;
    napi_create_string_utf8(env, property.id.c_str(), NAPI_AUTO_LENGTH, &methodId);
    napi_set_named_property(env, prop, "methodId", methodId);
    napi_set_named_property(env, prop, "id", methodId);

    napi_value icon = nullptr;
    napi_create_string_utf8(env, property.icon.c_str(), NAPI_AUTO_LENGTH, &icon);
    napi_set_named_property(env, prop, "icon", icon);

    napi_value iconId = nullptr;
    napi_create_uint32(env, property.iconId, &iconId);
    napi_set_named_property(env, prop, "iconId", iconId);

    napi_value label = nullptr;
    napi_create_string_utf8(env, property.label.c_str(), NAPI_AUTO_LENGTH, &label);
    napi_set_named_property(env, prop, "label", label);

    napi_value labelId = nullptr;
    napi_create_uint32(env, property.labelId, &labelId);
    napi_set_named_property(env, prop, "labelId", labelId);

    JsUtil::Object::WriteProperty(env, prop, "enabledState", static_cast<int32_t>(property.status));
    return prop;
}

napi_value JsInputMethod::GetJsInputMethodSubProperty(napi_env env, const SubProperty &subProperty)
{
    napi_value prop = nullptr;
    napi_create_object(env, &prop);

    napi_value id = nullptr;
    napi_create_string_utf8(env, subProperty.id.c_str(), NAPI_AUTO_LENGTH, &id);
    napi_set_named_property(env, prop, "id", id);

    napi_value label = nullptr;
    napi_create_string_utf8(env, subProperty.label.c_str(), NAPI_AUTO_LENGTH, &label);
    napi_set_named_property(env, prop, "label", label);

    napi_value labelId = nullptr;
    napi_create_uint32(env, subProperty.labelId, &labelId);
    napi_set_named_property(env, prop, "labelId", labelId);

    napi_value name = nullptr;
    napi_create_string_utf8(env, subProperty.name.c_str(), NAPI_AUTO_LENGTH, &name);
    napi_set_named_property(env, prop, "name", name);

    napi_value mode = nullptr;
    napi_create_string_utf8(env, subProperty.mode.c_str(), NAPI_AUTO_LENGTH, &mode);
    napi_set_named_property(env, prop, "mode", mode);

    napi_value locale = nullptr;
    napi_create_string_utf8(env, subProperty.locale.c_str(), NAPI_AUTO_LENGTH, &locale);
    napi_set_named_property(env, prop, "locale", locale);

    napi_value language = nullptr;
    napi_create_string_utf8(env, subProperty.language.c_str(), NAPI_AUTO_LENGTH, &language);
    napi_set_named_property(env, prop, "language", language);

    napi_value icon = nullptr;
    napi_create_string_utf8(env, subProperty.icon.c_str(), NAPI_AUTO_LENGTH, &icon);
    napi_set_named_property(env, prop, "icon", icon);

    napi_value iconId = nullptr;
    napi_create_uint32(env, subProperty.iconId, &iconId);
    napi_set_named_property(env, prop, "iconId", iconId);
    return prop;
}

napi_value JsInputMethod::GetJsInputConfigElement(napi_env env, const OHOS::AppExecFwk::ElementName &elementName)
{
    napi_value element = nullptr;
    napi_create_object(env, &element);

    napi_value bundleName = nullptr;
    napi_create_string_utf8(env, elementName.GetBundleName().c_str(), NAPI_AUTO_LENGTH, &bundleName);
    napi_set_named_property(env, element, "bundleName", bundleName);

    napi_value moduleName = nullptr;
    napi_create_string_utf8(env, elementName.GetModuleName().c_str(), NAPI_AUTO_LENGTH, &moduleName);
    napi_set_named_property(env, element, "moduleName", moduleName);

    napi_value abilityName = nullptr;
    napi_create_string_utf8(env, elementName.GetAbilityName().c_str(), NAPI_AUTO_LENGTH, &abilityName);
    napi_set_named_property(env, element, "abilityName", abilityName);

    return element;
}

napi_value JsInputMethod::GetJSInputMethodSubProperties(napi_env env, const std::vector<SubProperty> &subProperties)
{
    uint32_t index = 0;
    napi_value prop = nullptr;
    napi_create_array(env, &prop);
    if (prop == nullptr) {
        IMSA_HILOGE("create array failed!");
        return prop;
    }
    for (const auto &subproperty : subProperties) {
        napi_value pro = GetJsInputMethodSubProperty(env, subproperty);
        napi_set_element(env, prop, index, pro);
        index++;
    }
    return prop;
}

napi_value JsInputMethod::GetJSInputMethodProperties(napi_env env, const std::vector<Property> &properties)
{
    uint32_t index = 0;
    napi_value prop = nullptr;
    napi_create_array(env, &prop);
    if (prop == nullptr) {
        IMSA_HILOGE("create array failed!");
        return prop;
    }
    for (const auto &property : properties) {
        napi_value pro = GetJsInputMethodProperty(env, property);
        napi_set_element(env, prop, index, pro);
        index++;
    }
    return prop;
}

napi_value JsInputMethod::SwitchInputMethod(napi_env env, napi_callback_info info)
{
    InputMethodSyncTrace tracer("JsInputMethod_SwitchInputMethod");
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_invalid_arg);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[0], &valueType);
        PARAM_CHECK_RETURN(env, valueType == napi_object || valueType == napi_string,
            "target/bundleName type must be InputMethodProperty/string!", TYPE_NONE, napi_invalid_arg);
        napi_status status = napi_generic_failure;
        if (valueType == napi_object) {
            ctxt->trigger = SwitchTrigger::CURRENT_IME;
            status = GetInputMethodProperty(env, argv[0], ctxt);
        } else {
            status = JsUtils::GetValue(env, argv[0], ctxt->packageName);
            ctxt->trigger = SwitchTrigger::SYSTEM_APP;
            napi_valuetype type = napi_undefined;
            napi_typeof(env, argv[1], &type);
            if (argc > 1 && type == napi_string) {
                JsUtils::GetValue(env, argv[1], ctxt->id);
            }
        }
        return status;
    };
    auto output = [ctxt](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, ctxt->isSwitchInput, result);
        return status;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx) {
        int32_t errCode = ErrorCode::ERROR_EX_NULL_POINTER;
        auto instance = InputMethodController::GetInstance();
        if (instance != nullptr) {
            errCode = instance->SwitchInputMethod(ctxt->trigger, ctxt->packageName, ctxt->id);
        }
        if (errCode == ErrorCode::NO_ERROR) {
            ctxt->status = napi_ok;
            ctxt->SetState(ctxt->status);
            ctxt->isSwitchInput = true;
        } else {
            IMSA_HILOGE("exec SwitchInputMethod failed ret: %{public}d!", errCode);
            ctxt->SetErrorCode(errCode);
        }
    };
    ctxt->SetAction(std::move(input), std::move(output));
    // 2 means JsAPI:switchInputMethod has 2 params at most.
    AsyncCall asyncCall(env, info, ctxt, 2);
    return asyncCall.Call(env, exec, "switchInputMethod");
}

napi_value JsInputMethod::GetCurrentInputMethod(napi_env env, napi_callback_info info)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("input method controller is nullptr!");
        return JsUtil::Const::Null(env);
    }
    std::shared_ptr<Property> property = instance->GetCurrentInputMethod();
    if (property == nullptr) {
        IMSA_HILOGE("current input method is nullptr!");
        return JsUtil::Const::Null(env);
    }
    return GetJsInputMethodProperty(env, *property);
}

napi_value JsInputMethod::GetCurrentInputMethodSubtype(napi_env env, napi_callback_info info)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("input method controller is nullptr!");
        return JsUtil::Const::Null(env);
    }
    std::shared_ptr<SubProperty> subProperty = instance->GetCurrentInputMethodSubtype();
    if (subProperty == nullptr) {
        IMSA_HILOGE("current input method subtype is nullptr!");
        return JsUtil::Const::Null(env);
    }
    return GetJsInputMethodSubProperty(env, *subProperty);
}

napi_value JsInputMethod::GetDefaultInputMethod(napi_env env, napi_callback_info info)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("input method controller is nullptr!");
        return JsUtil::Const::Null(env);
    }
    std::shared_ptr<Property> property;
    int32_t ret = instance->GetDefaultInputMethod(property);
    if (property == nullptr) {
        IMSA_HILOGE("default input method is nullptr!");
        return JsUtil::Const::Null(env);
    }
    if (ret != ErrorCode::NO_ERROR) {
        JsUtils::ThrowException(env, JsUtils::Convert(ret), "failed to get default input method!", TYPE_NONE);
        return JsUtil::Const::Null(env);
    }
    return GetJsInputMethodProperty(env, *property);
}

napi_value JsInputMethod::GetSystemInputMethodConfigAbility(napi_env env, napi_callback_info info)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("input method controller is nullptr!");
        return JsUtil::Const::Null(env);
    }
    OHOS::AppExecFwk::ElementName inputMethodConfig;
    int32_t ret = instance->GetInputMethodConfig(inputMethodConfig);
    if (ret != ErrorCode::NO_ERROR) {
        JsUtils::ThrowException(env, JsUtils::Convert(ret), "failed to get input method config", TYPE_NONE);
        return JsUtil::Const::Null(env);
    }
    return GetJsInputConfigElement(env, inputMethodConfig);
}

napi_value JsInputMethod::SwitchCurrentInputMethodSubtype(napi_env env, napi_callback_info info)
{
    InputMethodSyncTrace tracer("JsInputMethod_SwitchCurrentInputMethodSubtype");
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_invalid_arg);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[0], &valueType);
        PARAM_CHECK_RETURN(env, valueType == napi_object, "target type must be InputMethodSubtype!", TYPE_NONE,
            napi_invalid_arg);
        napi_status status = GetInputMethodSubProperty(env, argv[0], ctxt);
        return status;
    };
    auto output = [ctxt](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, ctxt->isSwitchInput, result);
        IMSA_HILOGE("output get boolean != nullptr[%{public}d]!", result != nullptr);
        return status;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx) {
        int32_t errCode = ErrorCode::ERROR_EX_NULL_POINTER;
        auto instance = InputMethodController::GetInstance();
        if (instance != nullptr) {
            errCode = instance->SwitchInputMethod(SwitchTrigger::CURRENT_IME, ctxt->name, ctxt->id);
        }
        if (errCode == ErrorCode::NO_ERROR) {
            IMSA_HILOGI("exec SwitchInputMethod success.");
            ctxt->status = napi_ok;
            ctxt->SetState(ctxt->status);
            ctxt->isSwitchInput = true;
        } else {
            ctxt->SetErrorCode(errCode);
        }
    };
    ctxt->SetAction(std::move(input), std::move(output));
    // 2 means JsAPI:switchCurrentInputMethodSubtype has 2 params at most.
    AsyncCall asyncCall(env, info, ctxt, 2);
    return asyncCall.Call(env, exec, "switchCurrentInputMethodSubtype");
}

napi_value JsInputMethod::SwitchCurrentInputMethodAndSubtype(napi_env env, napi_callback_info info)
{
    InputMethodSyncTrace tracer("JsInputMethod_SwitchCurrentInputMethodAndSubtype");
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PARAM_CHECK_RETURN(env, argc > 1, "at least two parameters is required!", TYPE_NONE, napi_invalid_arg);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[0], &valueType);
        PARAM_CHECK_RETURN(env, valueType == napi_object, "inputMethodProperty type must be InputMethodProperty!",
            TYPE_NONE, napi_invalid_arg);
        napi_typeof(env, argv[1], &valueType);
        PARAM_CHECK_RETURN(env, valueType == napi_object, "inputMethodSubtype type must be InputMethodSubtype!",
            TYPE_NONE, napi_invalid_arg);
        napi_status status = GetInputMethodSubProperty(env, argv[1], ctxt);
        return status;
    };
    auto output = [ctxt](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, ctxt->isSwitchInput, result);
        IMSA_HILOGE("output get boolean != nullptr[%{public}d]!", result != nullptr);
        return status;
    };
    auto exec = [ctxt](AsyncCall::Context *ctx) {
        int32_t errCode = ErrorCode::ERROR_EX_NULL_POINTER;
        auto instance = InputMethodController::GetInstance();
        if (instance != nullptr) {
            errCode = instance->SwitchInputMethod(SwitchTrigger::CURRENT_IME, ctxt->name, ctxt->id);
        }
        if (errCode == ErrorCode::NO_ERROR) {
            IMSA_HILOGI("exec SwitchInputMethod success.");
            ctxt->status = napi_ok;
            ctxt->SetState(ctxt->status);
            ctxt->isSwitchInput = true;
        } else {
            ctxt->SetErrorCode(errCode);
        }
    };
    ctxt->SetAction(std::move(input), std::move(output));
    // 3 means JsAPI:switchCurrentInputMethodAndSubtype has 3 params at most.
    AsyncCall asyncCall(env, info, ctxt, 3);
    return asyncCall.Call(env, exec, "switchCurrentInputMethodAndSubtype");
}

napi_value JsInputMethod::SetSimpleKeyboardEnabled(napi_env env, napi_callback_info info)
{
    InputMethodSyncTrace tracer("JsInputMethod_SetSimpleKeyboardEnabled");
    bool isSimpleKeyboardEnabled = false;
    size_t argc = 1;
    napi_value argv[1] = { nullptr };
    IMF_CALL(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    // 1 means least param num.
    PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, JsUtil::Const::Null(env));
    PARAM_CHECK_RETURN(env, JsUtil::GetValue(env, argv[0], isSimpleKeyboardEnabled),
        "enable must be boolean!", TYPE_NONE, JsUtil::Const::Null(env));
    auto controller = InputMethodController::GetInstance();
    if (controller != nullptr) {
        auto ret = controller->SetSimpleKeyboardEnabled(isSimpleKeyboardEnabled);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("SetSimpleKeyboardEnabled failed:%{public}d.", ret);
        }
    }

    return JsUtil::Const::Null(env);
}

napi_value JsInputMethod::OnAttachmentDidFail(napi_env env, napi_callback_info info)
{
    return Subscribe(env, info, ATTACH_FAIL_CB_EVENT_TYPE);
}

napi_value JsInputMethod::OffAttachmentDidFail(napi_env env, napi_callback_info info)
{
    return UnSubscribe(env, info, ATTACH_FAIL_CB_EVENT_TYPE);
}

napi_value JsInputMethod::Subscribe(napi_env env, napi_callback_info info, const std::string &eventType)
{
    IMSA_HILOGD("event type: %{public}s.", eventType.c_str());

    size_t argc = ARGC_MAX;
    napi_value argv[ARGC_MAX] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    // 1 means least param num.
    PARAM_CHECK_RETURN(env, argc >= 1, "at least one parameters is required!", TYPE_NONE, JsUtil::Const::Null(env));
    napi_value callback = argv[0];
    PARAM_CHECK_RETURN(
        env, JsUtil::GetType(env, callback) == napi_function, "callback", TYPE_FUNCTION, JsUtil::Const::Null(env));
    SetImcInnerListener();
    AddCallback(env, callback, eventType);

    return JsUtil::Const::Null(env);
}

napi_value JsInputMethod::UnSubscribe(napi_env env, napi_callback_info info, const std::string &eventType)
{
    IMSA_HILOGD("event type: %{public}s.", eventType.c_str());
    size_t argc = ARGC_MAX;
    napi_value argv[ARGC_MAX] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    napi_value callback = nullptr;
    if (argc > 0) {
        // if the one param is not napi_function/napi_undefined, return
        napi_value param = argv[0];
        auto paramType = JsUtil::GetType(env, param);
        if (paramType != napi_function && paramType != napi_undefined) {
            return JsUtil::Const::Null(env);
        }
        // if the second param is napi_function, delete it, else delete all
        callback = paramType == napi_function ? param : nullptr;
    }
    RemoveCallback(callback, eventType);

    return JsUtil::Const::Null(env);
}

void JsInputMethod::AddCallback(napi_env env, napi_value callback, const std::string &eventType)
{
    IMSA_HILOGD("event type: %{public}s", eventType.c_str());
    std::lock_guard<std::mutex> lock(jsCbsLock_);
    auto isSameCb = [&callback](const std::shared_ptr<JSCallbackObject> &cbObject) {
        return cbObject != nullptr &&
            JsUtils::Equals(cbObject->env_, callback, cbObject->callback_, cbObject->threadId_);
    };
    auto &cbObjects = jsCbs_[eventType];
    auto ret = std::any_of(cbObjects.begin(), cbObjects.end(), isSameCb);
    if (ret) {
        IMSA_HILOGD("callback already add.");
        return;
    }
    auto cbObject = std::make_shared<JSCallbackObject>(
        env, callback, std::this_thread::get_id(), AppExecFwk::EventHandler::Current());
    IMSA_HILOGD("add %{public}s callback succeed.", eventType.c_str());
    cbObjects.push_back(std::move(cbObject));
}

void JsInputMethod::RemoveCallback(napi_value callback, const std::string &eventType)
{
    IMSA_HILOGD("event type: %{public}s", eventType.c_str());
    std::lock_guard<std::mutex> lock(jsCbsLock_);
    auto eventIter = jsCbs_.find(eventType);
    if (eventIter == jsCbs_.end()) {
        IMSA_HILOGE("no callback for event:%{public}s!", eventType.c_str());
        return;
    }
    if (callback == nullptr) {
        IMSA_HILOGD("remove all callbacks for event:%{public}s.", eventType.c_str());
        jsCbs_.erase(eventIter);
        return;
    }
    auto isSameCb = [&callback](const std::shared_ptr<JSCallbackObject> &cbObject) {
        return cbObject != nullptr
               && JsUtils::Equals(cbObject->env_, callback, cbObject->callback_, cbObject->threadId_);
    };
    auto &cbObjects = eventIter->second;
    auto cbIter = std::find_if(cbObjects.begin(), cbObjects.end(), isSameCb);
    if (cbIter == cbObjects.end()) {
        IMSA_HILOGD("callback for event:%{public}s may be removed already!", eventType.c_str());
        return;
    }
    cbObjects.erase(cbIter);
    IMSA_HILOGD("remove %{public}s callback succeed.", eventType.c_str());
    if (cbObjects.empty()) {
        jsCbs_.erase(eventIter);
    }
}

napi_value JsInputMethod::GetJsAttachFailureReasonProperty(napi_env env)
{
    napi_value attachFailureReason = nullptr;
    IMF_CALL(napi_create_object(env, &attachFailureReason));
    bool ret = JsUtil::Object::WriteProperty(
        env, attachFailureReason, "CALLER_NOT_FOCUSED", static_cast<int32_t>(AttachFailureReason::CALLER_NOT_FOCUSED));
    ret = ret
          && JsUtil::Object::WriteProperty(
              env, attachFailureReason, "IME_ABNORMAL", static_cast<int32_t>(AttachFailureReason::IME_ABNORMAL));
    ret = ret
          && JsUtil::Object::WriteProperty(env, attachFailureReason, "SERVICE_ABNORMAL",
              static_cast<int32_t>(AttachFailureReason::SERVICE_ABNORMAL));
    return ret ? attachFailureReason : JsUtil::Const::Null(env);
}

void JsInputMethod::OnAttachmentDidFail(AttachFailureReason reason)
{
    IMSA_HILOGD("reason: %{public}d.", reason);
    auto jsCbObjects = GetJsCbObjects(ATTACH_FAIL_CB_EVENT_TYPE);
    for (const auto &jsCbObject : jsCbObjects) {
        OnAttachmentDidFail(reason, jsCbObject);
    }
}

void JsInputMethod::OnAttachmentDidFail(AttachFailureReason reason, const std::shared_ptr<JSCallbackObject> &jsCbObject)
{
    if (jsCbObject == nullptr) {
        IMSA_HILOGE("jsCbObject is nullptr.");
        return;
    }
    auto handler = jsCbObject->jsHandler_;
    if (handler == nullptr) {
        IMSA_HILOGE("handler is nullptr.");
        return;
    }
    auto entry = GetEntry(jsCbObject, [reason](UvEntry &entry) { entry.attachFailureReason = reason; });
    auto task = [entry]() {
        auto getReason = [entry](napi_env env, napi_value *args, uint8_t argc) -> bool {
            if (argc < 1) {
                return false;
            }
            auto reason = JsUtil::GetValue(env, static_cast<int32_t>(entry->attachFailureReason));
            if (reason == nullptr) {
                IMSA_HILOGE("failed to converse reason!");
                return false;
            }
            // 0 means the first param of callback.
            args[0] = reason;
            return true;
        };
        // 1 means callback has one param.
        JsCallbackHandler::Traverse(entry->jsCbObject, { 1, getReason });
    };
    handler->PostTask(task, ATTACH_FAIL_CB_EVENT_TYPE, 0, AppExecFwk::EventQueue::Priority::VIP);
}

std::shared_ptr<JsInputMethod::UvEntry> JsInputMethod::GetEntry(
    const std::shared_ptr<JSCallbackObject> &jsCbObject, const JsInputMethod::EntrySetter &entrySetter)
{
    auto entry = std::make_shared<UvEntry>(jsCbObject);
    if (entrySetter != nullptr) {
        entrySetter(*entry);
    }
    return entry;
}

std::vector<std::shared_ptr<JSCallbackObject>> JsInputMethod::GetJsCbObjects(const std::string &type)
{
    IMSA_HILOGD("type: %{public}s", type.c_str());
    std::lock_guard<std::mutex> lock(jsCbsLock_);
    auto iter = jsCbs_.find(type);
    if (iter == jsCbs_.end()) {
        IMSA_HILOGD("%{public}s not register.", type.c_str());
        return {};
    }
    return iter->second;
}

void JsInputMethod::SetImcInnerListener()
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        return;
    }
    static auto listener = std::make_shared<JsInputMethod>();
    instance->SetImcInnerListener(listener);
}
} // namespace MiscServices
} // namespace OHOS