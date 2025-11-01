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
#ifndef INTERFACE_KITS_JS_INPUT_METHOD_H
#define INTERFACE_KITS_JS_INPUT_METHOD_H

#include <utility>

#include "async_call.h"
#include "element_name.h"
#include "global.h"
#include "imc_inner_listener.h"
#include "input_method_controller.h"
#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"

namespace OHOS {
namespace MiscServices {
struct SwitchInputMethodContext : public AsyncCall::Context {
    bool isSwitchInput = false;
    std::string packageName; // in InputMethodProperty
    std::string methodId;    // in InputMethodProperty
    std::string name;        // in InputMethodSubtype
    std::string id;          // in InputMethodSubtype
    SwitchTrigger trigger = SwitchTrigger::CURRENT_IME;
    napi_status status = napi_generic_failure;
    SwitchInputMethodContext() : Context(nullptr, nullptr){};
    SwitchInputMethodContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output)){};

    napi_status operator()(napi_env env, size_t argc, napi_value *argv, napi_value self) override
    {
        CHECK_RETURN(self != nullptr, "self is nullptr!", napi_invalid_arg);
        return Context::operator()(env, argc, argv, self);
    }
    napi_status operator()(napi_env env, napi_value *result) override
    {
        if (status != napi_ok) {
            output_ = nullptr;
            return status;
        }
        return Context::operator()(env, result);
    }
};

class JsInputMethod : public ImcInnerListener {
public:
    JsInputMethod() = default;
    ~JsInputMethod() = default;
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value SwitchInputMethod(napi_env env, napi_callback_info info);
    static napi_value SwitchCurrentInputMethodSubtype(napi_env env, napi_callback_info info);
    static napi_value SwitchCurrentInputMethodAndSubtype(napi_env env, napi_callback_info info);
    static napi_value GetCurrentInputMethodSubtype(napi_env env, napi_callback_info info);
    static napi_value GetCurrentInputMethod(napi_env env, napi_callback_info info);
    static napi_value GetDefaultInputMethod(napi_env env, napi_callback_info info);
    static napi_value GetSystemInputMethodConfigAbility(napi_env env, napi_callback_info info);
    static napi_value GetJsInputMethodProperty(napi_env env, const Property &property);
    static napi_value GetJSInputMethodSubProperties(napi_env env, const std::vector<SubProperty> &subProperties);
    static napi_value GetJSInputMethodProperties(napi_env env, const std::vector<Property> &properties);
    static napi_value GetJsInputMethodSubProperty(napi_env env, const SubProperty &subProperty);
    static napi_value GetJsInputConfigElement(napi_env env, const OHOS::AppExecFwk::ElementName &elementName);
    static napi_value SetSimpleKeyboardEnabled(napi_env env, napi_callback_info info);
    static napi_value OnAttachmentDidFail(napi_env env, napi_callback_info info);
    static napi_value OffAttachmentDidFail(napi_env env, napi_callback_info info);
    static napi_value GetJsAttachFailureReasonProperty(napi_env env);
    void OnAttachmentDidFail(AttachFailureReason reason) override;

private:
    static napi_status GetInputMethodProperty(napi_env env, napi_value argv,
        std::shared_ptr<SwitchInputMethodContext> ctxt);
    static napi_status GetInputMethodSubProperty(napi_env env, napi_value argv,
        std::shared_ptr<SwitchInputMethodContext> ctxt);
    static napi_value Subscribe(napi_env env, napi_callback_info info, const std::string &eventType);
    static napi_value UnSubscribe(napi_env env, napi_callback_info info, const std::string &eventType);
    static void AddCallback(napi_env env, napi_value callback, const std::string &eventType);
    static void RemoveCallback(napi_value callback, const std::string &eventType);
    static constexpr std::int32_t MAX_VALUE_LEN = 4096;
    static constexpr size_t PARAM_POS_TWO = 2;
    static constexpr size_t PARAM_POS_ONE = 1;
    static constexpr size_t ARGC_MAX = 6;
    static constexpr const char *ATTACH_FAIL_CB_EVENT_TYPE = "attachmentDidFail";
    struct UvEntry {
        std::shared_ptr<JSCallbackObject> jsCbObject;
        AttachFailureReason attachFailureReason{ AttachFailureReason::SERVICE_ABNORMAL };
        explicit UvEntry(const std::shared_ptr<JSCallbackObject> &object) : jsCbObject(object)
        {
        }
    };
    using EntrySetter = std::function<void(UvEntry &)>;
    std::shared_ptr<UvEntry> GetEntry(
        const std::shared_ptr<JSCallbackObject> &jsCbObject, const EntrySetter &entrySetter = nullptr);
    std::vector<std::shared_ptr<JSCallbackObject>> GetJsCbObjects(const std::string &type);
    static void SetImcInnerListener();
    void OnAttachmentDidFail(AttachFailureReason reason, const std::shared_ptr<JSCallbackObject> &jsCbObject);
    static std::mutex jsCbsLock_;
    static std::unordered_map<std::string, std::vector<std::shared_ptr<JSCallbackObject>>> jsCbs_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // INTERFACE_KITS_JS_INPUT_METHOD_H