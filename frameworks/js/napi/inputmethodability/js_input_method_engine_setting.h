/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef INTERFACE_KITS_JS_INPUT_METHOD_ENGINE_SETTING_H
#define INTERFACE_KITS_JS_INPUT_METHOD_ENGINE_SETTING_H

#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <uv.h>

#include "async_call.h"
#include "global.h"
#include "input_method_engine_listener.h"
#include "input_method_property.h"
#include "js_callback_object.h"
#include "js_panel.h"
#include "napi/native_api.h"
#include "input_method_panel.h"

namespace OHOS {
namespace MiscServices {
class JsInputMethodEngineSetting : public InputMethodEngineListener {
public:
    JsInputMethodEngineSetting() = default;
    ~JsInputMethodEngineSetting() override = default;
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value GetInputMethodEngine(napi_env env, napi_callback_info info);
    static napi_value GetInputMethodAbility(napi_env env, napi_callback_info info);
    static napi_value Subscribe(napi_env env, napi_callback_info info);
    static napi_value UnSubscribe(napi_env env, napi_callback_info info);
    static napi_value MoveCursor(napi_env env, napi_callback_info info);
    static napi_value CreatePanel(napi_env env, napi_callback_info info);
    static napi_value DestroyPanel(napi_env env, napi_callback_info info);
    void OnInputStart() override;
    void OnKeyboardStatus(bool isShow) override;
    void OnInputStop(const std::string &imeId) override;
    void OnSetCallingWindow(uint32_t windowId) override;
    void OnSetSubtype(const SubProperty &property) override;

private:
    enum arg : int { ARG_ERROR, ARG_DATA, ARG_BUTT };
    struct PanelContext : public AsyncCall::Context {
        int32_t panelType = -1;
        int32_t panelFlag = 0;
        JsPanel *jsPanel = nullptr;
        void *contextPtr = nullptr;
        napi_ref ref = nullptr;
        PanelContext() : Context(nullptr, nullptr){};
        PanelContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output)){};

        napi_status operator()(napi_env env, size_t argc, napi_value *argv, napi_value self) override
        {
            NAPI_ASSERT_BASE(env, self != nullptr, "self is nullptr", napi_invalid_arg);
            return Context::operator()(env, argc, argv, self);
        }
        napi_status operator()(napi_env env, napi_value *result) override
        {
            if (status_ != napi_ok) {
                output_ = nullptr;
                return status_;
            }
            return Context::operator()(env, result);
        }
    };

    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
    static std::shared_ptr<JsInputMethodEngineSetting> GetInputMethodEngineSetting();
    static napi_value GetJsConstProperty(napi_env env, uint32_t num);
    static napi_value GetIntJsConstProperty(napi_env env, int32_t num);
    static napi_value GetIMEInstance(napi_env env, napi_callback_info info, int flag);
    void RegisterListener(napi_value callback, std::string type, std::shared_ptr<JSCallbackObject> callbackObj);
    void UnRegisterListener(napi_value callback, std::string type);
    static napi_value GetResultOnSetSubtype(napi_env env, const SubProperty &property);
    static napi_ref NewWithRef(napi_env env, size_t argc, napi_value *argv, void **out, napi_value constructor);
    static void GetNativeContext(napi_env env, NativeValue *nativeContext, void *&contextPtr);
    static const std::string IMES_CLASS_NAME;
    static thread_local napi_ref IMESRef_;
    struct UvEntry {
        std::vector<std::shared_ptr<JSCallbackObject>> vecCopy;
        std::string type;
        std::string imeid;
        uint32_t windowid = 0;
        SubProperty subProperty;
        UvEntry(const std::vector<std::shared_ptr<JSCallbackObject>> &cbVec, const std::string &type)
            : vecCopy(cbVec), type(type)
        {
        }
    };
    using EntrySetter = std::function<void(UvEntry &)>;
    uv_work_t *GetUVwork(const std::string &type, EntrySetter entrySetter = nullptr);
    uv_loop_s *loop_ = nullptr;
    std::recursive_mutex mutex_;
    std::map<std::string, std::vector<std::shared_ptr<JSCallbackObject>>> jsCbMap_;
    static std::mutex engineMutex_;
    static std::shared_ptr<JsInputMethodEngineSetting> inputMethodEngine_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // INTERFACE_KITS_JS_INPUT_METHOD_ENGINE_SETTING_H