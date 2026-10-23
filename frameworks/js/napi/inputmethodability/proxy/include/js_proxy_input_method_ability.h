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

#ifndef FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_JS_PROXY_INPUT_METHOD_ABILITY_H
#define FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_JS_PROXY_INPUT_METHOD_ABILITY_H

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "event_handler.h"
#include "global.h"
#include "input_method_engine_listener.h"
#include "input_method_property.h"
#include "inputmethod_message_handler.h"
#include "js_callback_object.h"
#include "js_proxy_listener_base.h"
#include "js_proxy_text_input_client.h"
#include "napi/native_api.h"

namespace OHOS {
namespace MiscServices {
class JsProxyInputMethodAbility : public JsProxyListenerBase, public InputMethodEngineListener {
public:
    JsProxyInputMethodAbility() = default;
    ~JsProxyInputMethodAbility() override = default;
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value JsConstructor(napi_env env, napi_callback_info cbInfo);
    static napi_value SubscribeInputStart(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeInputStart(napi_env env, napi_callback_info info);
    static napi_value SubscribeKeyboardShow(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeKeyboardShow(napi_env env, napi_callback_info info);
    static napi_value SubscribeKeyboardHide(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeKeyboardHide(napi_env env, napi_callback_info info);
    static napi_value SubscribeUnregister(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeUnregister(napi_env env, napi_callback_info info);
    static napi_value GetProxyInputMethodAbility(napi_env env, napi_callback_info info);

    void OnInputStart() override;
    void OnUnregister() override;

protected:
    void OnKeyboardStatus(bool isShow) override;
    static void DealInputStart(const std::shared_ptr<JSCallbackObject> &callback);

private:
    static std::shared_ptr<JsProxyInputMethodAbility> GetInstance();
    static bool InitProxyInputMethodAbility();
    static const std::string PIMAS_CLASS_NAME;
    static thread_local napi_ref PIMASRef_;
    static std::mutex instanceMutex_;
    static std::shared_ptr<JsProxyInputMethodAbility> instance_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_JS_PROXY_INPUT_METHOD_ABILITY_H
