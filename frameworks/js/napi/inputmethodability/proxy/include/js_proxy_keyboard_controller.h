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

#ifndef FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_PROXY_INPUTMETHODABILITY_JS_PROXY_KEYBOARD_CONTROLLER_H
#define FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_PROXY_INPUTMETHODABILITY_JS_PROXY_KEYBOARD_CONTROLLER_H

#include "async_call.h"
#include "global.h"
#include "napi/native_api.h"

namespace OHOS {
namespace MiscServices {
class JsProxyKeyboardController {
public:
    JsProxyKeyboardController() = default;
    ~JsProxyKeyboardController() = default;
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static napi_value HideSelf(napi_env env, napi_callback_info info);
    static napi_value GetProxyKeyboardControllerInstance(napi_env env);

private:
    struct HideSelfContext : public AsyncCall::Context {
        HideSelfContext() : Context(nullptr, nullptr){};

        napi_status operator()(napi_env env, napi_value *result) override
        {
            if (status_ != napi_ok) {
                output_ = nullptr;
                return status_;
            }
            return Context::operator()(env, result);
        }
    };
    static const std::string PKC_CLASS_NAME;
    static thread_local napi_ref PKCRef_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_PROXY_INPUTMETHODABILITY_JS_PROXY_KEYBOARD_CONTROLLER_H
