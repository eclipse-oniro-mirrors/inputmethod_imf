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

#ifndef FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_JS_PROXY_TEXT_INPUT_CLIENT_H
#define FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_JS_PROXY_TEXT_INPUT_CLIENT_H

#include <string>

#include "async_call.h"
#include "napi/native_api.h"

namespace OHOS {
namespace MiscServices {
class JsProxyTextInputClient {
public:
    JsProxyTextInputClient() = default;
    ~JsProxyTextInputClient() = default;
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static napi_value GetProxyTextInputClientInstance(napi_env env);
    static napi_value SendKeyFunction(napi_env env, napi_callback_info info);
    static napi_value DeleteForward(napi_env env, napi_callback_info info);
    static napi_value DeleteBackward(napi_env env, napi_callback_info info);
    static napi_value InsertText(napi_env env, napi_callback_info info);

private:
    struct ProxySendKeyFunctionContext : public AsyncCall::Context {
        int32_t action = 0;
        napi_status status = napi_generic_failure;
        ProxySendKeyFunctionContext() : Context(nullptr, nullptr){};
        ProxySendKeyFunctionContext(InputAction input, OutputAction output)
            : Context(std::move(input), std::move(output)){};

        napi_status operator()(napi_env env, size_t argc, napi_value *argv, napi_value self) override
        {
            CHECK_RETURN(self != nullptr, "self is nullptr", napi_invalid_arg);
            return Context::operator()(env, argc, argv, self);
        }
    };

    struct ProxyDeleteContext : public AsyncCall::Context {
        int32_t length = 0;
        napi_status status = napi_generic_failure;
        ProxyDeleteContext() : Context(nullptr, nullptr){};
        ProxyDeleteContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output)){};

        napi_status operator()(napi_env env, size_t argc, napi_value *argv, napi_value self) override
        {
            CHECK_RETURN(self != nullptr, "self is nullptr", napi_invalid_arg);
            return Context::operator()(env, argc, argv, self);
        }
    };

    struct ProxyInsertTextContext : public AsyncCall::Context {
        std::string text;
        napi_status status = napi_generic_failure;
        ProxyInsertTextContext() : Context(nullptr, nullptr){};
        ProxyInsertTextContext(InputAction input, OutputAction output)
            : Context(std::move(input), std::move(output)){};

        napi_status operator()(napi_env env, size_t argc, napi_value *argv, napi_value self) override
        {
            CHECK_RETURN(self != nullptr, "self is nullptr", napi_invalid_arg);
            return Context::operator()(env, argc, argv, self);
        }
    };

    static const std::string PIC_CLASS_NAME;
    static thread_local napi_ref PICRef_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_JS_PROXY_TEXT_INPUT_CLIENT_H
