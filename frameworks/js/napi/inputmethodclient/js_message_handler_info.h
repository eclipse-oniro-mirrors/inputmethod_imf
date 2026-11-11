/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IMF_MESSAGE_HANDLER_INFO
#define IMF_MESSAGE_HANDLER_INFO

#include "async_call.h"
#include "global.h"
#include "input_method_utils.h"
#include "js_utils.h"

namespace OHOS {
namespace MiscServices {
struct MessageHandlerInfo {
    std::chrono::system_clock::time_point timestamp{};
    ArrayBuffer arrayBuffer;
    bool operator==(const MessageHandlerInfo &info) const
    {
        return (timestamp == info.timestamp && arrayBuffer == info.arrayBuffer);
    }
};

struct SendMessageContext : public AsyncCall::Context {
    ArrayBuffer arrayBuffer;
    napi_status status = napi_generic_failure;
    MessageHandlerInfo info;
    bool queued = false;
    SendMessageContext() : Context(nullptr, nullptr){};
    SendMessageContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output)){};

    napi_status ReadMessage(napi_env env, size_t argc, napi_value *argv)
    {
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(
            env, JsUtil::GetType(env, argv[0]) == napi_string, "msgId", TYPE_STRING, napi_generic_failure);
        CHECK_RETURN(JsUtils::GetValue(env, argv[0], arrayBuffer.msgId) == napi_ok, "msgId covert failed!",
            napi_generic_failure);
        arrayBuffer.jsArgc = argc;
        if (argc > 1) {
            bool isArrayBuffer = false;
            CHECK_RETURN(napi_is_arraybuffer(env, argv[1], &isArrayBuffer) == napi_ok, "napi_is_arraybuffer failed!",
                napi_generic_failure);
            PARAM_CHECK_RETURN(env, isArrayBuffer, "msgParam", TYPE_ARRAY_BUFFER, napi_generic_failure);
            CHECK_RETURN(JsUtils::GetValue(env, argv[1], arrayBuffer.msgParam) == napi_ok, "msgParam covert failed!",
                napi_generic_failure);
        }
        PARAM_CHECK_RETURN(env, ArrayBuffer::IsSizeValid(arrayBuffer), "msgId limit 256B and msgParam limit 128KB.",
            TYPE_NONE, napi_generic_failure);
        return napi_ok;
    }

    napi_status operator()(napi_env env, size_t argc, napi_value *argv, napi_value self) override
    {
        CHECK_RETURN(self != nullptr, "self is nullptr", napi_invalid_arg);
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
} // namespace MiscServices
} // namespace OHOS
#endif // IMF_MESSAGE_HANDLER_INFO
