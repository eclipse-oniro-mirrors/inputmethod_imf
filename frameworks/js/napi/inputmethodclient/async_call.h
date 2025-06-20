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
#ifndef ASYN_CALL_H
#define ASYN_CALL_H

#include "cpp/mutex.h"
#include "global.h"
#include "js_utils.h"
#include "ffrt.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "event_handler.h"

namespace OHOS {
namespace MiscServices {
class AsyncCall {
public:
    class Context {
    public:
        using InputAction = std::function<napi_status(napi_env, size_t, napi_value *, napi_value)>;
        using OutputAction = std::function<napi_status(napi_env, napi_value *)>;
        using ExecAction = std::function<void(Context *)>;
        using CallBackAction = std::function<void()>;
        using AsynExecAction = std::function<void(Context *, CallBackAction)>;
        Context(InputAction input, OutputAction output) : input_(std::move(input)), output_(std::move(output))
        {
            handler_ = AppExecFwk::EventHandler::Current();
        };
        virtual ~Context(){};
        void SetAction(InputAction input, OutputAction output = nullptr)
        {
            input_ = input;
            output_ = output;
        }

        void SetErrorCode(int32_t errorCode)
        {
            errorCode_ = errorCode;
        }

        void SetErrorMessage(const std::string &errMessage)
        {
            errMessage_ = errMessage;
        }

        void SetState(const napi_status &status)
        {
            status_ = status;
        }

        napi_status GetState()
        {
            return status_;
        }

        void SetAction(OutputAction output)
        {
            SetAction(nullptr, std::move(output));
        }

        virtual napi_status operator()(napi_env env, size_t argc, napi_value *argv, napi_value self)
        {
            if (input_ == nullptr) {
                return napi_ok;
            }
            auto ret = input_(env, argc, argv, self);
            input_ = nullptr;
            return ret;
        }

        virtual napi_status operator()(napi_env env, napi_value *result)
        {
            if (output_ == nullptr) {
                *result = nullptr;
                return napi_ok;
            }
            auto ret = output_(env, result);
            output_ = nullptr;
            return ret;
        }

        virtual void Exec()
        {
            if (exec_ == nullptr) {
                return;
            }
            exec_(this);
            exec_ = nullptr;
        };

        virtual void AsyncExec(CallBackAction cb)
        {
            if (asyncExec_ == nullptr) {
                return;
            }
            asyncExec_(this, cb);
            asyncExec_ = nullptr;
        };

        std::shared_ptr<AppExecFwk::EventHandler> GetHandler()
        {
            return handler_;
        }
    protected:
        friend class AsyncCall;
        InputAction input_ = nullptr;
        OutputAction output_ = nullptr;
        ExecAction exec_ = nullptr;
        AsynExecAction asyncExec_ = nullptr;
        napi_status status_ = napi_generic_failure;
        int32_t errorCode_ = 0;
        std::string errMessage_;
        std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    };

    struct InnerTask {
        InnerTask(napi_env env, napi_async_work work, const char *name);
        ~InnerTask();
        napi_env env = nullptr;
        napi_async_work work = nullptr;
        const char *name = nullptr;
        uint64_t startTime = 0;
    };

    struct TaskQueue {
        ffrt::mutex queuesMutex_;
        std::queue<InnerTask> taskQueue_;
        bool isRunning = false;
    };

    AsyncCall(napi_env env, napi_callback_info info, std::shared_ptr<Context> context, size_t maxParamCount);
    ~AsyncCall();
    napi_value Call(napi_env env, Context::ExecAction exec = nullptr, const std::string &resourceName = "AsyncCall");
    napi_value Call(napi_env env, Context::AsynExecAction exec = nullptr,
        const std::string &resourceName = "AsyncCallEx");
    napi_value Post(napi_env env, Context::ExecAction exec, std::shared_ptr<TaskQueue> queue, const char *func);
    napi_value SyncCall(napi_env env, Context::ExecAction exec = nullptr);

protected:
    struct AsyncContext {
        std::shared_ptr<Context> ctx = nullptr;
        napi_ref callback = nullptr;
        napi_ref self = nullptr;
        napi_deferred defer = nullptr;
        napi_async_work work = nullptr;
        std::shared_ptr<TaskQueue> queue = nullptr;
    };
    static void OnExecuteAsync(napi_env env, AsyncContext *context, Context::CallBackAction cb);
    static void OnComplete(napi_env env, napi_status status, void *data);

private:
    virtual void CallImpl(napi_env env, AsyncContext *context, const std::string &resourceName);

private:
    enum Arg : int { ARG_ERROR, ARG_DATA, ARG_BUTT };
    static void OnExecute(napi_env env, void *data);
    static void OnExecuteSeq(napi_env env, void *data);
    static void DeleteContext(napi_env env, AsyncContext *context);

    AsyncContext *context_ = nullptr;
    napi_env env_ = nullptr;
};
} // namespace MiscServices
} // namespace OHOS
#endif // ASYNC_CALL_H
