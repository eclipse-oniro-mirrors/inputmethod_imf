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

#include "async_call.h"

#include <algorithm>

#include "global.h"
#include "js_utils.h"
#include "native_engine/native_deferred.h"

namespace OHOS {
namespace MiscServices {
using namespace std::chrono;
constexpr size_t ARGC_MAX = 6;
constexpr int32_t MAX_WAIT_TIME = 500; // ms
static inline uint64_t GetTimeStamp()
{
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
AsyncCall::AsyncCall(napi_env env, napi_callback_info info, std::shared_ptr<Context> context, size_t maxParamCount)
    : env_(env)
{
    auto *asyncContext = new (std::nothrow) AsyncContext();
    if (asyncContext == nullptr) {
        IMSA_HILOGE("context_  is nullptr");
        return;
    }
    context_.reset(asyncContext);
    context_->ctx = std::move(context);
    context_->env = env;
    size_t argc = ARGC_MAX;
    napi_value self = nullptr;
    napi_value argv[ARGC_MAX] = { nullptr };
    IMF_CALL_RETURN_VOID(napi_get_cb_info(env, info, &argc, argv, &self, nullptr));
    napi_valuetype valueType = napi_undefined;
    argc = std::min(argc, maxParamCount);
    if (argc > 0) {
        IMF_CALL_RETURN_VOID(napi_typeof(env, argv[argc - 1], &valueType));
        if (valueType == napi_function) {
            IMF_CALL_RETURN_VOID(napi_create_reference(env, argv[argc - 1], 1, &context_->callback));
            argc = argc - 1;
        }
    }
    if (context_->ctx == nullptr) {
        IMSA_HILOGE("context is nullptr!");
        return;
    }
    IMF_CALL_RETURN_VOID((*context_->ctx)(env, argc, argv, self));
    IMF_CALL_RETURN_VOID(napi_create_reference(env, self, 1, &context_->self));
    context_->inputValid = true;
}

AsyncCall::~AsyncCall()
{
    if (context_ == nullptr) {
        return;
    }

    DeleteContext(env_, context_.get());
}

bool AsyncCall::PrepareResult(napi_env env, napi_value &result)
{
    if (context_ != nullptr && context_->ctx != nullptr && context_->inputValid) {
        context_->cleanupOwner = new (std::nothrow) AsyncContextOwner { context_ };
        if (context_->cleanupOwner == nullptr ||
            napi_add_env_cleanup_hook(env, OnEnvCleanup, context_->cleanupOwner) != napi_ok) {
            delete context_->cleanupOwner;
            context_->cleanupOwner = nullptr;
            JsUtils::ThrowException(env, IMFErrorCode::EXCEPTION_IMMS, "Failed to register async cleanup.", TYPE_NONE);
            return false;
        }
        auto status = context_->callback == nullptr ? napi_create_promise(env, &context_->defer, &result) :
                                                      napi_get_undefined(env, &result);
        if (status == napi_ok) {
            return true;
        }
    }
    IMSA_HILOGE("Failed to prepare async input or result channel.");
    bool pending = false;
    if (napi_is_exception_pending(env, &pending) == napi_ok && !pending) {
        JsUtils::ThrowException(env, IMFErrorCode::EXCEPTION_IMMS, "Failed to initialize async call.", TYPE_NONE);
    }
    return false;
}

napi_value AsyncCall::Call(napi_env env, Context::ExecAction exec, const std::string &resourceName)
{
    napi_value promise = nullptr;
    if (!PrepareResult(env, promise)) {
        return nullptr;
    }
    context_->ctx->exec_ = std::move(exec);
    auto context = context_;
    context_ = nullptr;
    CallImpl(env, context, resourceName);
    return promise;
}

napi_value AsyncCall::Post(napi_env env, Context::ExecAction exec, std::shared_ptr<TaskQueue> queue, const char *func)
{
    CHECK_RETURN(queue != nullptr, "Async task queue is unavailable.", nullptr);
    napi_value promise = nullptr;
    if (!PrepareResult(env, promise)) {
        return nullptr;
    }
    context_->ctx->exec_ = std::move(exec);
    napi_async_work work = context_->work;
    napi_value resource = nullptr;
    napi_status status = napi_create_string_utf8(env, func, NAPI_AUTO_LENGTH, &resource);
    if (status == napi_ok) {
        context_->workData = new (std::nothrow) AsyncContextOwner { context_ };
        status = context_->workData == nullptr ? napi_generic_failure : napi_ok;
    }
    if (status == napi_ok) {
        status = napi_create_async_work(
            env, nullptr, resource, AsyncCall::OnWorkExecuteSeq, AsyncCall::OnWorkComplete, context_->workData, &work);
    }
    if (status != napi_ok) {
        auto context = context_;
        context_ = nullptr;
        Fail(env, context, "Failed to create sequential async work.");
        return promise;
    }
    context_->work = work;
    context_->queue = queue;
    {
        std::unique_lock<ffrt::mutex> lock(queue->queuesMutex_);
        queue->taskQueue_.emplace(env, work, func);
        queue->taskQueue_.back().context = context_;
        context_ = nullptr;
    }
    StartNextTask(queue);
    return promise;
}

napi_value AsyncCall::SyncCall(napi_env env, AsyncCall::Context::ExecAction exec)
{
    napi_value promise = nullptr;
    if (!PrepareResult(env, promise)) {
        return nullptr;
    }
    context_->ctx->exec_ = std::move(exec);
    auto context = std::move(context_);
    AsyncCall::OnExecute(env, context.get());
    AsyncCall::OnComplete(env, context->ctx->status_, context.get());
    return promise;
}

void AsyncCall::OnWorkExecute(napi_env env, void *data)
{
    auto context = static_cast<AsyncContextOwner *>(data)->context;
    OnExecute(env, context.get());
}

void AsyncCall::OnWorkExecuteSeq(napi_env env, void *data)
{
    auto context = static_cast<AsyncContextOwner *>(data)->context;
    OnExecuteSeq(env, context.get());
}

void AsyncCall::OnWorkComplete(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContextOwner> owner(static_cast<AsyncContextOwner *>(data));
    auto context = owner->context;
    {
        std::lock_guard<std::mutex> lock(context->completionMutex);
        context->workData = nullptr;
        context->workSubmitted = false;
    }
    OnComplete(env, status, context.get());
}

void AsyncCall::OnExecute(napi_env env, void *data)
{
    AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
    if (context == nullptr || context->ctx == nullptr) {
        IMSA_HILOGE("context or context->ctx is nullptr!");
        return;
    }
    context->ctx->Exec();
}

void AsyncCall::OnExecuteSeq(napi_env env, void *data)
{
    AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
    if (context == nullptr || context->ctx == nullptr || context->queue == nullptr) {
        IMSA_HILOGE("context or context->queue is nullptr!");
        return;
    }
    auto queue = context->queue;
    {
        std::unique_lock<ffrt::mutex> lock(queue->queuesMutex_);
        if (queue->taskQueue_.empty() || queue->taskQueue_.front().work != context->work) {
            context->ctx->SetErrorCode(ErrorCode::ERROR_EX_SERVICE_SPECIFIC);
            context->ctx->SetErrorMessage("Async work does not own the queue head.");
            context->ctx->SetState(napi_generic_failure);
            return;
        }
    }
    OnExecute(env, data);
    {
        std::unique_lock<ffrt::mutex> lock(queue->queuesMutex_);
        if (queue->taskQueue_.empty() || queue->taskQueue_.front().work != context->work) {
            IMSA_HILOGE("Async queue head changed before completion.");
            return;
        }
        queue->taskQueue_.pop();
        queue->isRunning = false;
    }
    StartNextTask(queue);
}

void AsyncCall::StartNextTask(const std::shared_ptr<TaskQueue> &queue)
{
    napi_env failedEnv = nullptr;
    while (auto failed = SubmitNextTask(queue, failedEnv)) {
        Fail(failedEnv, failed, "Failed to submit sequential async work.");
    }
}

std::shared_ptr<AsyncCall::AsyncContext> AsyncCall::SubmitNextTask(
    const std::shared_ptr<TaskQueue> &queue, napi_env &failedEnv)
{
    std::unique_lock<ffrt::mutex> lock(queue->queuesMutex_);
    if (queue->isRunning || queue->taskQueue_.empty()) {
        return nullptr;
    }
    auto &task = queue->taskQueue_.front();
    std::lock_guard<std::mutex> contextLock(task.context->completionMutex);
    task.context->workSubmitted = true;
    auto status = task.context->closing ? napi_closing :
                                          napi_queue_async_work_with_qos(task.env, task.work, napi_qos_user_initiated);
    if (status == napi_ok) {
        queue->isRunning = true;
        return nullptr;
    }
    task.context->workSubmitted = false;
    IMSA_HILOGE("Failed to submit %{public}s, status: %{public}d", task.name, status);
    auto failed = task.context;
    failedEnv = task.env;
    queue->taskQueue_.pop();
    return failed;
}

void AsyncCall::Fail(napi_env env, const std::shared_ptr<AsyncContext> &context, const std::string &message)
{
    context->ctx->SetErrorCode(ErrorCode::ERROR_EX_SERVICE_SPECIFIC);
    context->ctx->SetErrorMessage(message);
    context->ctx->SetState(napi_generic_failure);
    context->ctx->Cleanup();
    IMSA_HILOGE("%{public}s", message.c_str());
    CompleteOnJsThread(env, context, napi_generic_failure);
}

void AsyncCall::CompleteOnJsThread(napi_env env, const std::shared_ptr<AsyncContext> &context, napi_status status)
{
    std::lock_guard<std::mutex> lock(context->completionMutex);
    if (context->closing) {
        context->ctx->Cleanup();
        return;
    }
    auto task = [env, context, status]() {
        OnComplete(env, status, context.get());
    };
    auto postStatus = napi_send_event(env, task, napi_eprio_high, "IMF_AsyncComplete");
    if (postStatus == napi_ok) {
        return;
    }
    if (postStatus != napi_closing) {
        auto handler = context->ctx->GetHandler();
        if (handler != nullptr &&
            handler->PostTask(task, "IMF_AsyncComplete", 0, AppExecFwk::EventQueue::Priority::VIP)) {
            return;
        }
    }
    context->ctx->Cleanup();
    IMSA_HILOGE(
        "Unable to deliver async completion, status: %{public}d; resources remain owned by the env cleanup hook.",
        postStatus);
}

void AsyncCall::OnComplete(napi_env env, napi_status status, void *data)
{
    AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
    if (context != nullptr && context->closing) {
        DeleteContext(env, context);
        return;
    }
    JsUtil::ScopeGuard scopeGuard(env);
    napi_value output = nullptr;
    if (context == nullptr || context->ctx == nullptr) {
        IMSA_HILOGE("context or context->ctx is nullptr!");
        DeleteContext(env, context);
        return;
    }
    if (status != napi_ok && context->ctx->errorCode_ == ErrorCode::NO_ERROR) {
        context->ctx->SetErrorCode(ErrorCode::ERROR_EX_SERVICE_SPECIFIC);
        context->ctx->SetErrorMessage("Async work failed or was cancelled.");
    }
    napi_status runStatus = status == napi_ok ? (*context->ctx)(env, &output) : status;
    context->ctx->Cleanup();
    AdvanceQueue(context);
    napi_value result[ARG_BUTT] = { 0 };
    if (status == napi_ok && runStatus == napi_ok) {
        napi_get_undefined(env, &result[ARG_ERROR]);
        if (output != nullptr) {
            IMSA_HILOGD("output != nullptr!");
            result[ARG_DATA] = output;
        } else {
            IMSA_HILOGD("output is nullptr!");
            napi_get_undefined(env, &result[ARG_DATA]);
        }
    } else {
        IMSA_HILOGE("failed, [status:%{public}d, runStatus:%{public}d, errorCode:%{public}d, errMessage:%{public}s].",
            status, runStatus, context->ctx->errorCode_, context->ctx->errMessage_.c_str());
        result[ARG_ERROR] = JsUtils::ToError(env, context->ctx->errorCode_, context->ctx->errMessage_);
        napi_get_undefined(env, &result[ARG_DATA]);
    }
    CompleteResult(env, context, status == napi_ok && runStatus == napi_ok, result);
    DeleteContext(env, context);
}

void AsyncCall::AdvanceQueue(AsyncContext *context)
{
    bool advance = false;
    if (context->queue != nullptr) {
        std::unique_lock<ffrt::mutex> lock(context->queue->queuesMutex_);
        if (!context->queue->taskQueue_.empty() && context->queue->taskQueue_.front().work == context->work) {
            context->queue->taskQueue_.pop();
            context->queue->isRunning = false;
            advance = true;
        }
    }
    if (advance) {
        StartNextTask(context->queue);
    }
}

void AsyncCall::CompleteResult(napi_env env, AsyncContext *context, bool success, napi_value (&result)[ARG_BUTT])
{
    if (context->defer != nullptr) {
        bool pending = false;
        auto resultValue = success ? result[ARG_DATA] : result[ARG_ERROR];
        if (resultValue != nullptr && napi_is_exception_pending(env, &pending) == napi_ok && !pending) {
            auto deferred = context->defer;
            context->defer = nullptr;
            if (success) {
                napi_resolve_deferred(env, deferred, result[ARG_DATA]);
            } else {
                napi_reject_deferred(env, deferred, result[ARG_ERROR]);
            }
        }
    } else {
        napi_value callback = nullptr;
        napi_get_reference_value(env, context->callback, &callback);
        napi_value returnValue;
        napi_call_function(env, nullptr, callback, ARG_BUTT, result, &returnValue);
    }
}

void AsyncCall::OnEnvCleanup(void *data)
{
    std::unique_ptr<AsyncContextOwner> owner(static_cast<AsyncContextOwner *>(data));
    auto context = owner->context;
    auto queue = context->queue;
    // Match StartNextTask's lock order, and never leave an unsubmitted work item in the shared queue.
    std::unique_lock<ffrt::mutex> queueLock;
    if (queue != nullptr) {
        queueLock = std::unique_lock<ffrt::mutex>(queue->queuesMutex_);
    }
    {
        std::lock_guard<std::mutex> lock(context->completionMutex);
        context->closing = true;
        context->cleanupOwner = nullptr;
        if (queue != nullptr && !context->workSubmitted) {
            std::queue<InnerTask> remaining;
            while (!queue->taskQueue_.empty()) {
                auto &task = queue->taskQueue_.front();
                if (task.context != context) {
                    remaining.push(std::move(task));
                }
                queue->taskQueue_.pop();
            }
            queue->taskQueue_.swap(remaining);
        }
        ReleaseResources(context->env, context.get());
    }
    if (queueLock.owns_lock()) {
        queueLock.unlock();
    }
}

void AsyncCall::DeleteContext(napi_env env, AsyncContext *context)
{
    if (context == nullptr) {
        IMSA_HILOGE("context is nullptr!");
        return;
    }
    std::unique_ptr<AsyncContextOwner> owner(context->cleanupOwner);
    std::lock_guard<std::mutex> lock(context->completionMutex);
    context->closing = true;
    if (owner != nullptr) {
        napi_remove_env_cleanup_hook(env, OnEnvCleanup, owner.get());
        context->cleanupOwner = nullptr;
    }
    ReleaseResources(env, context);
}

void AsyncCall::ReleaseResources(napi_env env, AsyncContext *context)
{
    if (env != nullptr) {
        if (context->ctx != nullptr) {
            context->ctx->Cleanup();
            if (!context->jsResourcesReleased) {
                context->ctx->ReleaseJsResources(env);
            }
            context->ctx->input_ = nullptr;
            context->ctx->output_ = nullptr;
            if (!context->workSubmitted) {
                context->ctx->exec_ = nullptr;
                context->ctx->asyncExec_ = nullptr;
            }
        }
        if (context->callback != nullptr && napi_delete_reference(env, context->callback) != napi_ok) {
            IMSA_HILOGE("Failed to release async callback.");
        }
        context->callback = nullptr;
        if (context->self != nullptr && napi_delete_reference(env, context->self) != napi_ok) {
            IMSA_HILOGE("Failed to release async receiver.");
        }
        context->self = nullptr;
        // NAPI has no discard API; its native deferred owns a VM global handle until settled or destroyed.
        delete reinterpret_cast<NativeDeferred *>(context->defer);
        context->defer = nullptr;
        context->jsResourcesReleased = true;
        if (!context->workSubmitted) {
            if (context->work != nullptr && napi_delete_async_work(env, context->work) != napi_ok) {
                IMSA_HILOGE("Failed to release async work.");
            }
            context->work = nullptr;
            delete context->workData;
            context->workData = nullptr;
        }
    }
}

AsyncCall::InnerTask::InnerTask(napi_env env, napi_async_work work, const char *name)
    : env(env), work(work), name(name), startTime(GetTimeStamp())
{
}

AsyncCall::InnerTask::~InnerTask()
{
    auto endTime = GetTimeStamp();
    if (startTime > endTime) {
        IMSA_HILOGE("startTime:%{public}" PRIu64 ", endTime:%{public}" PRIu64, startTime, endTime);
        return;
    }
    if (endTime - startTime > MAX_WAIT_TIME) {
        IMSA_HILOGW("async work timeout! func:%{public}s, startTime:%{public}" PRIu64 ", endTime:%{public}" PRIu64
                    ", cost:%{public}" PRIu64 "ms",
            name, startTime, endTime, endTime - startTime);
    } else {
        IMSA_HILOGD("async work finished! func:%{public}s, startTime:%{public}" PRIu64 ", endTime:%{public}" PRIu64
                    ", cost:%{public}" PRIu64 "ms",
            name, startTime, endTime, endTime - startTime);
    }
}

napi_value AsyncCall::Call(napi_env env, Context::AsynExecAction exec, const std::string &resourceName)
{
    napi_value promise = nullptr;
    if (!PrepareResult(env, promise)) {
        return nullptr;
    }
    context_->ctx->asyncExec_ = std::move(exec);
    auto context = context_;
    context_ = nullptr;
    CallImpl(env, context, resourceName);
    return promise;
}

void AsyncCall::OnExecuteAsync(napi_env env, const std::shared_ptr<AsyncContext> &context, Context::CallBackAction cb)
{
    if (context == nullptr || context->ctx == nullptr) {
        IMSA_HILOGE("context or context->ctx is nullptr!");
        return;
    }

    context->ctx->AsyncExec(cb);
}

void AsyncCall::CallImpl(napi_env env, const std::shared_ptr<AsyncContext> &context, const std::string &resourceName)
{
    if (context == nullptr) {
        IMSA_HILOGE("context is nullptr!");
        return;
    }
    napi_value resource = nullptr;
    std::string name = "IMF_" + resourceName;
    napi_status status = napi_create_string_utf8(env, name.c_str(), NAPI_AUTO_LENGTH, &resource);
    if (status == napi_ok) {
        context->workData = new (std::nothrow) AsyncContextOwner { context };
        status = context->workData == nullptr ? napi_generic_failure : napi_ok;
    }
    if (status == napi_ok) {
        status = napi_create_async_work(env, nullptr, resource, AsyncCall::OnWorkExecute, AsyncCall::OnWorkComplete,
            context->workData, &context->work);
    }
    if (status != napi_ok) {
        Fail(env, context, "Failed to create async work.");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(context->completionMutex);
        context->workSubmitted = true;
        status = napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated);
        context->workSubmitted = status == napi_ok;
    }
    if (status != napi_ok) {
        Fail(env, context, "Failed to submit async work.");
    }
}
} // namespace MiscServices
} // namespace OHOS
