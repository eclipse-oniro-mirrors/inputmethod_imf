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
#ifndef EDIT_ASYN_CALL_H
#define EDIT_ASYN_CALL_H

#include <atomic>

#include "async_call.h"
namespace OHOS {
namespace MiscServices {
class EditAsyncCall : public AsyncCall {
public:
    EditAsyncCall(napi_env env, napi_callback_info info, std::shared_ptr<Context> context, size_t maxParamCount)
        : AsyncCall(env, info, context, maxParamCount){};
    virtual ~EditAsyncCall(){};

private:
    void CallImpl(napi_env env, const std::shared_ptr<AsyncContext> &context, const std::string &resourceName) override
    {
        if (context == nullptr || context->ctx == nullptr) {
            IMSA_HILOGE("context is nullptr!");
            return;
        }
        auto completed = std::make_shared<std::atomic<bool>>(false);
        std::weak_ptr<AsyncContext> weakContext = context;
        auto cb = [env, weakContext, completed, resourceName]() -> void {
            if (completed->exchange(true)) {
                IMSA_HILOGE("Ignoring repeated %{public}s completion.", resourceName.c_str());
                return;
            }
            auto context = weakContext.lock();
            if (context == nullptr) {
                return;
            }
            CompleteOnJsThread(env, context, context->ctx->GetState());
        };
        AsyncCall::OnExecuteAsync(env, context, cb);
    }
};
} // namespace MiscServices
} // namespace OHOS
#endif // EDIT_ASYN_CALL_H
