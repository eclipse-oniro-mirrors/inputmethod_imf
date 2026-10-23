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
#include "proxy_listener_base.h"

#include <algorithm>

namespace OHOS {
namespace MiscServices {

std::vector<std::shared_ptr<CallbackObjects>> ProxyListenerBase::GetCallbacks(const std::string &type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = jsCbMap_.find(type);
    if (it == jsCbMap_.end() || it->second.empty()) {
        return {};
    }
    return it->second;
}

void ProxyListenerBase::RegisterListener(
    std::string const &type, callbackTypes &&cb, uintptr_t opq)
{
    std::lock_guard<std::mutex> lock(mutex_);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        IMSA_HILOGE("Failed to register %{public}s", type.c_str());
        return;
    }
    auto &cbVec = jsCbMap_[type];
    bool isDuplicate =
        std::any_of(cbVec.begin(), cbVec.end(), [env, callbackRef](const std::shared_ptr<CallbackObjects> &obj) {
            ani_boolean isEqual = false;
            return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
        });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        IMSA_HILOGD("%{public}s is already registered", type.c_str());
        return;
    }
    cbVec.emplace_back(std::make_shared<CallbackObjects>(cb, callbackRef));
    IMSA_HILOGI("Registered success type: %{public}s", type.c_str());
}

void ProxyListenerBase::UnRegisterListener(
    std::string const &type, taihe::optional_view<uintptr_t> opq)
{
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("Failed to unregister %{public}s, env is nullptr", type.c_str());
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const auto iter = jsCbMap_.find(type);
    if (iter == jsCbMap_.end()) {
        IMSA_HILOGE("%{public}s is not registered", type.c_str());
        return;
    }
    if (!opq.has_value()) {
        jsCbMap_.erase(iter);
        return;
    }
    GlobalRefGuards guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        IMSA_HILOGE("Failed to unregister %{public}s, GlobalRefGuard is false!", type.c_str());
        return;
    }
    const auto pred = [env, targetRef = guard.get()](const std::shared_ptr<CallbackObjects> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        (*it)->Release();
        callbacks.erase(it);
    }
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
    }
}

} // namespace MiscServices
} // namespace OHOS
