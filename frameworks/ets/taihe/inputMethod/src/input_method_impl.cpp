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

#include "input_method_impl.h"

#include "input_method_controller.h"

namespace OHOS {
namespace MiscServices {
std::mutex InputMethodImpl::jsCbsLock_;
std::mutex InputMethodImpl::listenerMutex_;
std::shared_ptr<InputMethodImpl> InputMethodImpl::listener_{ nullptr };
std::unordered_map<std::string, std::vector<std::shared_ptr<CallbackObject>>> InputMethodImpl::jsCbMap_;
std::shared_ptr<InputMethodImpl> InputMethodImpl::GetInstance()
{
    if (listener_ == nullptr) {
        std::lock_guard<std::mutex> lock(listenerMutex_);
        if (listener_ == nullptr) {
            listener_ = std::make_shared<InputMethodImpl>();
        }
    }
    return listener_;
}

void InputMethodImpl::SetImcInnerListener()
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        return;
    }
    instance->SetImcInnerListener(listener_);
}

void InputMethodImpl::RegisterListener(std::string const &type, callbackType &&cb, uintptr_t opq)
{
    IMSA_HILOGD("event type: %{public}s.", type.c_str());
    SetImcInnerListener();
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        IMSA_HILOGE("ani_env is nullptr or GlobalReference_Create failed, type: %{public}s!", type.c_str());
        return;
    }

    std::lock_guard<std::mutex> lock(jsCbsLock_);
    auto &cbVec = jsCbMap_[type];
    bool isDuplicate = std::any_of(cbVec.begin(), cbVec.end(),
        [env, callbackRef](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean isEqual = false;
        return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
    });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        IMSA_HILOGI("callback already registered, type: %{public}s!", type.c_str());
        return;
    }
    cbVec.emplace_back(std::make_shared<CallbackObject>(cb, callbackRef));
    IMSA_HILOGD("add %{public}s callback succeed.", type.c_str());
}

void InputMethodImpl::UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq)
{
    IMSA_HILOGD("event type: %{public}s.", type.c_str());
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("ani_env is nullptr!");
        return;
    }
    std::lock_guard<std::mutex> lock(jsCbsLock_);
    const auto iter = jsCbMap_.find(type);
    if (iter == jsCbMap_.end()) {
        IMSA_HILOGE("no callback for event:%{public}s!", type.c_str());
        return;
    }

    if (!opq.has_value()) {
        IMSA_HILOGD("remove all callbacks for event:%{public}s.", type.c_str());
        jsCbMap_.erase(iter);
        return;
    }

    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        IMSA_HILOGE("GlobalRefGuard is false!");
        return;
    }

    const auto pred = [env, targetRef = guard.get()](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it == callbacks.end()) {
        IMSA_HILOGD("callback for event:%{public}s may be removed already!", type.c_str());
        return;
    }
    callbacks.erase(it);
    IMSA_HILOGD("remove %{public}s callback succeed.", type.c_str());
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
    }
}

std::vector<std::shared_ptr<CallbackObject>> InputMethodImpl::GetJsCbObjects(const std::string &type)
{
    IMSA_HILOGD("type: %{public}s", type.c_str());
    std::lock_guard<std::mutex> lock(jsCbsLock_);
    auto iter = jsCbMap_.find(type);
    if (iter == jsCbMap_.end()) {
        IMSA_HILOGD("%{public}s not register.", type.c_str());
        return {};
    }
    return iter->second;
}

void InputMethodImpl::OnAttachmentDidFail(AttachFailureReason reason)
{
    IMSA_HILOGD("reason: %{public}d.", reason);
    auto jsCbObjects = GetJsCbObjects(ATTACH_FAIL_CB_EVENT_TYPE);
    for (const auto &jsCbObject : jsCbObjects) {
        OnAttachmentDidFail(reason, jsCbObject);
    }
}

void InputMethodImpl::OnAttachmentDidFail(AttachFailureReason reason, const std::shared_ptr<CallbackObject> &jsCbObject)
{
    if (jsCbObject == nullptr) {
        IMSA_HILOGE("jsCbObject is nullptr.");
        return;
    }
    auto &func = std::get<taihe::callback<void(AttachFailureReason_t)>>(jsCbObject->callback);
    AttachFailureReason_t tmpReason = EnumConvert::ConvertAttachFailureReason(reason);
    func(tmpReason);
}
} // namespace MiscServices
} // namespace OHOS