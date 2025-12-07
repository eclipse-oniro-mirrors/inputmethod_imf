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
#include "input_method_client_impl.h"
#include "js_utils.h"
#include "event_checker.h"
#include "input_method_ability.h"

namespace OHOS {
namespace MiscServices {
using namespace taihe;
std::mutex InputMethodClientImpl::engineMutex_;
std::shared_ptr<InputMethodClientImpl> InputMethodClientImpl::textInputClientEngine_ {nullptr};
ani_ref InputMethodClientImpl::TICRef_ = nullptr;
std::shared_ptr<InputMethodClientImpl> InputMethodClientImpl::GetInstance()
{
    if (textInputClientEngine_ == nullptr) {
        std::lock_guard<std::mutex> lock(engineMutex_);
        if (textInputClientEngine_ == nullptr) {
            textInputClientEngine_ = std::make_shared<InputMethodClientImpl>();
            if (!Init()) {
                IMSA_HILOGE("Init failed!");
                return nullptr;
            }
        }
    }
    return textInputClientEngine_;
}

bool InputMethodClientImpl::InitTextInputClientEngine()
{
    if (!InputMethodAbility::GetInstance().IsCurrentIme()) {
        return false;
    }
    if (textInputClientEngine_ == nullptr) {
        return false;
    }
    InputMethodAbility::GetInstance().SetTextInputClientListener(textInputClientEngine_);
    return true;
}

bool InputMethodClientImpl::Init()
{
    if (!InitTextInputClientEngine()) {
        IMSA_HILOGE("textInputClientEngine_ is nullptr!");
        return false;
    }
    return true;
}

ani_ref InputMethodClientImpl::GetInputClientInstance(ani_env *env)
{
    ani_ref result = nullptr;
    if (env == nullptr) {
        IMSA_HILOGE("InputMethodClientImpl: env is nullptr");
        return result;
    }
    ani_class cls;
    if (ANI_OK != env->FindClass("@ohos.inputMethodEngine.inputMethodEngine._taihe_InputClient_inner", &cls)) {
        IMSA_HILOGE("InputMethodClientImpl: FindClass failed");
        return result;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        IMSA_HILOGE("InputMethodClientImpl: Class_FindMethod 'constructor' failed");
        return result;
    }

    ani_object obj;
    if (ANI_OK != env->Object_New(cls, ctor, &obj)) {
        IMSA_HILOGE("InputMethodClientImpl: Object_New ani_object failed");
        return result;
    }
    if (ANI_OK != env->GlobalReference_Create(reinterpret_cast<ani_ref>(obj), &TICRef_)) {
        IMSA_HILOGE("InputMethodClientImpl: GlobalReference_Create TICRef_ failed");
        return result;
    }
    if (TICRef_ == nullptr) {
        IMSA_HILOGE("InputMethodClientImpl: TICRef_ is nullptr");
        return result;
    }
    ani_wref wref;
    if ((env->WeakReference_Create(TICRef_, &wref)) != ANI_OK) {
        IMSA_HILOGE("InputMethodClientImpl: create weakref error");
        return result;
    }

    ani_boolean wasReleased;
    if ((env->WeakReference_GetReference(wref, &wasReleased, &result)) != ANI_OK) {
        IMSA_HILOGE("InputMethodClientImpl: create ref error");
        return result;
    }
    IMSA_HILOGI("InputMethodClientImpl: success");
    return result;
}

void InputMethodClientImpl::RegisterListener(std::string const &type, callbackTypes &&cb, uintptr_t opq)
{
    if (!EventChecker::IsValidEventType(EventSubscribeModule::TEXT_INPUT_CLIENT, type)) {
        IMSA_HILOGE("subscribe failed, type: %{public}s.", type.c_str());
        return;
    }
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
        std::any_of(cbVec.begin(), cbVec.end(), [env, callbackRef](std::unique_ptr<CallbackObjects> &obj) {
            ani_boolean isEqual = false;
            return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
        });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        IMSA_HILOGD("%{public}s is already registered", type.c_str());
        return;
    }
    cbVec.emplace_back(std::make_unique<CallbackObjects>(cb, callbackRef));
    IMSA_HILOGI("Registered success type: %{public}s", type.c_str());
}

void InputMethodClientImpl::UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq)
{
    if (!EventChecker::IsValidEventType(EventSubscribeModule::TEXT_INPUT_CLIENT, type)) {
        IMSA_HILOGE("unsubscribe failed, type: %{public}s.", type.c_str());
        return;
    }

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

    const auto pred = [env, targetRef = guard.get()](std::unique_ptr<CallbackObjects> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        callbacks.erase(it);
    }
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
    }
}

void InputMethodClientImpl::OnAttachOptionsChanged(const AttachOptions &attachOptions)
{
    IMSA_HILOGD("OnAttachOptionsChanged requestKeyboardReason:%{public}d.", attachOptions.requestKeyboardReason);
    std::string type = "attachOptionsDidChange";
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(AttachOptions_t const&)>>(cb->callback);
        func(CommonConvert::NativeAttachOptionsToAni(attachOptions));
    }
}
} // namespace MiscServices
} // namespace OHOS