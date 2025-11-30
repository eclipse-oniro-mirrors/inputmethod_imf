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
#include "input_method_keyboard_delegate_impl.h"
#include "input_method_ability.h"
#include "event_checker.h"

namespace OHOS {
namespace MiscServices {
constexpr size_t ARGC_TWO = 2;
using namespace taihe;
std::mutex KeyboardDelegateImpl::keyboardMutex_;
std::shared_ptr<KeyboardDelegateImpl> KeyboardDelegateImpl::keyboardDelegate_{ nullptr };
ani_ref KeyboardDelegateImpl::KCERef_ = nullptr;
ani_env* KeyboardDelegateImpl::env_ {nullptr};
ani_vm* KeyboardDelegateImpl::vm_ {nullptr};
ani_vm* KeyboardDelegateImpl::GetAniVm(ani_env* env)
{
    ani_vm* vm = nullptr;
    if (env->GetVM(&vm) != ANI_OK) {
        IMSA_HILOGE("GetVM failed");
        return nullptr;
    }
    return vm;
}

ani_env* KeyboardDelegateImpl::GetAniEnv(ani_vm* vm)
{
    ani_env* env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        IMSA_HILOGE("GetEnv failed");
        return nullptr;
    }
    return env;
}

ani_env* KeyboardDelegateImpl::AttachAniEnv(ani_vm* vm)
{
    ani_env *workerEnv = nullptr;
    ani_options aniArgs {0, nullptr};
    if (vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &workerEnv) != ANI_OK) {
        IMSA_HILOGE("Attach Env failed");
        return nullptr;
    }
    return workerEnv;
}

std::shared_ptr<KeyboardDelegateImpl> KeyboardDelegateImpl::GetInstance()
{
    if (keyboardDelegate_ == nullptr) {
        std::lock_guard<std::mutex> lock(keyboardMutex_);
        if (keyboardDelegate_ == nullptr) {
            auto delegate = std::make_shared<KeyboardDelegateImpl>();
            if (delegate == nullptr) {
                IMSA_HILOGE("keyboard delegate is nullptr!");
                return nullptr;
            }
            keyboardDelegate_ = delegate;
        }
    }
    return keyboardDelegate_;
}

ani_ref KeyboardDelegateImpl::GetKeyboardDelegateInstance(ani_env *env)
{
    ani_ref result = nullptr;
    if (env == nullptr) {
        IMSA_HILOGE("KeyboardDelegateImpl: env is nullptr");
        return result;
    }
    ani_class cls;
    if (ANI_OK != env->FindClass("@ohos.inputMethodEngine.inputMethodEngine._taihe_KeyboardDelegate_inner", &cls)) {
        IMSA_HILOGE("KeyboardDelegateImpl: FindClass failed");
        return result;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        IMSA_HILOGE("KeyboardDelegateImpl: Class_FindMethod 'constructor' failed");
        return result;
    }
    ani_object obj;
    if (ANI_OK != env->Object_New(cls, ctor, &obj)) {
        IMSA_HILOGE("KeyboardDelegateImpl: Object_New ani_object failed");
        return result;
    }
    if (ANI_OK != env->GlobalReference_Create(reinterpret_cast<ani_ref>(obj), &KCERef_)) {
        IMSA_HILOGE("KeyboardDelegateImpl: GlobalReference_Create KCERef_ failed");
        return result;
    }

    if (KCERef_ == nullptr) {
        IMSA_HILOGE("KeyboardDelegateImpl: KCERef_ is nullptr");
        return result;
    }
    ani_wref wref;
    if ((env->WeakReference_Create(KCERef_, &wref)) != ANI_OK) {
        IMSA_HILOGE("KeyboardDelegateImpl: create weakref error");
        return result;
    }

    ani_boolean wasReleased;
    if ((env->WeakReference_GetReference(wref, &wasReleased, &result)) != ANI_OK) {
        IMSA_HILOGE("KeyboardDelegateImpl: create ref error");
        return result;
    }
    IMSA_HILOGI("KeyboardDelegateImpl: success");
    return result;
}

void KeyboardDelegateImpl::RegisterListener(std::string const &type, callbackTypes &&cb, uintptr_t opq)
{
    if (!EventChecker::IsValidEventType(EventSubscribeModule::KEYBOARD_DELEGATE, type)) {
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
    env_ = env;
    vm_ = GetAniVm(env);
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

void KeyboardDelegateImpl::UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq)
{
    if (!EventChecker::IsValidEventType(EventSubscribeModule::KEYBOARD_DELEGATE, type)) {
        IMSA_HILOGE("subscribe failed, type: %{public}s.", type.c_str());
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

bool KeyboardDelegateImpl::OnKeyEvent(int32_t keyCode, int32_t keyStatus, sptr<KeyEventConsumerProxy> &consumer)
{
    std::string type = (keyStatus == ARGC_TWO ? "keyDown" : "keyUp");
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<bool(KeyEventType_t const&)>>(cb->callback);
        KeyEventType_t event {
            .keyCode = keyCode,
            .keyAction = keyStatus,
        };
        bool isConsumed = false;
        isConsumed = func(event);
        if (consumer != nullptr) {
            IMSA_HILOGE("consumer result: %{public}d!", isConsumed);
            OnKeyCodeConsumeResult(isConsumed, consumer);
        }
    }
    return true;
}

void KeyboardDelegateImpl::OnKeyCodeConsumeResult(bool isConsumed, sptr<KeyEventConsumerProxy> consumer)
{
    IMSA_HILOGI("result: %{public}d.", isConsumed);
    keyCodeConsume_ = true;
    keyCodeResult_ = isConsumed;
    if (keyEventConsume_) {
        consumer->OnKeyEventResult(keyCodeResult_ || keyEventResult_);
        keyCodeConsume_ = false;
        keyCodeResult_ = false;
    }
}

void KeyboardDelegateImpl::OnKeyEventConsumeResult(bool isConsumed, sptr<KeyEventConsumerProxy> consumer)
{
    IMSA_HILOGI("result: %{public}d.", isConsumed);
    keyEventConsume_ = true;
    keyEventResult_ = isConsumed;
    if (keyCodeConsume_) {
        consumer->OnKeyEventResult(keyCodeResult_ || keyEventResult_);
        keyEventConsume_ = false;
        keyEventResult_ = false;
    }
}

bool KeyboardDelegateImpl::OnKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent,
    sptr<KeyEventConsumerProxy> &consumer)
{
    std::string type = "keyEvent";
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<bool(KeyEvent_t const&)>>(cb->callback);
        bool isConsumed = func(CommonConvert::ToTaiheKeyEvent(keyEvent));
        if (consumer != nullptr) {
            IMSA_HILOGE("consumer result: %{public}d!", isConsumed);
            OnKeyEventConsumeResult(isConsumed, consumer);
        }
    }
    return true;
}

void KeyboardDelegateImpl::OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height)
{
    std::string type = "cursorContextChange";
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(int32_t, int32_t, int32_t)>>(cb->callback);
        func(positionX, positionY, height);
    }
}

void KeyboardDelegateImpl::OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd)
{
    std::string type = "selectionChange";
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(int32_t, int32_t, int32_t, int32_t)>>(cb->callback);
        func(oldBegin, oldEnd, newBegin, newEnd);
    }
}

void KeyboardDelegateImpl::OnTextChange(const std::string &text)
{
    std::string type = "textChange";
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(taihe::string_view)>>(cb->callback);
        func(taihe::string_view(text));
    }
}

void KeyboardDelegateImpl::OnEditorAttributeChange(const InputAttribute &inputAttribute)
{
    std::string type = "editorAttributeChanged";
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(EditorAttribute_t const&)>>(cb->callback);
        func(CommonConvert::NativeAttributeToAni(inputAttribute));
    }
}

bool KeyboardDelegateImpl::OnDealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId,
    const sptr<IRemoteObject> &channelObject)
{
    if (keyEvent == nullptr || channelObject == nullptr) {
        IMSA_HILOGE("keyEvent or channelObjectis nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbEventVec = jsCbMap_["keyEvent"];
    for (auto &cb : cbEventVec) {
        auto &func = std::get<taihe::callback<bool(KeyEvent_t const&)>>(cb->callback);
        bool isKeyEventConsumed = func(CommonConvert::ToTaiheKeyEvent(keyEvent));
        if (!isKeyEventConsumed) {
            if (keyEvent != nullptr && keyEvent->GetKeyAction() == MMI::KeyEvent::KEY_ACTION_DOWN) {
                IMSA_HILOGW("keyEvent is not consumed by ime");
            }
            isKeyEventConsumed = InputMethodAbility::GetInstance().HandleUnconsumedKey(keyEvent);
        }
        IMSA_HILOGD("final consumed result: %{public}d.", isKeyEventConsumed);
        auto ret = InputMethodAbility::GetInstance().HandleKeyEventResult(cbId, isKeyEventConsumed, channelObject);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("handle keyEvent failed:%{public}d", ret);
        }
    }
    std::string type = (keyEvent->GetKeyAction() == ARGC_TWO ? "keyDown" : "keyUp");
    auto &cbCodeVec = jsCbMap_[type];
    for (auto &cb : cbCodeVec) {
        auto &func = std::get<taihe::callback<bool(KeyEventType_t const&)>>(cb->callback);
        KeyEventType_t event {
            .keyCode = keyEvent->GetKeyCode(),
            .keyAction = keyEvent->GetKeyAction(),
        };
        bool isKeyCodeConsumed = false;
        isKeyCodeConsumed = func(event);
        if (!isKeyCodeConsumed) {
            if (keyEvent != nullptr && keyEvent->GetKeyAction() == MMI::KeyEvent::KEY_ACTION_DOWN) {
                IMSA_HILOGW("keyEvent is not consumed by ime");
            }
            isKeyCodeConsumed = InputMethodAbility::GetInstance().HandleUnconsumedKey(keyEvent);
        }
        IMSA_HILOGD("final consumed result: %{public}d.", isKeyCodeConsumed);
        auto ret = InputMethodAbility::GetInstance().HandleKeyEventResult(cbId, isKeyCodeConsumed, channelObject);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("handle keyEvent failed:%{public}d", ret);
        }
    }
    return true;
}
} // namespace MiscServices
} // namespace OHOS