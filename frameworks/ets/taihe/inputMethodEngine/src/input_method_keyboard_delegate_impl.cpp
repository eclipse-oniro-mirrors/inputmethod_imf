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
std::mutex KeyboardDelegateImpl::mutex_;
std::mutex KeyboardDelegateImpl::handlerMutex_;
std::mutex KeyboardDelegateImpl::keyboardMutex_;
std::map<std::string, std::vector<std::unique_ptr<CallbackObjects>>> KeyboardDelegateImpl::jsCbMap_;
std::map<std::string, std::vector<taihe::callback<bool(KeyEvent_t const& event)>>> KeyboardDelegateImpl::eventCbMap_;
std::shared_ptr<AppExecFwk::EventHandler> KeyboardDelegateImpl::handler_{ nullptr };
std::shared_ptr<KeyboardDelegateImpl> KeyboardDelegateImpl::keyboardDelegate_{ nullptr };
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

void KeyboardDelegateImpl::RegisterListenerEvent(std::string const &type,
    taihe::callback_view<bool(KeyEvent_t const& event)> callback)
{
    if (type != "keyEvent") {
        IMSA_HILOGE("subscribe failed, type: %{public}s.", type.c_str());
        return;
    }
    {
        std::lock_guard<std::mutex> lock(handlerMutex_);
        if (handler_ == nullptr) {
            auto runner = AppExecFwk::EventRunner::GetMainEventRunner();
            if (!runner) {
                IMSA_HILOGW("null EventRunner");
            } else {
                handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
            }
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = eventCbMap_[type];
    auto it = std::find_if(cbVec.begin(), cbVec.end(),
        [&callback](const auto &existingCb) {
        return callback == existingCb;
    });
    if (it == cbVec.end()) {
        cbVec.emplace_back(callback);
        IMSA_HILOGD("callback registered success");
    } else {
        IMSA_HILOGD("%{public}s is already registered", type.c_str());
    }
}

void KeyboardDelegateImpl::UnRegisterListenerEvent(std::string const &type,
    taihe::optional_view<taihe::callback<bool(KeyEvent_t const& event)>> callback)
{
    if (type != "keyEvent") {
        IMSA_HILOGE("subscribe failed, type: %{public}s.", type.c_str());
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const auto iter = eventCbMap_.find(type);
    if (iter == eventCbMap_.end()) {
        IMSA_HILOGE("%{public}s is not registered", type.c_str());
        return;
    }
    if (!callback.has_value()) {
        eventCbMap_.erase(iter);
        IMSA_HILOGD("unregistered all %{public}s callback", type.c_str());
        return;
    }
    auto &callbacks = iter->second;
    auto onceCallback = callback.value();
    auto it = std::find_if(callbacks.begin(), callbacks.end(),
        [&onceCallback](const auto &existingCb) {
        return onceCallback == existingCb;
    });
    if (it != callbacks.end()) {
        IMSA_HILOGD("unregistered callback success");
        callbacks.erase(it);
    }
    if (callbacks.empty()) {
        eventCbMap_.erase(iter);
        IMSA_HILOGD("callback is empty");
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

bool KeyboardDelegateImpl::isRegistered(const std::string &type)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (eventCbMap_["keyEvent"].empty() && jsCbMap_[type].empty()) {
            IMSA_HILOGW("callback is not registered.");
            return false;
        }
    }
    return true;
}

bool KeyboardDelegateImpl::OnDealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId,
    const sptr<IRemoteObject> &channelObject)
{
    if (keyEvent == nullptr || channelObject == nullptr) {
        IMSA_HILOGE("keyEvent or channelObjectis nullptr");
        return false;
    }
    std::string type = (keyEvent->GetKeyAction() == ARGC_TWO ? "keyDown" : "keyUp");
    if (!isRegistered(type)) {
        IMSA_HILOGW("key event callback is not registered.");
        return false;
    }
    IMSA_HILOGD("run in.");
    auto task = [keyEvent, cbId, type, channelObject]() {
        DealKeyEvent(keyEvent, cbId, type, channelObject);
    };
    std::lock_guard<std::mutex> lock(handlerMutex_);
    if (handler_ == nullptr) {
        IMSA_HILOGE("handler_ is nullptr");
        return false;
    }
    handler_->PostTask(task, "OnDealKeyEvent", 0, AppExecFwk::EventQueue::Priority::VIP);
    return true;
}

void KeyboardDelegateImpl::DealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent,
    uint64_t cbId, const std::string &type, const sptr<IRemoteObject> &channelObject)
{
    bool isKeyEventConsumed = false;
    bool isKeyCodeConsumed = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &cbEventVec = eventCbMap_["keyEvent"];
        for (auto &cb : cbEventVec) {
            isKeyEventConsumed = cb(CommonConvert::ToTaiheKeyEvent(keyEvent));
            break;
        }
        auto &cbCodeVec = jsCbMap_[type];
        for (auto &cb : cbCodeVec) {
            auto &func = std::get<taihe::callback<bool(KeyEventType_t const&)>>(cb->callback);
            KeyEventType_t event {
                .keyCode = keyEvent->GetKeyCode(),
                .keyAction = keyEvent->GetKeyAction(),
            };
            isKeyCodeConsumed = func(event);
            break;
        }
    }
    bool consumeResult = isKeyEventConsumed || isKeyCodeConsumed;
    if (!consumeResult) {
        if (keyEvent != nullptr && keyEvent->GetKeyAction() == MMI::KeyEvent::KEY_ACTION_DOWN) {
            IMSA_HILOGW("keyEvent is not consumed by ime");
        }
        consumeResult = InputMethodAbility::GetInstance().HandleUnconsumedKey(keyEvent);
    }
    auto ret = InputMethodAbility::GetInstance().HandleKeyEventResult(cbId, consumeResult, channelObject);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("handle keyEvent failed:%{public}d", ret);
    }
}
} // namespace MiscServices
} // namespace OHOS