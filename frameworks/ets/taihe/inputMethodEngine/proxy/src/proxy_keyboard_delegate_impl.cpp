/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "proxy_keyboard_delegate_impl.h"

namespace OHOS {
namespace MiscServices {
std::mutex ProxyKeyboardDelegateImpl::keyboardMutex_;
std::mutex ProxyKeyboardDelegateImpl::handlerMutex_;
std::shared_ptr<ProxyKeyboardDelegateImpl> ProxyKeyboardDelegateImpl::keyboardDelegate_ = nullptr;
std::shared_ptr<AppExecFwk::EventHandler> ProxyKeyboardDelegateImpl::handler_ = nullptr;

std::shared_ptr<ProxyKeyboardDelegateImpl> ProxyKeyboardDelegateImpl::GetInstance()
{
    if (keyboardDelegate_ == nullptr) {
        std::lock_guard<std::mutex> lock(keyboardMutex_);
        if (keyboardDelegate_ == nullptr) {
            keyboardDelegate_ = std::make_shared<ProxyKeyboardDelegateImpl>();
        }
    }
    return keyboardDelegate_;
}

std::shared_ptr<AppExecFwk::EventHandler> ProxyKeyboardDelegateImpl::GetHandler()
{
    std::lock_guard<std::mutex> lock(handlerMutex_);
    if (handler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::GetMainEventRunner();
        if (runner != nullptr) {
            handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
        }
    }
    if (handler_ == nullptr) {
        IMSA_HILOGE("handler_ is nullptr");
        return nullptr;
    }
    return handler_;
}

void ProxyKeyboardDelegateImpl::OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height)
{
    IMSA_HILOGD("OnCursorUpdate x: %{public}d, y: %{public}d, height: %{public}d", positionX, positionY, height);
    auto callbacks = GetCallbacks("cursorContextChange");
    if (callbacks.empty()) {
        return;
    }
    for (auto &item : callbacks) {
        if (item) {
            std::get<taihe::callback<void(double, double, double)>>(item->callback)(
                static_cast<double>(positionX), static_cast<double>(positionY), static_cast<double>(height));
        }
    }
}

void ProxyKeyboardDelegateImpl::OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd)
{
    IMSA_HILOGD("OnSelectionChange oldBegin: %{public}d, oldEnd: %{public}d, newBegin: %{public}d, newEnd: %{public}d",
        oldBegin, oldEnd, newBegin, newEnd);
    auto callbacks = GetCallbacks("selectionChange");
    if (callbacks.empty()) {
        return;
    }
    for (auto &item : callbacks) {
        if (item) {
            std::get<taihe::callback<void(int32_t, int32_t, int32_t, int32_t)>>(item->callback)(
                oldBegin, oldEnd, newBegin, newEnd);
        }
    }
}

void ProxyKeyboardDelegateImpl::OnTextChange(const std::string &text)
{
    IMSA_HILOGD("run in.");
    auto callbacks = GetCallbacks("textChange");
    if (callbacks.empty()) {
        return;
    }
    for (auto &item : callbacks) {
        if (item) {
            std::get<taihe::callback<void(taihe::string_view)>>(item->callback)(taihe::string_view(text));
        }
    }
}

void ProxyKeyboardDelegateImpl::OnEditorAttributeChange(const InputAttribute &inputAttribute)
{
    IMSA_HILOGD("OnEditorAttributeChange inputPattern: %{public}d", inputAttribute.inputPattern);
    auto callbacks = GetCallbacks("editorAttributeChanged");
    if (callbacks.empty()) {
        return;
    }
    auto attr = CommonConvert::NativeAttributeToAni(inputAttribute);
    for (auto &item : callbacks) {
        if (item) {
            std::get<taihe::callback<void(EditorAttribute_t const &)>>(item->callback)(attr);
        }
    }
}

bool ProxyKeyboardDelegateImpl::OnDealKeyEvent(
    const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId, const sptr<IRemoteObject> &channelObject)
{
    if (keyEvent == nullptr || channelObject == nullptr) {
        IMSA_HILOGE("keyEvent or channelObject is nullptr");
        return false;
    }
    auto eventCallbacks = GetCallbacks("keyEvent");
    if (eventCallbacks.empty()) {
        IMSA_HILOGW("key event callback is not registered.");
        return false;
    }
    IMSA_HILOGD("run in.");
    auto task = [eventCallbacks = std::move(eventCallbacks), keyEvent, cbId, channelObject]() {
        DealKeyEvent(std::move(eventCallbacks), keyEvent, cbId, channelObject);
    };
    auto handler = GetHandler();
    if (handler == nullptr) {
        return false;
    }
    handler->PostTask(task, "OnDealKeyEvent", 0, AppExecFwk::EventQueue::Priority::VIP);
    return true;
}

void ProxyKeyboardDelegateImpl::DealKeyEvent(std::vector<std::shared_ptr<CallbackObjects>> eventCallbacks,
    const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId, const sptr<IRemoteObject> &channelObject)
{
    if (keyEvent == nullptr) {
        IMSA_HILOGW("keyEvent is nullptr");
        return;
    }
    bool consumeResult = false;
    for (auto &item : eventCallbacks) {
        if (item != nullptr) {
            consumeResult = std::get<taihe::callback<bool(KeyEvent_t const &)>>(item->callback)(
                CommonConvert::ToTaiheKeyEvent(keyEvent));
            break;
        }
    }
    if (!consumeResult) {
        if (keyEvent->GetKeyAction() == MMI::KeyEvent::KEY_ACTION_DOWN) {
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
