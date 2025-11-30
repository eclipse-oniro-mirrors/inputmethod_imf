/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


#include "input_method_panel_listener.h"

namespace OHOS {
namespace MiscServices {
std::mutex InputMethodPanelListener::listenerMutex_;
std::shared_ptr<InputMethodPanelListener> InputMethodPanelListener::instance_{ nullptr };

std::shared_ptr<InputMethodPanelListener> InputMethodPanelListener::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(listenerMutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<InputMethodPanelListener>();
        }
    }
    return instance_;
}

InputMethodPanelListener::~InputMethodPanelListener() {}

void InputMethodPanelListener::Subscribe(uint32_t windowId, const std::string &type, callbackTypes &&cb, uintptr_t opq)
{
    std::lock_guard<std::mutex> lock(mutex_);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        IMSA_HILOGE("ani_env is nullptr or GlobalReference_Create failed, type: %{public}s!", type.c_str());
        return;
    }
    auto subscriptionAction = [&type, &env, &callbackRef, &cb](uint32_t windowId,
        std::map<std::string, std::unique_ptr<CallbackObjects>> &cbs) -> bool {
        if (cbs.find(type) != cbs.end()) {
            env->GlobalReference_Delete(callbackRef);
            IMSA_HILOGI("callback already registered, type: %{public}s!", type.c_str());
            return true;
        }
        auto result = cbs.try_emplace(type, std::make_unique<CallbackObjects>(cb, callbackRef));
        bool inserted = result.second;

        if (inserted) {
            IMSA_HILOGI("start to subscribe type: %{public}s of windowId: %{public}u.", type.c_str(), windowId);
        } else {
            IMSA_HILOGD("type: %{public}s of windowId: %{public}u already subscribed.", type.c_str(), windowId);
        }
        return !cbs.empty();
    };
    jsCbMap_.Compute(windowId, subscriptionAction);
}

void InputMethodPanelListener::RemoveInfo(uint32_t windowId, const std::string &type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    jsCbMap_.ComputeIfPresent(windowId,
        [&type](auto windowId, std::map<std::string, std::unique_ptr<CallbackObjects>> &cbs) {
            cbs.erase(type);
            return !cbs.empty();
        });
}

std::unique_ptr<CallbackObjects> InputMethodPanelListener::GetCallback(uint32_t windowId, const std::string &type)
{
    std::unique_ptr<CallbackObjects> callBack = nullptr;
    jsCbMap_.ComputeIfPresent(windowId,
        [&type, &callBack](auto windowId, std::map<std::string, std::unique_ptr<CallbackObjects>> &cbs) {
        auto it = cbs.find(type);
        if (it == cbs.end()) {
            return !cbs.empty();
        }
        callBack = std::move(it->second);
        return !cbs.empty();
    });
    return callBack;
}

void InputMethodPanelListener::OnPanelStatus(uint32_t windowId, bool isShow)
{
    std::string type = isShow ? "show" : "hide";
    std::lock_guard<std::mutex> lock(mutex_);
    auto cbVec = GetCallback(windowId, type);
    if (cbVec == nullptr) {
        IMSA_HILOGE("callBack is nullptr!");
        return;
    }
    auto &func = std::get<taihe::callback<void()>>(cbVec->callback);
    func();
}

void InputMethodPanelListener::OnSizeChange(uint32_t windowId, const WindowSize &size)
{
    std::string type = "sizeChange";
    std::lock_guard<std::mutex> lock(mutex_);
    auto cbVec = GetCallback(windowId, type);
    if (cbVec == nullptr) {
        IMSA_HILOGE("callBack is nullptr!");
        return;
    }
    auto &func = std::get<taihe::callback<void(uintptr_t, taihe::optional_view<KeyboardArea_t>)>>(cbVec->callback);
    ani_env* env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr");
        return;
    }
    ani_object obj = CommonConvert::CreateAniSize(env, size.width, size.height);
    if (obj == nullptr) {
        IMSA_HILOGE("create Ani size failed");
        return;
    }
    uintptr_t windowSize = reinterpret_cast<uintptr_t>(obj);
    func(windowSize, taihe::optional<KeyboardArea_t>(std::nullopt));
}

void InputMethodPanelListener::OnSizeChange(uint32_t windowId, const WindowSize &size,
    const PanelAdjustInfo &keyboardArea, const std::string &event)
{
    std::string type = "sizeUpdate";
    std::lock_guard<std::mutex> lock(mutex_);
    auto cbVec = GetCallback(windowId, type);
    if (cbVec == nullptr) {
        IMSA_HILOGE("callBack is nullptr!");
        return;
    }
    auto &func = std::get<taihe::callback<void(uintptr_t, KeyboardArea_t const&)>>(cbVec->callback);
    ani_env* env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr");
        return;
    }
    ani_object obj = CommonConvert::CreateAniSize(env, size.width, size.height);
    if (obj == nullptr) {
        IMSA_HILOGE("create Ani size failed");
        return;
    }
    uintptr_t windowSize = reinterpret_cast<uintptr_t>(obj);
    KeyboardArea_t area {
        .top = keyboardArea.top,
        .bottom = keyboardArea.bottom,
        .left = keyboardArea.left,
        .right = keyboardArea.right
    };
    func(windowSize, area);
}

void InputMethodPanelListener::SetEventHandler(std::shared_ptr<AppExecFwk::EventHandler> handler)
{
    std::unique_lock<decltype(eventHandlerMutex_)> lock(eventHandlerMutex_);
    handler_ = handler;
}
} // namespace MiscServices
} // namespace OHOS