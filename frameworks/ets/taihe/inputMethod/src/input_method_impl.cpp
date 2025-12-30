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
std::unordered_map<std::string,
    std::vector<taihe::callback<void(AttachFailureReason_t data)>>> InputMethodImpl::jsCbMap_;
constexpr const char *ATTACH_FAIL_CB_EVENT_TYPE = "attachmentDidFail";
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

void InputMethodImpl::RegisterListener(std::string const &type,
    taihe::callback_view<void(AttachFailureReason_t data)> callback)
{
    IMSA_HILOGD("event type: %{public}s.", type.c_str());
    SetImcInnerListener();
    {
        std::lock_guard<std::mutex> lock(jsCbsLock_);
        auto &cbVec = jsCbMap_[type];
        auto it = std::find_if(cbVec.begin(), cbVec.end(),
            [&callback](const auto &existingCb) {
            return callback == existingCb;
        });
        if (it == cbVec.end()) {
            cbVec.emplace_back(callback);
            IMSA_HILOGD("callback registered success");
        } else {
            IMSA_HILOGD("add %{public}s callback succeed.", type.c_str());
        }
    }
}

void InputMethodImpl::UnRegisterListener(std::string const &type,
    taihe::optional_view<taihe::callback<void(AttachFailureReason_t data)>> callback)
{
    IMSA_HILOGD("event type: %{public}s.", type.c_str());
    std::lock_guard<std::mutex> lock(jsCbsLock_);
    const auto iter = jsCbMap_.find(type);
    if (iter == jsCbMap_.end()) {
        IMSA_HILOGE("%{public}s is not registered", type.c_str());
        return;
    }
    if (!callback.has_value()) {
        jsCbMap_.erase(iter);
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
        jsCbMap_.erase(iter);
        IMSA_HILOGD("callback is empty");
    }
}

void InputMethodImpl::OnAttachmentDidFail(AttachFailureReason reason)
{
    IMSA_HILOGD("reason: %{public}d.", reason);
    std::lock_guard<std::mutex> lock(jsCbsLock_);
    auto &cbVec = jsCbMap_[ATTACH_FAIL_CB_EVENT_TYPE];
    for (auto &cb : cbVec) {
        AttachFailureReason_t tmpReason = EnumConvert::ConvertAttachFailureReason(reason);
        cb(tmpReason);
    }
}
} // namespace MiscServices
} // namespace OHOS