/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "ets_keyboard_panel_manager.h"

#include "global.h"
#include "js_utils.h"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace MiscServices {
std::mutex EtsKeyboardPanelManager::managerMutex_;
sptr<EtsKeyboardPanelManager> EtsKeyboardPanelManager::keyboardPanelManager_ { nullptr };

sptr<EtsKeyboardPanelManager> EtsKeyboardPanelManager::GetInstance()
{
    if (keyboardPanelManager_ == nullptr) {
        std::lock_guard<std::mutex> lock(managerMutex_);
        if (keyboardPanelManager_ == nullptr) {
            keyboardPanelManager_ = new (std::nothrow) EtsKeyboardPanelManager();
        }
    }
    return keyboardPanelManager_;
}

EtsKeyboardPanelManager::~EtsKeyboardPanelManager()
{
    std::lock_guard<std::recursive_mutex> lock(etsCbsLock_);
    etsCbMap_.clear();
}

void EtsKeyboardPanelManager::RegisterListener(const std::string &type, CallbackTypes&& callback)
{
    IMSA_HILOGD("event type: %{public}s.", type.c_str());
    auto channel = ImeSystemCmdChannel::GetInstance();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr.");
        return;
    }

    if (!(channel->IsSystemApp())) {
        IMSA_HILOGE("not system app, type: %{public}s.", type.c_str());
        taihe::set_business_error(EXCEPTION_SYSTEM_PERMISSION, JsUtils::ToMessage(EXCEPTION_SYSTEM_PERMISSION));
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(etsCbsLock_);
    auto &cbVec = etsCbMap_[type];
    auto it = std::find_if(cbVec.begin(), cbVec.end(), [&callback](const auto &existingCb) {
        return callback == existingCb;
    });
    if (it == cbVec.end()) {
        cbVec.emplace_back(callback);
        IMSA_HILOGI("%{public}s callback registered success", type.c_str());
    } else {
        IMSA_HILOGI("%{public}s is already registered", type.c_str());
    }
}

void EtsKeyboardPanelManager::UnRegisterListener(const std::string &type, CallbackTypes &&cb)
{
    IMSA_HILOGD("event type: %{public}s.", type.c_str());
    auto channel = ImeSystemCmdChannel::GetInstance();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr.");
        return;
    }

    if (!(channel->IsSystemApp())) {
        IMSA_HILOGE("not system app, type: %{public}s.", type.c_str());
        taihe::set_business_error(EXCEPTION_SYSTEM_PERMISSION, JsUtils::ToMessage(EXCEPTION_SYSTEM_PERMISSION));
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(etsCbsLock_);
    const auto iter = etsCbMap_.find(type);
    if (iter == etsCbMap_.end()) {
        IMSA_HILOGE("%{public}s is not registered", type.c_str());
        return;
    }
    if (std::holds_alternative<std::nullptr_t>(cb)) {
        etsCbMap_.erase(iter);
        IMSA_HILOGI("unregistered all %{public}s callback", type.c_str());
        return;
    }
    auto &callbacks = iter->second;
    auto it = std::find_if(callbacks.begin(), callbacks.end(), [&cb](const auto &existingCb) {
        return cb == existingCb;
    });
    if (it != callbacks.end()) {
        IMSA_HILOGI("unregistered callback success");
        callbacks.erase(it);
    }
    if (callbacks.empty()) {
        etsCbMap_.erase(iter);
        IMSA_HILOGI("callback is empty");
    }
}

void EtsKeyboardPanelManager::ReceivePrivateCommand(
    const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    IMSA_HILOGD("start.");
    std::vector<CallbackTypes> cbVec;
    {
        std::lock_guard<std::recursive_mutex> lock(etsCbsLock_);
        cbVec = etsCbMap_[PANEL_PRIVATE_COMMAND_CB_EVENT_TYPE];
    }
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(::taihe::map_view<::taihe::string, CommandDataType_t>)>>(cb);
        taihe::map<::taihe::string, CommandDataType_t> commandMap(privateCommand.size());
        for (const auto &[key, value] : privateCommand) {
            CommandDataType_t data = ConvertToDataType(value);
            commandMap.emplace(key, data);
        }
        func(commandMap);
    }
}

void EtsKeyboardPanelManager::NotifyPanelStatus(const SysPanelStatus &sysPanelStatus)
{
    IMSA_HILOGD("start.");
    std::vector<CallbackTypes> cbVec;
    {
        std::lock_guard<std::recursive_mutex> lock(etsCbsLock_);
        cbVec = etsCbMap_[PANEL_STATUS_CHANGE_CB_EVENT_TYPE];
    }
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(SystemPanelStatus_t const &)>>(cb);
        SystemPanelStatus_t status {
            .inputType = ConvertInputType(sysPanelStatus.inputType),
            .panelFlag = ConvertPanelFlag(sysPanelStatus.flag),
            .isPanelRaised = sysPanelStatus.isPanelRaised,
            .needFuncButton = sysPanelStatus.needFuncButton,
        };
        func(status);
    }
}

CommandDataType_t EtsKeyboardPanelManager::ConvertToDataType(const PrivateDataValue &value)
{
    size_t idx = value.index();
    if (idx == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_STRING)) {
        auto stringValue = std::get_if<std::string>(&value);
        if (stringValue != nullptr) {
            return CommandDataType_t::make_type_String(*stringValue);
        }
    } else if (idx == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_BOOL)) {
        auto boolValue = std::get_if<bool>(&value);
        if (boolValue != nullptr) {
            return CommandDataType_t::make_type_Bool(*boolValue);
        }
    } else if (idx == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_NUMBER)) {
        auto numberValue = std::get_if<int32_t>(&value);
        if (numberValue != nullptr) {
            return CommandDataType_t::make_type_Int(*numberValue);
        }
    }
    IMSA_HILOGW("ConvertToDataType: unknown type index %{public}zu, returning default bool(true)", idx);
    return CommandDataType_t::make_type_Bool(true);
}

InputMethodInputType_t EtsKeyboardPanelManager::ConvertInputType(InputType type)
{
    switch (type) {
        case InputType::NONE:
            return InputMethodInputType_t::key_t::NONE;
        case InputType::CAMERA_INPUT:
            return InputMethodInputType_t::key_t::CAMERA_INPUT;
        case InputType::SECURITY_INPUT:
            return InputMethodInputType_t::key_t::SECURITY_INPUT;
        case InputType::VOICE_INPUT:
            return InputMethodInputType_t::key_t::VOICE_INPUT;
        case InputType::VOICEKB_INPUT:
            return InputMethodInputType_t::key_t::FLOATING_VOICE_INPUT;
        default:
            IMSA_HILOGW("ConvertInputType: unknown input type %{public}d, returning NONE", static_cast<int32_t>(type));
            return InputMethodInputType_t::key_t::NONE;
    }
}

PanelFlag_t EtsKeyboardPanelManager::ConvertPanelFlag(int32_t flag)
{
    switch (flag) {
        case PanelFlag::FLG_FIXED:
            return PanelFlag_t::key_t::FLAG_FIXED;
        case PanelFlag::FLG_FLOATING:
            return PanelFlag_t::key_t::FLAG_FLOATING;
        case PanelFlag::FLG_CANDIDATE_COLUMN:
            return PanelFlag_t::key_t::FLAG_CANDIDATE;
        default:
            IMSA_HILOGW("ConvertPanelFlag: unknown panel flag %{public}d, returning FLAG_FIXED", flag);
            return PanelFlag_t::key_t::FLAG_FIXED;
    }
}
} // namespace MiscServices
} // namespace OHOS
