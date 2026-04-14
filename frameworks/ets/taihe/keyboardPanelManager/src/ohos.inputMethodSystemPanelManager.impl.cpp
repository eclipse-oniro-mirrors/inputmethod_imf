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
#include "ohos.inputMethodSystemPanelManager.impl.hpp"
#include "taihe/runtime.hpp"

#include "global.h"
#include "ets_keyboard_panel_manager.h"
#include "js_utils.h"

using namespace OHOS::MiscServices;

namespace {
// You can add using namespace statements here if needed.

void OnSystemPrivateCommand(::taihe::callback_view<void(
        ::taihe::map_view<::taihe::string, ::ohos::inputMethodSystemPanelManager::CommandDataType> data)>
        f)
{
    auto instance = EtsKeyboardPanelManager::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("instance is nullptr!");
        return;
    }

    instance->RegisterListener(PANEL_PRIVATE_COMMAND_CB_EVENT_TYPE, f);
}

void OffSystemPrivateCommand(::taihe::optional_view<::taihe::callback<void(
        ::taihe::map_view<::taihe::string, ::ohos::inputMethodSystemPanelManager::CommandDataType> data)>>
        f)
{
    auto instance = EtsKeyboardPanelManager::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("instance is nullptr!");
        return;
    }

    if (f.has_value()) {
        instance->UnRegisterListener(PANEL_PRIVATE_COMMAND_CB_EVENT_TYPE, f.value());
        return;
    }

    instance->UnRegisterListener(PANEL_PRIVATE_COMMAND_CB_EVENT_TYPE, nullptr);
}

void OnSystemPanelStatusChange(
    ::taihe::callback_view<void(::ohos::inputMethodSystemPanelManager::SystemPanelStatus const &status)> f)
{
    auto instance = EtsKeyboardPanelManager::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("instance is nullptr!");
        return;
    }
    instance->RegisterListener(PANEL_STATUS_CHANGE_CB_EVENT_TYPE, f);
}

void OffSystemPanelStatusChange(::taihe::optional_view<
    ::taihe::callback<void(::ohos::inputMethodSystemPanelManager::SystemPanelStatus const &status)>>
        f)
{
    auto instance = EtsKeyboardPanelManager::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("instance is nullptr!");
        return;
    }
    if (f.has_value()) {
        instance->UnRegisterListener(PANEL_STATUS_CHANGE_CB_EVENT_TYPE, f.value());
        return;
    }
    instance->UnRegisterListener(PANEL_STATUS_CHANGE_CB_EVENT_TYPE, nullptr);
}

static ValueMap Convert(taihe::map_view<taihe::string, CommandDataType_t> command)
{
    ValueMap valueMap;
    for (auto &[key, value] : command) {
        if (key.empty()) {
            IMSA_HILOGE("key is empty.");
            continue;
        }
        PrivateDataValue nativeValue;
        switch (value.get_tag()) {
            case CommandDataType_t::tag_t::type_Int:
                nativeValue = value.get_type_Int_ref();
                break;
            case CommandDataType_t::tag_t::type_String:
                nativeValue = std::string(value.get_type_String_ref());
                break;
            case CommandDataType_t::tag_t::type_Bool:
                nativeValue = value.get_type_Bool_ref();
                break;
            default:
                IMSA_HILOGE("invalid type.");
                break;
        }
        valueMap.insert(std::make_pair(std::string(key), nativeValue));
    }
    return valueMap;
}

void SendPrivateCommandSync(
    ::taihe::map_view<::taihe::string, ::ohos::inputMethodSystemPanelManager::CommandDataType> commandData)
{
    IMSA_HILOGD("start");
    auto channel = ImeSystemCmdChannel::GetInstance();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr.");
        return;
    }

    if (!(channel->IsSystemApp())) {
        IMSA_HILOGE("not system app, type");
        taihe::set_business_error(EXCEPTION_SYSTEM_PERMISSION, JsUtils::ToMessage(EXCEPTION_SYSTEM_PERMISSION));
        return;
    }

    auto nativeMap = Convert(commandData);
    // Validate user-provided commands BEFORE adding sys_cmd field
    // This ensures user commands comply with spec: max 5 commands, 32KB total size
    if (!ImeSystemCmdChannel::IsUserPrivateCommandValid(nativeMap)) {
        IMSA_HILOGE("privateCommand invalid.");
        taihe::set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, "commandData size limit 32KB, count limit 5.");
        return;
    }

    nativeMap["sys_cmd"] = 1;
    int32_t ret = channel->SendPrivateCommand(nativeMap);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SendPrivateCommand failed.");
        taihe::set_business_error(EXCEPTION_SYSTEM_PANEL_ERROR, JsUtils::ToMessage(EXCEPTION_SYSTEM_PANEL_ERROR));
        return;
    }
    IMSA_HILOGI("SendPrivateCommand success.");
}

void ConnectSystemChannelSync()
{
    IMSA_HILOGD("start");
    auto manager = EtsKeyboardPanelManager::GetInstance();
    if (manager == nullptr) {
        IMSA_HILOGE("manager is nullptr!");
        return;
    }
    auto channel = ImeSystemCmdChannel::GetInstance();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return;
    }
    auto ret = channel->ConnectSystemCmd(manager);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("ConnectSystemCmd failed, ret = %{public}d", ret);
        if (ret != ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION && ret != ErrorCode::ERROR_STATUS_PERMISSION_DENIED &&
            ret != ErrorCode::ERROR_SYSTEM_PANEL_ERROR) {
            ret = ErrorCode::ERROR_IMSA_NULLPTR;
        }
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
}
} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OnSystemPrivateCommand(OnSystemPrivateCommand);
TH_EXPORT_CPP_API_OffSystemPrivateCommand(OffSystemPrivateCommand);
TH_EXPORT_CPP_API_OnSystemPanelStatusChange(OnSystemPanelStatusChange);
TH_EXPORT_CPP_API_OffSystemPanelStatusChange(OffSystemPanelStatusChange);
TH_EXPORT_CPP_API_SendPrivateCommandSync(SendPrivateCommandSync);
TH_EXPORT_CPP_API_ConnectSystemChannelSync(ConnectSystemChannelSync);
// NOLINTEND
