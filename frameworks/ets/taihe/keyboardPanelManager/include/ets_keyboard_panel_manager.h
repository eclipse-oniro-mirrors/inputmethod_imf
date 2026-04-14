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
#ifndef ETS_KEYBOARD_PANEL_MANAGER_H
#define ETS_KEYBOARD_PANEL_MANAGER_H

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>

#include "nocopyable.h"
#include "ime_system_channel.h"
#include "ohos.inputMethodSystemPanelManager.impl.hpp"

namespace OHOS {
namespace MiscServices {
constexpr const char *PANEL_PRIVATE_COMMAND_CB_EVENT_TYPE = "systemPrivateCommand";
constexpr const char *PANEL_STATUS_CHANGE_CB_EVENT_TYPE = "systemPanelStatusChange";
using CommandDataType_t = ::ohos::inputMethodSystemPanelManager::CommandDataType;
using SystemPanelStatus_t = ::ohos::inputMethodSystemPanelManager::SystemPanelStatus;
using InputMethodInputType_t = ::ohos::inputMethodSystemPanelManager::InputMethodInputType;
using PanelFlag_t = ::ohos::inputMethod::Panel::PanelFlag;
using CallbackTypes = std::variant<
    std::nullptr_t, ::taihe::callback<void(::taihe::map_view<::taihe::string, CommandDataType_t>)>,
    ::taihe::callback<void(SystemPanelStatus_t const &)>>;
class EtsKeyboardPanelManager : public OnSystemCmdListener {
public:
    ~EtsKeyboardPanelManager();
    static sptr<EtsKeyboardPanelManager> GetInstance();

    void RegisterListener(const std::string &type, CallbackTypes &&callback);
    void UnRegisterListener(const std::string &type, CallbackTypes &&callback);

    void ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) override;
    void NotifyPanelStatus(const SysPanelStatus &sysPanelStatus) override;

private:
    DISALLOW_COPY_AND_MOVE(EtsKeyboardPanelManager);
    EtsKeyboardPanelManager() = default;
    static CommandDataType_t ConvertToDataType(const PrivateDataValue &value);
    static InputMethodInputType_t ConvertInputType(InputType type);
    static PanelFlag_t ConvertPanelFlag(int32_t flag);

    static std::mutex managerMutex_;
    static sptr<EtsKeyboardPanelManager> keyboardPanelManager_;
    std::recursive_mutex etsCbsLock_;
    std::unordered_map<std::string, std::vector<CallbackTypes>> etsCbMap_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // ETS_KEYBOARD_PANEL_MANAGER_H
