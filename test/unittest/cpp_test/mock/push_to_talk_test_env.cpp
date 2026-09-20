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

#include "push_to_talk_test_env.h"

#include <new>

#include "../../../../services/adapter/os_account_adapter/include/os_account_adapter.h"
#include "../../../../services/include/ime_info_inquirer.h"
#include "ability_manager_client.h"
#include "input_type_manager.h"
#include "os_account_manager.h"
#include "peruser_session.h"
#include "settings_data_utils.h"

namespace OHOS {
namespace MiscServices {
PttTestState &GetPttTestState()
{
    static PttTestState state;
    return state;
}

PttDialogTestState &GetPttDialogTestState()
{
    static PttDialogTestState state;
    return state;
}

int32_t SettingsDataUtils::GetStringValue(const std::string &, const std::string &key, std::string &value)
{
    if (key != "settings.keyboard.push_talk_switch") {
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto &state = GetPttTestState();
    value = state.settingValue;
    return state.settingResult;
}

bool SettingsDataUtils::GetPushToTalkDialogPopped()
{
    ++GetPttDialogTestState().reads;
    return false;
}

void SettingsDataUtils::SetPushToTalkDialogPopped()
{
    ++GetPttDialogTestState().writes;
}

bool OsAccountAdapter::IsOsAccountForeground(int32_t userId)
{
    auto &state = GetPttTestState();
    return state.isForeground && userId == state.foregroundUserId;
}

int32_t PerUserSession::NotifyRollbackSpace()
{
    auto &state = GetPttTestState();
    state.calls.emplace_back("rollback");
    state.sessionUserIds.emplace_back(userId_);
    return state.rollbackResult;
}

int32_t PerUserSession::NotifyPttGestureCancelled()
{
    auto &state = GetPttTestState();
    state.calls.emplace_back("cancel");
    state.sessionUserIds.emplace_back(userId_);
    return state.cancelResult;
}

int32_t PerUserSession::SendPttStopPrivateCommand()
{
    auto &state = GetPttTestState();
    state.calls.emplace_back("stop");
    state.sessionUserIds.emplace_back(userId_);
    return state.stopResult;
}

int32_t PerUserSession::StartCurrentIme(bool, StartReason)
{
    auto &state = GetPttTestState();
    state.calls.emplace_back("restore");
    state.sessionUserIds.emplace_back(userId_);
    state.inputTypeStartedOnRestore = InputTypeManager::GetInstance().IsStarted();
    return state.restoreResult;
}

std::shared_ptr<Property> ImeInfoInquirer::GetCurrentInputMethod(int32_t userId)
{
    auto &state = GetPttTestState();
    ++state.currentImeQueries;
    state.dialogUserId = userId;
    return state.currentIme;
}

std::vector<std::string> ImeInfoInquirer::GetRunningIme(int32_t)
{
    return {};
}

bool ImeInfoInquirer::IsSysIme(const std::string &bundleName)
{
    auto &state = GetPttTestState();
    return state.isSystemIme && state.currentIme != nullptr && bundleName == state.currentIme->name;
}

sptr<AAFwk::IAbilityConnection> CreatePushToTalkDialogConnection(
    const std::string &dialogBundleName, const std::string &dialogAbilityName, const std::string &paramStr)
{
    if (GetPttTestState().failConnectionCreation) {
        return nullptr;
    }
    sptr<AAFwk::IAbilityConnection> connection { new (std::nothrow)
            PushToTalkConnection(dialogBundleName, dialogAbilityName, paramStr) };
    return connection;
}
} // namespace MiscServices

namespace AccountSA {
ErrCode OsAccountManager::GetForegroundOsAccountLocalId(int32_t &localId)
{
    auto &state = MiscServices::GetPttTestState();
    ++state.foregroundQueries;
    localId = state.foregroundUserId;
    return state.foregroundResult;
}
} // namespace AccountSA

namespace AAFwk {
ErrCode AbilityManagerClient::ConnectAbility(const Want &want, sptr<IAbilityConnection> connect, int32_t userId)
{
    auto &state = MiscServices::GetPttDialogTestState();
    ++state.connections;
    state.connectionUserId = userId;
    state.bundleName = want.GetElement().GetBundleName();
    state.abilityName = want.GetElement().GetAbilityName();
    state.connection = connect;
    return ERR_OK;
}
} // namespace AAFwk
} // namespace OHOS
