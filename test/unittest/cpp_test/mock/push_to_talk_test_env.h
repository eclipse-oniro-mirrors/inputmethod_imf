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

#ifndef INPUTMETHOD_IMF_PUSH_TO_TALK_TEST_ENV_H
#define INPUTMETHOD_IMF_PUSH_TO_TALK_TEST_ENV_H

#include <memory>
#include <string>
#include <vector>

#include "global.h"
#include "input_client_stub.h"
#include "input_method_utils.h"
#include "input_status_info.h"
#include "input_window_info.h"
#include "push_to_talk_connection.h"

namespace OHOS {
namespace MiscServices {
constexpr int32_t PTT_UNIT_TEST_USER_ID = 8701;
constexpr int32_t PTT_UNIT_MISSING_USER_ID = 8702;

// Linked only into PushToTalkManagerUnitTest. The manager and controller remain real.
struct PttTestState {
    std::string settingValue { "true" };
    int32_t settingResult { ErrorCode::NO_ERROR };
    int32_t foregroundUserId { PTT_UNIT_TEST_USER_ID };
    int32_t foregroundResult { ERR_OK };
    int32_t foregroundQueries { 0 };
    bool isForeground { true };
    int32_t blockResult { ErrorCode::NO_ERROR };
    int32_t rollbackResult { ErrorCode::NO_ERROR };
    int32_t startResult { ErrorCode::NO_ERROR };
    int32_t cancelResult { ErrorCode::NO_ERROR };
    int32_t stopResult { ErrorCode::NO_ERROR };
    int32_t restoreResult { ErrorCode::NO_ERROR };
    int32_t startedUserId { -1 };
    bool inputTypeStartedOnRestore { true };
    std::vector<std::string> calls;
    std::vector<int32_t> sessionUserIds;
    std::shared_ptr<Property> currentIme;
    bool isSystemIme { true };
    int32_t currentImeQueries { 0 };
    int32_t dialogUserId { -1 };
    bool failConnectionCreation { false };
};

// The production dialog flag is process-wide; retain these observations across repeated tests too.
struct PttDialogTestState {
    int32_t reads { 0 };
    int32_t writes { 0 };
    int32_t connections { 0 };
    int32_t connectionUserId { 0 };
    std::string bundleName;
    std::string abilityName;
    sptr<AAFwk::IAbilityConnection> connection;
};

PttTestState &GetPttTestState();
PttDialogTestState &GetPttDialogTestState();

class PttTestClient final : public InputClientStub {
public:
    ErrCode OnInputReady(const sptr<IRemoteObject> &, const BindImeInfo &) override
    {
        return ERR_OK;
    }

    ErrCode OnInputStop(bool, const sptr<IRemoteObject> &, bool, bool) override
    {
        return ERR_OK;
    }

    ErrCode OnInputStopAsync(bool, bool, bool) override
    {
        return ERR_OK;
    }

    ErrCode OnSwitchInput(const Property &, const SubProperty &, int32_t) override
    {
        return ERR_OK;
    }

    ErrCode OnPanelStatusChange(uint32_t, const ImeWindowInfo &) override
    {
        return ERR_OK;
    }

    ErrCode NotifyInputStart(const InputStartInfo &) override
    {
        return ERR_OK;
    }

    ErrCode NotifyInputStop(const InputStopInfo &) override
    {
        return ERR_OK;
    }

    ErrCode NotifySoftKeyBoardInfoChanged(int32_t, const BoundImeInfo &, const BoundImeInfo &) override
    {
        return ERR_OK;
    }

    ErrCode DeactivateClient() override
    {
        return ERR_OK;
    }

    ErrCode OnImeMirrorStop(const sptr<IRemoteObject> &) override
    {
        return ERR_OK;
    }

    ErrCode GetCurrentCursorInfo(CursorInfoInner &) override
    {
        return ERR_OK;
    }

    ErrCode OnExecTextInteraction(const std::string &) override
    {
        return ERR_OK;
    }

    ErrCode StartPttSpaceKeyEventBlock() override
    {
        auto &state = GetPttTestState();
        state.calls.emplace_back("block");
        return state.blockResult;
    }
};
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_IMF_PUSH_TO_TALK_TEST_ENV_H
