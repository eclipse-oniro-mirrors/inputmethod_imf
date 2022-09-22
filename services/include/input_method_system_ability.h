/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef SERVICES_INCLUDE_INPUT_METHOD_SYSTEM_ABILITY_H
#define SERVICES_INCLUDE_INPUT_METHOD_SYSTEM_ABILITY_H

#include <thread>
#include <map>
#include "system_ability.h"
#include "input_method_system_ability_stub.h"
#include "peruser_setting.h"
#include "peruser_session.h"
#include "event_handler.h"
#include "bundle_mgr_proxy.h"
#include "ability_manager_interface.h"
#include "inputmethod_dump.h"
#include "inputmethod_trace.h"

namespace OHOS {
namespace MiscServices {
    class InputDataChannelStub;
    using AbilityType = AppExecFwk::ExtensionAbilityType;
    enum class ServiceRunningState {
        STATE_NOT_START,
        STATE_RUNNING
    };

    class InputMethodSystemAbility : public SystemAbility, public InputMethodSystemAbilityStub {
        DECLARE_SYSTEM_ABILITY(InputMethodSystemAbility);
    public:
        DISALLOW_COPY_AND_MOVE(InputMethodSystemAbility);
        InputMethodSystemAbility(int32_t systemAbilityId, bool runOnCreate);
        InputMethodSystemAbility();
        ~InputMethodSystemAbility();
        static sptr<InputMethodSystemAbility> GetInstance();
        
        int32_t GetUserState(int32_t userId);

        int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                MessageOption &option) override;
        int32_t getDisplayMode(int32_t &retMode) override;
        int32_t getKeyboardWindowHeight(int32_t &retHeight) override;
        int32_t getCurrentKeyboardType(KeyboardType *retType) override;
        std::shared_ptr<InputMethodProperty> GetCurrentInputMethod() override;
        std::vector<InputMethodProperty> ListInputMethod(InputMethodStatus stauts) override;
        std::vector<InputMethodProperty> ListInputMethodByUserId(int32_t userId, InputMethodStatus status) override;
        int32_t listKeyboardType(const std::u16string &imeId, std::vector<KeyboardType *> *types) override;
        int Dump(int fd, const std::vector<std::u16string> &args) override;
        void DumpAllMethod(int fd);

    protected:
        void OnStart() override;
        void OnStop() override;

    private:
        int32_t Init();
        void Initialize();
        
        std::thread workThreadHandler; /*!< thread handler of the WorkThread */

        std::map<int32_t, PerUserSetting*> userSettings;

        std::map<int32_t, PerUserSession*> userSessions;
        std::map<int32_t, MessageHandler*> msgHandlers;

        void WorkThread();
        PerUserSetting *GetUserSetting(int32_t userId);
        PerUserSession *GetUserSession(int32_t userId);
        bool StartInputService(std::string imeId);
        void StopInputService(std::string imeId);
        int32_t OnUserStarted(const Message *msg);
        int32_t OnUserStopped(const Message *msg);
        int32_t OnUserUnlocked(const Message *msg);
        int32_t OnUserLocked(const Message *msg);
        int32_t OnHandleMessage(Message *msg);
        int32_t OnRemotePeerDied(const Message *msg);
        int32_t OnSettingChanged(const Message *msg);
        int32_t OnPackageRemoved(const Message *msg);
        int32_t OnPackageAdded(const Message *msg);
        int32_t OnDisableIms(const Message *msg);
        int32_t OnAdvanceToNext(const Message *msg);
        void OnDisplayOptionalInputMethod(int32_t userId);
        static sptr<AAFwk::IAbilityManager> GetAbilityManagerService();
        OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgr();
        std::vector<InputMethodProperty> listInputMethodByType(int32_t userId, AbilityType type);
        std::vector<InputMethodProperty> ListAllInputMethod(int32_t userId);
        std::vector<InputMethodProperty> ListEnabledInputMethod();
        std::vector<InputMethodProperty> ListDisabledInputMethod(int32_t userId);
        void StartUserIdListener();
        int32_t OnSwitchInputMethod(int32_t userId, const InputMethodProperty &target);
        std::string GetInputMethodParam(const std::vector<InputMethodProperty> &properties);
        ServiceRunningState state_;
        void InitServiceHandler();
        static std::mutex instanceLock_;
        static sptr<InputMethodSystemAbility> instance_;
        static std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
        int32_t userId_;
        static constexpr const char *SELECT_DIALOG_ACTION = "action.system.inputmethodselect";
        static constexpr const char *SELECT_DIALOG_HAP = "cn.openharmony.inputmethodchoosedialog";
        static constexpr const char *SELECT_DIALOG_ABILITY = "InputMethod";
    };
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_INPUT_METHOD_SYSTEM_ABILITY_H
