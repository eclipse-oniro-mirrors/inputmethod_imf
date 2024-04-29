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

#include <atomic>
#include <map>
#include <thread>

#include "application_info.h"
#include "block_queue.h"
#include "bundle_mgr_proxy.h"
#include "enable_ime_data_parser.h"
#include "settings_data_utils.h"
#include "security_mode_parser.h"
#include "element_name.h"
#include "event_handler.h"
#include "identity_checker_impl.h"
#include "ime_info_inquirer.h"
#include "input_method_status.h"
#include "input_method_system_ability_stub.h"
#include "inputmethod_dump.h"
#include "inputmethod_trace.h"
#include "peruser_session.h"
#include "system_ability.h"
#include "unRegistered_type.h"

namespace OHOS {
namespace MiscServices {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class InputMethodSystemAbility : public SystemAbility, public InputMethodSystemAbilityStub {
    DECLARE_SYSTEM_ABILITY(InputMethodSystemAbility);

public:
    DISALLOW_COPY_AND_MOVE(InputMethodSystemAbility);
    InputMethodSystemAbility(int32_t systemAbilityId, bool runOnCreate);
    InputMethodSystemAbility();
    ~InputMethodSystemAbility();

    int32_t StartInput(InputClientInfo &inputClientInfo, sptr<IRemoteObject> &agent) override;
    int32_t ShowCurrentInput() override;
    int32_t HideCurrentInput() override;
    int32_t ShowInput(sptr<IInputClient> client) override;
    int32_t HideInput(sptr<IInputClient> client) override;
    int32_t StopInputSession() override;
    int32_t ReleaseInput(sptr<IInputClient> client) override;
    int32_t RequestShowInput() override;
    int32_t RequestHideInput() override;
    int32_t GetDefaultInputMethod(std::shared_ptr<Property> &prop) override;
    int32_t GetInputMethodConfig(OHOS::AppExecFwk::ElementName &inputMethodConfig) override;
    std::shared_ptr<Property> GetCurrentInputMethod() override;
    std::shared_ptr<SubProperty> GetCurrentInputMethodSubtype() override;
    int32_t ListInputMethod(InputMethodStatus status, std::vector<Property> &props) override;
    int32_t ListCurrentInputMethodSubtype(std::vector<SubProperty> &subProps) override;
    int32_t ListInputMethodSubtype(const std::string &bundleName, std::vector<SubProperty> &subProps) override;
    int32_t SwitchInputMethod(
        const std::string &bundleName, const std::string &subName, SwitchTrigger trigger) override;
    int32_t DisplayOptionalInputMethod() override;
    int32_t SetCoreAndAgent(const sptr<IInputMethodCore> &core, const sptr<IRemoteObject> &agent) override;
    int32_t UnRegisteredProxyIme(UnRegisteredType type, const sptr<IInputMethodCore> &core) override;
    int32_t PanelStatusChange(const InputWindowStatus &status, const ImeWindowInfo &info) override;
    int32_t UpdateListenEventFlag(InputClientInfo &clientInfo, uint32_t eventFlag) override;
    bool IsCurrentIme() override;
    bool IsInputTypeSupported(InputType type) override;
    int32_t StartInputType(InputType type) override;
    int32_t ExitCurrentInputType() override;
    int32_t IsPanelShown(const PanelInfo &panelInfo, bool &isShown) override;
    int32_t GetSecurityMode(int32_t &security) override;
    int32_t ConnectSystemCmd(const sptr<IRemoteObject> &channel, sptr<IRemoteObject> &agent) override;
    // Deprecated because of no permission check, kept for compatibility
    int32_t HideCurrentInputDeprecated() override;
    int32_t ShowCurrentInputDeprecated() override;
    int Dump(int fd, const std::vector<std::u16string> &args) override;
    void DumpAllMethod(int fd);
    int32_t IsDefaultIme() override;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    int32_t Init();
    void Initialize();

    std::thread workThreadHandler; /*!< thread handler of the WorkThread */
    std::shared_ptr<PerUserSession> userSession_ = nullptr;
    std::shared_ptr<IdentityChecker> identityChecker_ = nullptr;
    int32_t PrepareInput(InputClientInfo &clientInfo);
    void WorkThread();
    bool StartInputService(const std::shared_ptr<ImeNativeCfg> &imeId);
    void StopInputService();
    int32_t OnUserStarted(const Message *msg);
    int32_t OnUserRemoved(const Message *msg);
    int32_t OnPackageRemoved(const Message *msg);
    int32_t OnDisplayOptionalInputMethod();
    void StartUserIdListener();
    bool IsNeedSwitch(const std::string &bundleName, const std::string &subName);
    int32_t CheckSwitchPermission(const SwitchInfo &switchInfo, SwitchTrigger trigger);
    bool IsStartInputTypePermitted();
    int32_t OnSwitchInputMethod(const SwitchInfo &switchInfo, SwitchTrigger trigger);
    int32_t OnStartInputType(const SwitchInfo &switchInfo, bool isCheckPermission);
    int32_t Switch(const std::string &bundleName, const std::shared_ptr<ImeInfo> &info);
    int32_t SwitchExtension(const std::shared_ptr<ImeInfo> &info);
    int32_t SwitchSubType(const std::shared_ptr<ImeInfo> &info);
    int32_t SwitchInputType(const SwitchInfo &switchInfo);
    ServiceRunningState state_;
    void InitServiceHandler();
    int32_t GetCurrentUserIdFromOsAccount();
    void HandleUserChanged(int32_t userId);
    int32_t StartImeWhenWmsReady();
    void HandleWmsReady(int32_t userId);
    int32_t InitAccountMonitor();
    static std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    int32_t userId_;
    static constexpr const char *SELECT_DIALOG_ACTION = "action.system.inputmethodchoose";
    static constexpr const char *SELECT_DIALOG_HAP = "com.ohos.inputmethodchoosedialog";
    static constexpr const char *SELECT_DIALOG_ABILITY = "InputMethod";
    static constexpr int32_t MAX_WAIT_TIME = 5000;
    BlockQueue<SwitchInfo> switchQueue_{ MAX_WAIT_TIME };
    bool stop_ = false;
    void InitMonitors();
    int32_t InitKeyEventMonitor();
    bool InitWmsMonitor();
    void InitSystemLanguageMonitor();
    void InitWmsConnectionMonitor();
    int32_t SwitchByCombinationKey(uint32_t state);
    int32_t SwitchMode();
    int32_t SwitchLanguage();
    int32_t SwitchType();
    int32_t GenerateClientInfo(InputClientInfo &clientInfo);
    void RegisterEnableImeObserver();
    void RegisterSecurityModeObserver();
    void CheckInputTypeOption(InputClientInfo &inputClientInfo);
    int32_t IsDefaultImeFromTokenId(uint32_t tokenId);
    void DealSwitchRequest();

    std::mutex checkMutex_;
    void DatashareCallback(const std::string &key);
    bool enableImeOn_ = false;
    bool enableSecurityMode_ = false;

    bool isScbEnable_ = false;
    std::atomic<bool> imeStarting_ = false;
    std::mutex switchImeMutex_;
    std::atomic<bool> switchTaskExecuting_ = false;
    std::atomic<uint32_t> targetSwitchCount_ = 0;
};
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_INPUT_METHOD_SYSTEM_ABILITY_H
