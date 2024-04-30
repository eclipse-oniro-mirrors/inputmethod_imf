/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_INPUT_METHOD_ABILITY_H
#define FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_INPUT_METHOD_ABILITY_H

#include <thread>

#include "calling_window_info.h"
#include "concurrent_map.h"
#include "foundation/ability/ability_runtime/interfaces/kits/native/appkit/ability_runtime/context/context.h"
#include "i_input_control_channel.h"
#include "i_input_data_channel.h"
#include "i_input_method_agent.h"
#include "i_input_method_core.h"
#include "i_input_method_system_ability.h"
#include "input_attribute.h"
#include "input_control_channel_proxy.h"
#include "input_data_channel_proxy.h"
#include "input_method_engine_listener.h"
#include "input_method_panel.h"
#include "iremote_object.h"
#include "keyboard_listener.h"
#include "keyevent_consumer_proxy.h"
#include "message.h"
#include "message_handler.h"
#include "private_command_interface.h"
#include "system_cmd_channel_proxy.h"
#include "unRegistered_type.h"

namespace OHOS {
namespace MiscServices {
class MessageHandler;
class InputMethodAbility : public RefBase, public PrivateCommandInterface {
public:
    InputMethodAbility();
    ~InputMethodAbility();
    static sptr<InputMethodAbility> GetInstance();
    int32_t SetCoreAndAgent();
    int32_t UnRegisteredProxyIme(UnRegisteredType type);
    int32_t InsertText(const std::string text);
    void SetImeListener(std::shared_ptr<InputMethodEngineListener> imeListener);
    void SetKdListener(std::shared_ptr<KeyboardListener> kdListener);
    int32_t DeleteForward(int32_t length);
    int32_t DeleteBackward(int32_t length);
    int32_t HideKeyboardSelf();
    int32_t StartInput(const InputClientInfo &clientInfo, bool isBindFromClient);
    int32_t StopInput(const sptr<IRemoteObject> &channelObject);
    int32_t ShowKeyboard();
    int32_t HideKeyboard();
    int32_t SendExtendAction(int32_t action);
    int32_t GetTextBeforeCursor(int32_t number, std::u16string &text);
    int32_t GetTextAfterCursor(int32_t number, std::u16string &text);
    int32_t SendFunctionKey(int32_t funcKey);
    int32_t MoveCursor(int32_t keyCode);
    int32_t SelectByRange(int32_t start, int32_t end);
    int32_t SelectByMovement(int32_t direction);
    int32_t DispatchKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, sptr<KeyEventConsumerProxy> &consumer);
    void SetCallingWindow(uint32_t windowId);
    int32_t GetEnterKeyType(int32_t &keyType);
    int32_t GetInputPattern(int32_t &inputPattern);
    int32_t GetTextIndexAtCursor(int32_t &index);
    int32_t GetTextConfig(TextTotalConfig &textConfig);
    int32_t CreatePanel(const std::shared_ptr<AbilityRuntime::Context> &context, const PanelInfo &panelInfo,
        std::shared_ptr<InputMethodPanel> &inputMethodPanel);
    int32_t DestroyPanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel);
    int32_t ShowPanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel);
    int32_t HidePanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel);
    bool IsCurrentIme();
    bool IsEnable();
    int32_t ExitCurrentInputType();
    int32_t IsPanelShown(const PanelInfo &panelInfo, bool &isShown);
    int32_t GetSecurityMode(int32_t &security);
    int32_t OnSecurityChange(int32_t security);
    int32_t OnConnectSystemCmd(const sptr<IRemoteObject> &channel, sptr<IRemoteObject> &agent);
    void OnClientInactive(const sptr<IRemoteObject> &channel);
    void NotifyKeyboardHeight(const std::shared_ptr<InputMethodPanel> inputMethodPanel);
    int32_t SendPrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) override;
    int32_t ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) override;
    bool IsDefaultIme();
    int32_t GetCallingWindowInfo(CallingWindowInfo &windowInfo);
    int32_t SetPreviewText(const std::string &text, const Range &range);
    int32_t FinishTextPreview();

private:
    std::thread workThreadHandler;
    MessageHandler *msgHandler_;
    bool stop_ = false;

    std::mutex controlChannelLock_;
    std::shared_ptr<InputControlChannelProxy> controlChannel_ = nullptr;

    std::mutex dataChannelLock_;
    sptr<IRemoteObject> dataChannelObject_ = nullptr;
    std::shared_ptr<InputDataChannelProxy> dataChannelProxy_ = nullptr;

    std::mutex systemCmdChannelLock_;
    sptr<SystemCmdChannelProxy> systemCmdChannelProxy_ = nullptr;

    std::shared_ptr<InputMethodEngineListener> imeListener_;
    std::shared_ptr<KeyboardListener> kdListener_;

    static std::mutex instanceLock_;
    static sptr<InputMethodAbility> instance_;
    std::mutex abilityLock_;
    sptr<IInputMethodSystemAbility> abilityManager_{ nullptr };
    sptr<InputDeathRecipient> deathRecipient_{ nullptr };
    sptr<IInputMethodSystemAbility> GetImsaProxy();
    void OnRemoteSaDied(const wptr<IRemoteObject> &object);

    sptr<SystemCmdChannelProxy> GetSystemCmdChannelProxy();
    void ClearSystemCmdChannel();

    void SetInputDataChannel(const sptr<IRemoteObject> &object);
    std::shared_ptr<InputDataChannelProxy> GetInputDataChannelProxy();
    void ClearDataChannel(const sptr<IRemoteObject> &channel);
    void SetInputControlChannel(sptr<IRemoteObject> &object);
    void ClearInputControlChannel();
    std::shared_ptr<InputControlChannelProxy> GetInputControlChannel();

    void Initialize();
    void WorkThread();
    void QuitWorkThread();

    void OnInitInputControlChannel(Message *msg);
    void OnSetSubtype(Message *msg);
    void NotifyAllTextConfig();
    void InvokeTextChangeCallback(const TextTotalConfig &textConfig);
    void OnCursorUpdate(Message *msg);
    void OnSelectionChange(Message *msg);
    void OnConfigurationChange(Message *msg);
    void OnStopInputService(Message *msg);

    int32_t HideKeyboard(Trigger trigger);
    std::shared_ptr<InputMethodPanel> GetSoftKeyboardPanel();
    /* param flag: ShowPanel is async, show/hide softkeyboard in alphabet keyboard attached,
       flag will be changed before finishing show/hide */
    int32_t ShowPanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel, PanelFlag flag, Trigger trigger);
    int32_t HidePanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel, PanelFlag flag, Trigger trigger);
    int32_t ShowSysPanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel, PanelFlag flag);
    void SetInputAttribute(const InputAttribute &inputAttribute);
    InputAttribute GetInputAttribute();
    void ClearInputAttribute();
    void NotifyPanelStatusInfo(const PanelStatusInfo &info);

    ConcurrentMap<PanelType, std::shared_ptr<InputMethodPanel>> panels_{};
    std::atomic_bool isBound_{ false };

    sptr<IInputMethodCore> coreStub_{ nullptr };
    sptr<IInputMethodAgent> agentStub_{ nullptr };
    sptr<IInputMethodAgent> systemAgentStub_{ nullptr };
    std::mutex imeCheckMutex_;
    bool isCurrentIme_ = false;

    double positionY_ = 0;
    double height_ = 0;

    bool isPendingShowKeyboard_ = false;

    std::mutex defaultImeCheckMutex_;
    bool isDefaultIme_ = false;
    std::mutex inputAttrLock_;
    InputAttribute inputAttribute_{};
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_INPUT_METHOD_ABILITY_H
