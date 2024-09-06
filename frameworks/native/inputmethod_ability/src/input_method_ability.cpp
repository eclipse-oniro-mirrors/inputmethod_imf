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

#include "input_method_ability.h"

#include <unistd.h>
#include <utility>

#include "global.h"
#include "input_method_agent_stub.h"
#include "input_method_core_stub.h"
#include "input_method_system_ability_proxy.h"
#include "input_method_utils.h"
#include "inputmethod_sysevent.h"
#include "inputmethod_trace.h"
#include "iservice_registry.h"
#include "itypes_util.h"
#include "message_parcel.h"
#include "string_ex.h"
#include "sys/prctl.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace MiscServices {
class MessageHandler;
using namespace MessageID;
sptr<InputMethodAbility> InputMethodAbility::instance_;
std::mutex InputMethodAbility::instanceLock_;
constexpr double INVALID_CURSOR_VALUE = -1.0;
constexpr int32_t INVALID_SELECTION_VALUE = -1;
constexpr uint32_t FIND_PANEL_RETRY_INTERVAL = 10;
constexpr uint32_t MAX_RETRY_TIMES = 100;
InputMethodAbility::InputMethodAbility() : msgHandler_(nullptr), stop_(false)
{
}

InputMethodAbility::~InputMethodAbility()
{
    IMSA_HILOGI("InputMethodAbility::~InputMethodAbility.");
    QuitWorkThread();
    if (msgHandler_ != nullptr) {
        delete msgHandler_;
        msgHandler_ = nullptr;
    }
}

sptr<InputMethodAbility> InputMethodAbility::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            IMSA_HILOGI("InputMethodAbility need new IMA.");
            instance_ = new (std::nothrow) InputMethodAbility();
            if (instance_ == nullptr) {
                IMSA_HILOGE("instance is nullptr!");
                return instance_;
            }
            instance_->Initialize();
        }
    }
    return instance_;
}

sptr<IInputMethodSystemAbility> InputMethodAbility::GetImsaProxy()
{
    std::lock_guard<std::mutex> lock(abilityLock_);
    if (abilityManager_ != nullptr) {
        return abilityManager_;
    }
    IMSA_HILOGI("InputMethodAbility get imsa proxy.");
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        IMSA_HILOGE("systemAbilityManager is nullptr!");
        return nullptr;
    }
    auto systemAbility = systemAbilityManager->GetSystemAbility(INPUT_METHOD_SYSTEM_ABILITY_ID, "");
    if (systemAbility == nullptr) {
        IMSA_HILOGE("systemAbility is nullptr!");
        return nullptr;
    }
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) InputDeathRecipient();
        if (deathRecipient_ == nullptr) {
            IMSA_HILOGE("failed to new death recipient!");
            return nullptr;
        }
    }
    deathRecipient_->SetDeathRecipient([this](const wptr<IRemoteObject> &remote) { OnRemoteSaDied(remote); });
    if ((systemAbility->IsProxyObject()) && (!systemAbility->AddDeathRecipient(deathRecipient_))) {
        IMSA_HILOGE("failed to add death recipient!");
        return nullptr;
    }
    abilityManager_ = iface_cast<IInputMethodSystemAbility>(systemAbility);
    return abilityManager_;
}

int32_t InputMethodAbility::SetCoreAndAgent()
{
    IMSA_HILOGD("InputMethodAbility, start.");
    if (isBound_.load()) {
        IMSA_HILOGD("already bound.");
        return ErrorCode::NO_ERROR;
    }
    auto proxy = GetImsaProxy();
    if (proxy == nullptr) {
        IMSA_HILOGE("imsa proxy is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    int32_t ret = proxy->SetCoreAndAgent(coreStub_, agentStub_->AsObject());
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("set failed, ret: %{public}d!", ret);
        return ret;
    }
    isBound_.store(true);
    IMSA_HILOGD("set successfully.");
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodAbility::UnRegisteredProxyIme(UnRegisteredType type)
{
    isBound_.store(false);
    auto proxy = GetImsaProxy();
    if (proxy == nullptr) {
        IMSA_HILOGE("imsa proxy is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    return proxy->UnRegisteredProxyIme(type, coreStub_);
}

void InputMethodAbility::Initialize()
{
    IMSA_HILOGD("IMA init.");
    sptr<InputMethodCoreStub> coreStub = new (std::nothrow) InputMethodCoreStub();
    if (coreStub == nullptr) {
        IMSA_HILOGE("failed to create core!");
        return;
    }
    sptr<InputMethodAgentStub> agentStub = new (std::nothrow) InputMethodAgentStub();
    if (agentStub == nullptr) {
        IMSA_HILOGE("failed to create agent!");
        return;
    }
    msgHandler_ = new (std::nothrow) MessageHandler();
    if (msgHandler_ == nullptr) {
        IMSA_HILOGE("failed to create message handler!");
        return;
    }
    coreStub->SetMessageHandler(msgHandler_);
    agentStub->SetMessageHandler(msgHandler_);
    agentStub_ = agentStub;
    coreStub_ = coreStub;
    workThreadHandler = std::thread([this] { this->WorkThread(); });
}

void InputMethodAbility::SetImeListener(std::shared_ptr<InputMethodEngineListener> imeListener)
{
    IMSA_HILOGD("InputMethodAbility start.");
    if (imeListener_ == nullptr) {
        imeListener_ = std::move(imeListener);
    }
}

void InputMethodAbility::SetKdListener(std::shared_ptr<KeyboardListener> kdListener)
{
    IMSA_HILOGD("InputMethodAbility start.");
    if (kdListener_ == nullptr) {
        kdListener_ = std::move(kdListener);
    }
}

void InputMethodAbility::WorkThread()
{
    prctl(PR_SET_NAME, "OS_IMAWorkThread start.");
    while (!stop_) {
        Message *msg = msgHandler_->GetMessage();
        switch (msg->msgId_) {
            case MSG_ID_INIT_INPUT_CONTROL_CHANNEL: {
                OnInitInputControlChannel(msg);
                break;
            }
            case MSG_ID_ON_CURSOR_UPDATE: {
                OnCursorUpdate(msg);
                break;
            }
            case MSG_ID_ON_SELECTION_CHANGE: {
                OnSelectionChange(msg);
                break;
            }
            case MSG_ID_ON_ATTRIBUTE_CHANGE: {
                OnAttributeChange(msg);
                break;
            }
            case MSG_ID_STOP_INPUT_SERVICE: {
                OnStopInputService(msg);
                break;
            }
            case MSG_ID_SET_SUBTYPE: {
                OnSetSubtype(msg);
                break;
            }
            default: {
                IMSA_HILOGD("the message is %{public}d.", msg->msgId_);
                break;
            }
        }
        delete msg;
        msg = nullptr;
    }
}

void InputMethodAbility::OnInitInputControlChannel(Message *msg)
{
    IMSA_HILOGD("InputMethodAbility::OnInitInputControlChannel start.");
    MessageParcel *data = msg->msgContent_;
    sptr<IRemoteObject> channelObject = data->ReadRemoteObject();
    if (channelObject == nullptr) {
        IMSA_HILOGE("channelObject is nullptr!");
        return;
    }
    SetInputControlChannel(channelObject);
}

int32_t InputMethodAbility::StartInput(const InputClientInfo &clientInfo, bool isBindFromClient)
{
    std::lock_guard<std::recursive_mutex> lock(keyboardCmdLock_);
    int32_t cmdCount = ++cmdId_;
    if (clientInfo.channel == nullptr) {
        IMSA_HILOGE("channelObject is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    IMSA_HILOGI("IMA isShowKeyboard: %{public}d, isBindFromClient: %{public}d.", clientInfo.isShowKeyboard,
        isBindFromClient);
    SetInputDataChannel(clientInfo.channel);
    if (clientInfo.needHide) {
        IMSA_HILOGD("pwd or normal input pattern changed, need hide panel first.");
        auto panel = GetSoftKeyboardPanel();
        if (panel != nullptr) {
            panel->HidePanel();
        }
    }
    int32_t ret = isBindFromClient ? InvokeStartInputCallback(clientInfo.config, clientInfo.isNotifyInputStart)
                                   : InvokeStartInputCallback(clientInfo.isNotifyInputStart);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to invoke callback, ret: %{public}d!", ret);
        return ret;
    }
    isPendingShowKeyboard_ = clientInfo.isShowKeyboard;
    if (clientInfo.isShowKeyboard) {
        auto task = [this, cmdCount]() {
            std::thread([this, cmdCount]() { ShowKeyboardImplWithLock(cmdCount); }).detach();
        };
        if (imeListener_ == nullptr || !imeListener_->PostTaskToEventHandler(task, "ShowKeyboard")) {
            IMSA_HILOGE("imeListener_ is nullptr, or post task failed!");
            ShowKeyboardImplWithoutLock(cmdCount);
        }
    }
    return ErrorCode::NO_ERROR;
}

void InputMethodAbility::OnSetSubtype(Message *msg)
{
    auto data = msg->msgContent_;
    SubProperty subProperty;
    if (!ITypesUtil::Unmarshal(*data, subProperty)) {
        IMSA_HILOGE("read message parcel failed!");
        return;
    }
    if (imeListener_ == nullptr) {
        IMSA_HILOGE("imeListener_ is nullptr!");
        return;
    }
    imeListener_->OnSetSubtype(subProperty);
}

void InputMethodAbility::ClearDataChannel(const sptr<IRemoteObject> &channel)
{
    std::lock_guard<std::mutex> lock(dataChannelLock_);
    if (dataChannelObject_ == nullptr || channel == nullptr) {
        IMSA_HILOGD("dataChannelObject_ already nullptr.");
        return;
    }
    if (dataChannelObject_.GetRefPtr() == channel.GetRefPtr()) {
        dataChannelObject_ = nullptr;
        dataChannelProxy_ = nullptr;
        IMSA_HILOGD("end.");
    }
}

int32_t InputMethodAbility::StopInput(const sptr<IRemoteObject> &channelObject)
{
    std::lock_guard<std::recursive_mutex> lock(keyboardCmdLock_);
    int32_t cmdCount = ++cmdId_;
    IMSA_HILOGI("IMA");
    HideKeyboardImplWithoutLock(cmdCount, false);
    ClearDataChannel(channelObject);
    ClearInputAttribute();
    if (imeListener_ != nullptr) {
        imeListener_->OnInputFinish();
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodAbility::DispatchKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent,
    sptr<KeyEventConsumerProxy> &consumer)
{
    if (keyEvent == nullptr) {
        IMSA_HILOGE("keyEvent is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    if (kdListener_ == nullptr) {
        IMSA_HILOGE("kdListener_ is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    IMSA_HILOGD("InputMethodAbility, start.");

    if (!kdListener_->OnDealKeyEvent(keyEvent, consumer)) {
        IMSA_HILOGE("keyEvent not deal!");
        return ErrorCode::ERROR_DISPATCH_KEY_EVENT;
    }
    return ErrorCode::NO_ERROR;
}

void InputMethodAbility::SetCallingWindow(uint32_t windowId)
{
    IMSA_HILOGD("InputMethodAbility windowId: %{public}d.", windowId);
    panels_.ForEach([windowId](const PanelType &panelType, const std::shared_ptr<InputMethodPanel> &panel) {
        panel->SetCallingWindow(windowId);
        return false;
    });
    if (imeListener_ == nullptr) {
        IMSA_HILOGD("imeListener_ is nullptr!");
        return;
    }
    imeListener_->OnSetCallingWindow(windowId);
}

void InputMethodAbility::OnCursorUpdate(Message *msg)
{
    MessageParcel *data = msg->msgContent_;
    int32_t positionX = data->ReadInt32();
    int32_t positionY = data->ReadInt32();
    int32_t height = data->ReadInt32();
    if (kdListener_ == nullptr) {
        IMSA_HILOGE("kdListener_ is nullptr!");
        return;
    }
    IMSA_HILOGD("x: %{public}d, y: %{public}d, height: %{public}d.", positionX, positionY, height);
    kdListener_->OnCursorUpdate(positionX, positionY, height);
}

void InputMethodAbility::OnSelectionChange(Message *msg)
{
    MessageParcel *data = msg->msgContent_;
    std::string text = Str16ToStr8(data->ReadString16());
    int32_t oldBegin = data->ReadInt32();
    int32_t oldEnd = data->ReadInt32();
    int32_t newBegin = data->ReadInt32();
    int32_t newEnd = data->ReadInt32();

    if (kdListener_ == nullptr) {
        IMSA_HILOGE("kdListener_ is nullptr!");
        return;
    }
    kdListener_->OnTextChange(text);
    kdListener_->OnSelectionChange(oldBegin, oldEnd, newBegin, newEnd);
}

void InputMethodAbility::OnAttributeChange(Message *msg)
{
    if (kdListener_ == nullptr || msg == nullptr) {
        IMSA_HILOGE("kdListener_ or msg is nullptr!");
        return;
    }
    MessageParcel *data = msg->msgContent_;
    InputAttribute attribute;
    if (!ITypesUtil::Unmarshal(*data, attribute)) {
        IMSA_HILOGE("failed to read attribute!");
        return;
    }
    IMSA_HILOGD("enterKeyType: %{public}d, inputPattern: %{public}d.", attribute.enterKeyType,
        attribute.inputPattern);
    SetInputAttribute(attribute);
    // add for mod inputPattern when panel show
    auto panel = GetSoftKeyboardPanel();
    if (panel != nullptr) {
        auto keyboardSize = panel->GetKeyboardSize();
        SysPanelStatus sysPanelStatus = { false, panel->GetPanelFlag(), keyboardSize.width, keyboardSize.height };
        NotifyPanelStatus(panel, sysPanelStatus);
    }
    kdListener_->OnEditorAttributeChange(attribute);
}

void InputMethodAbility::OnStopInputService(Message *msg)
{
    MessageParcel *data = msg->msgContent_;
    bool isTerminateIme = data->ReadBool();
    IMSA_HILOGI("isTerminateIme: %{public}d.", isTerminateIme);
    if (isTerminateIme && imeListener_ != nullptr) {
        imeListener_->OnInputStop();
    }
    isBound_.store(false);
}

int32_t InputMethodAbility::HideKeyboard(bool isForce)
{
    std::lock_guard<std::recursive_mutex> lock(keyboardCmdLock_);
    int32_t cmdCount = ++cmdId_;
    return HideKeyboardImplWithoutLock(cmdCount, isForce);
}

int32_t InputMethodAbility::HideKeyboardImplWithoutLock(int32_t cmdId, bool isForce)
{
    if (cmdId != cmdId_) {
        IMSA_HILOGE("current is not last cmd cur: %{public}d, cmdId_: %{public}d!", cmdId, cmdId_);
        return ErrorCode::NO_ERROR;
    }
    return HideKeyboard(Trigger::IMF, isForce);
}

int32_t InputMethodAbility::ShowKeyboard()
{
    std::lock_guard<std::recursive_mutex> lock(keyboardCmdLock_);
    int32_t cmdCount = ++cmdId_;
    return ShowKeyboardImplWithoutLock(cmdCount);
}

int32_t InputMethodAbility::ShowKeyboardImplWithLock(int32_t cmdId)
{
    std::lock_guard<std::recursive_mutex> lock(keyboardCmdLock_);
    return ShowKeyboardImplWithoutLock(cmdId);
}

int32_t InputMethodAbility::ShowKeyboardImplWithoutLock(int32_t cmdId)
{
    if (cmdId != cmdId_) {
        IMSA_HILOGE("current is not last cmd cur: %{public}d, cmdId_: %{public}d!", cmdId, cmdId_);
        return ErrorCode::NO_ERROR;
    }
    if (imeListener_ == nullptr) {
        IMSA_HILOGE("imeListener is nullptr!");
        return ErrorCode::ERROR_IME;
    }
    IMSA_HILOGI("IMA start.");
    if (panels_.Contains(SOFT_KEYBOARD)) {
        auto panel = GetSoftKeyboardPanel();
        if (panel == nullptr) {
            IMSA_HILOGE("panel is nullptr!");
            return ErrorCode::ERROR_IME;
        }
        auto flag = panel->GetPanelFlag();
        imeListener_->OnKeyboardStatus(true);
        if (flag == FLG_CANDIDATE_COLUMN) {
            IMSA_HILOGI("panel flag is candidate, no need to show.");
            NotifyKeyboardHeight(0, flag);
            return ErrorCode::NO_ERROR;
        }
        return ShowPanel(panel, flag, Trigger::IMF);
    }
    IMSA_HILOGI("panel not create.");
    auto channel = GetInputDataChannelProxy();
    if (channel != nullptr) {
        channel->SendKeyboardStatus(KeyboardStatus::SHOW);
    }
    imeListener_->OnKeyboardStatus(true);
    return ErrorCode::NO_ERROR;
}

void InputMethodAbility::NotifyPanelStatusInfo(const PanelStatusInfo &info)
{
    // CANDIDATE_COLUMN not notify
    if (info.panelInfo.panelFlag == PanelFlag::FLG_CANDIDATE_COLUMN) {
        return;
    }
    auto channel = GetInputDataChannelProxy();
    if (channel != nullptr) {
        if (info.panelInfo.panelType == PanelType::SOFT_KEYBOARD) {
            info.visible ? channel->SendKeyboardStatus(KeyboardStatus::SHOW)
                         : channel->SendKeyboardStatus(KeyboardStatus::HIDE);
        }
        channel->NotifyPanelStatusInfo(info);
    }

    auto controlChannel = GetInputControlChannel();
    if (controlChannel != nullptr && info.trigger == Trigger::IME_APP && !info.visible) {
        controlChannel->HideKeyboardSelf();
    }
}

int32_t InputMethodAbility::InvokeStartInputCallback(bool isNotifyInputStart)
{
    TextTotalConfig textConfig = {};
    int32_t ret = GetTextConfig(textConfig);
    if (ret == ErrorCode::NO_ERROR) {
        return InvokeStartInputCallback(textConfig, isNotifyInputStart);
    }
    IMSA_HILOGW("failed to get text config, ret: %{public}d.", ret);
    if (imeListener_ == nullptr) {
        IMSA_HILOGE("imeListener_ is nullptr!");
        return ErrorCode::ERROR_IME;
    }
    if (isNotifyInputStart) {
        imeListener_->OnInputStart();
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodAbility::InvokeStartInputCallback(const TextTotalConfig &textConfig, bool isNotifyInputStart)
{
    if (imeListener_ == nullptr) {
        IMSA_HILOGE("imeListener_ is nullptr!");
        return ErrorCode::ERROR_IME;
    }
    positionY_ = textConfig.positionY;
    height_ = textConfig.height;
    SetInputAttribute(textConfig.inputAttribute);
    if (kdListener_ != nullptr) {
        kdListener_->OnEditorAttributeChange(textConfig.inputAttribute);
    }
    if (TextConfig::IsPrivateCommandValid(textConfig.privateCommand) && IsDefaultIme()) {
        IMSA_HILOGI("notify privateCommand.");
        imeListener_->ReceivePrivateCommand(textConfig.privateCommand);
    }
    if (isNotifyInputStart) {
        imeListener_->OnInputStart();
    }
    if (kdListener_ != nullptr) {
        if (textConfig.cursorInfo.left != INVALID_CURSOR_VALUE) {
            kdListener_->OnCursorUpdate(textConfig.cursorInfo.left, textConfig.cursorInfo.top,
                textConfig.cursorInfo.height);
        }
        if (textConfig.textSelection.newBegin != INVALID_SELECTION_VALUE) {
            kdListener_->OnSelectionChange(textConfig.textSelection.oldBegin, textConfig.textSelection.oldEnd,
                textConfig.textSelection.newBegin, textConfig.textSelection.newEnd);
        }
    }
    if (textConfig.windowId == ANCO_INVALID_WINDOW_ID) {
        return ErrorCode::NO_ERROR;
    }
    auto task = [this, textConfig]() {
        panels_.ForEach([&textConfig](const PanelType &panelType, const std::shared_ptr<InputMethodPanel> &panel) {
            panel->SetCallingWindow(textConfig.windowId);
            return false;
        });
    };
    imeListener_->PostTaskToEventHandler(task, "SetCallingWindow");
    if (textConfig.windowId != INVALID_WINDOW_ID) {
        imeListener_->OnSetCallingWindow(textConfig.windowId);
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodAbility::InsertText(const std::string text)
{
    InputMethodSyncTrace tracer("IMA_InsertText");
    IMSA_HILOGD("InputMethodAbility start.");
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->InsertText(Str8ToStr16(text));
}

int32_t InputMethodAbility::DeleteForward(int32_t length)
{
    InputMethodSyncTrace tracer("IMA_DeleteForward");
    IMSA_HILOGD("InputMethodAbility start, length: %{public}d.", length);
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->DeleteForward(length);
}

int32_t InputMethodAbility::DeleteBackward(int32_t length)
{
    IMSA_HILOGD("InputMethodAbility start, length: %{public}d.", length);
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->DeleteBackward(length);
}

int32_t InputMethodAbility::SendFunctionKey(int32_t funcKey)
{
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->SendFunctionKey(funcKey);
}

int32_t InputMethodAbility::HideKeyboardSelf()
{
    InputMethodSyncTrace tracer("IMA_HideKeyboardSelf start.");
    auto ret = HideKeyboard(Trigger::IME_APP, false);
    if (ret == ErrorCode::NO_ERROR) {
        InputMethodSysEvent::GetInstance().OperateSoftkeyboardBehaviour(OperateIMEInfoCode::IME_HIDE_SELF);
    }
    return ret == ErrorCode::ERROR_CLIENT_NULL_POINTER ? ret : ErrorCode::NO_ERROR;
}

int32_t InputMethodAbility::SendExtendAction(int32_t action)
{
    IMSA_HILOGD("InputMethodAbility, action: %{public}d.", action);
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->HandleExtendAction(action);
}

int32_t InputMethodAbility::GetTextBeforeCursor(int32_t number, std::u16string &text)
{
    InputMethodSyncTrace tracer("IMA_GetForward");
    IMSA_HILOGD("InputMethodAbility, number: %{public}d.", number);
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->GetTextBeforeCursor(number, text);
}

int32_t InputMethodAbility::GetTextAfterCursor(int32_t number, std::u16string &text)
{
    InputMethodSyncTrace tracer("IMA_GetTextAfterCursor");
    IMSA_HILOGD("InputMethodAbility, number: %{public}d.", number);
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->GetTextAfterCursor(number, text);
}

int32_t InputMethodAbility::MoveCursor(int32_t keyCode)
{
    IMSA_HILOGD("InputMethodAbility, keyCode: %{public}d.", keyCode);
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->MoveCursor(keyCode);
}

int32_t InputMethodAbility::SelectByRange(int32_t start, int32_t end)
{
    IMSA_HILOGD("InputMethodAbility, start: %{public}d, end: %{public}d", start, end);
    if (start < 0 || end < 0) {
        IMSA_HILOGE("check parameter failed, start: %{public}d, end: %{public}d!", start, end);
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    auto dataChannel = GetInputDataChannelProxy();
    if (dataChannel == nullptr) {
        IMSA_HILOGE("datachannel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return dataChannel->SelectByRange(start, end);
}

int32_t InputMethodAbility::SelectByMovement(int32_t direction)
{
    IMSA_HILOGD("InputMethodAbility, direction: %{public}d.", direction);
    auto dataChannel = GetInputDataChannelProxy();
    if (dataChannel == nullptr) {
        IMSA_HILOGE("datachannel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return dataChannel->SelectByMovement(direction, 0);
}

int32_t InputMethodAbility::GetEnterKeyType(int32_t &keyType)
{
    IMSA_HILOGD("InputMethodAbility start.");
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->GetEnterKeyType(keyType);
}

int32_t InputMethodAbility::GetInputPattern(int32_t &inputPattern)
{
    IMSA_HILOGD("InputMethodAbility start.");
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->GetInputPattern(inputPattern);
}

int32_t InputMethodAbility::GetTextIndexAtCursor(int32_t &index)
{
    IMSA_HILOGD("InputMethodAbility start.");
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->GetTextIndexAtCursor(index);
}

int32_t InputMethodAbility::GetTextConfig(TextTotalConfig &textConfig)
{
    IMSA_HILOGD("InputMethodAbility start.");
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return channel->GetTextConfig(textConfig);
}

void InputMethodAbility::SetInputDataChannel(const sptr<IRemoteObject> &object)
{
    IMSA_HILOGD("SetInputDataChannel start.");
    std::lock_guard<std::mutex> lock(dataChannelLock_);
    auto channelProxy = std::make_shared<InputDataChannelProxy>(object);
    if (channelProxy == nullptr) {
        IMSA_HILOGE("failed to create channel proxy!");
        return;
    }
    dataChannelObject_ = object;
    dataChannelProxy_ = channelProxy;
}

std::shared_ptr<InputDataChannelProxy> InputMethodAbility::GetInputDataChannelProxy()
{
    std::lock_guard<std::mutex> lock(dataChannelLock_);
    return dataChannelProxy_;
}

void InputMethodAbility::SetInputControlChannel(sptr<IRemoteObject> &object)
{
    IMSA_HILOGD("SetInputControlChannel start.");
    std::lock_guard<std::mutex> lock(controlChannelLock_);
    std::shared_ptr<InputControlChannelProxy> channelProxy = std::make_shared<InputControlChannelProxy>(object);
    if (channelProxy == nullptr) {
        IMSA_HILOGD("channelProxy is nullptr!");
        return;
    }
    controlChannel_ = channelProxy;
}

void InputMethodAbility::ClearInputControlChannel()
{
    std::lock_guard<std::mutex> lock(controlChannelLock_);
    controlChannel_ = nullptr;
}

std::shared_ptr<InputControlChannelProxy> InputMethodAbility::GetInputControlChannel()
{
    std::lock_guard<std::mutex> lock(controlChannelLock_);
    return controlChannel_;
}

void InputMethodAbility::OnRemoteSaDied(const wptr<IRemoteObject> &object)
{
    IMSA_HILOGI("input method service died.");
    isBound_.store(false);
    ClearInputControlChannel();
    ClearSystemCmdChannel();
    {
        std::lock_guard<std::mutex> lock(abilityLock_);
        abilityManager_ = nullptr;
    }
    if (imeListener_ != nullptr) {
        imeListener_->OnInputStop();
    }
}

void InputMethodAbility::QuitWorkThread()
{
    stop_ = true;
    Message *msg = new Message(MessageID::MSG_ID_QUIT_WORKER_THREAD, nullptr);
    msgHandler_->SendMessage(msg);
    if (workThreadHandler.joinable()) {
        workThreadHandler.join();
    }
}

int32_t InputMethodAbility::GetSecurityMode(int32_t &security)
{
    IMSA_HILOGI("InputMethodAbility start.");
    auto proxy = GetImsaProxy();
    if (proxy == nullptr) {
        IMSA_HILOGE("failed to get imsa proxy!");
        return false;
    }
    return proxy->GetSecurityMode(security);
}

void InputMethodAbility::ClearSystemCmdChannel()
{
    std::lock_guard<std::mutex> lock(systemCmdChannelLock_);
    if (systemCmdChannelProxy_ == nullptr) {
        IMSA_HILOGD("systemCmdChannelProxy_ already nullptr.");
        return;
    }
    systemCmdChannelProxy_ = nullptr;
    IMSA_HILOGD("end.");
}

sptr<SystemCmdChannelProxy> InputMethodAbility::GetSystemCmdChannelProxy()
{
    std::lock_guard<std::mutex> lock(systemCmdChannelLock_);
    return systemCmdChannelProxy_;
}

int32_t InputMethodAbility::OnConnectSystemCmd(const sptr<IRemoteObject> &channel, sptr<IRemoteObject> &agent)
{
    IMSA_HILOGD("InputMethodAbility start.");
    std::lock_guard<std::mutex> lock(systemCmdChannelLock_);
    systemCmdChannelProxy_ = new (std::nothrow) SystemCmdChannelProxy(channel);
    if (systemCmdChannelProxy_ == nullptr) {
        IMSA_HILOGE("failed to create channel proxy!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    systemAgentStub_ = new (std::nothrow) InputMethodAgentStub();
    if (systemAgentStub_ == nullptr) {
        IMSA_HILOGE("failed to create agent!");
        systemCmdChannelProxy_ = nullptr;
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    agent = systemAgentStub_->AsObject();
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodAbility::OnSecurityChange(int32_t security)
{
    IMSA_HILOGI("InputMethodAbility start.");
    if (imeListener_ == nullptr) {
        IMSA_HILOGE("imeListener_ is nullptr!");
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    imeListener_->OnSecurityChange(security);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodAbility::CreatePanel(const std::shared_ptr<AbilityRuntime::Context> &context,
    const PanelInfo &panelInfo, std::shared_ptr<InputMethodPanel> &inputMethodPanel)
{
    IMSA_HILOGI("InputMethodAbility start.");
    auto panelHeightCallback = [this](uint32_t panelHeight, PanelFlag panelFlag) {
        NotifyKeyboardHeight(panelHeight, panelFlag);
    };
    auto flag = panels_.ComputeIfAbsent(
        panelInfo.panelType, [panelHeightCallback, &panelInfo, &context, &inputMethodPanel](
                                 const PanelType &panelType, std::shared_ptr<InputMethodPanel> &panel) {
            inputMethodPanel = std::make_shared<InputMethodPanel>();
            inputMethodPanel->SetPanelHeightCallback(panelHeightCallback);
            auto ret = inputMethodPanel->CreatePanel(context, panelInfo);
            if (ret == ErrorCode::NO_ERROR) {
                panel = inputMethodPanel;
                return true;
            }
            inputMethodPanel = nullptr;
            return false;
        });
    // Called when creating the input method first time, if the CreatePanel is called later than the ShowKeyboard.
    if (panelInfo.panelType == SOFT_KEYBOARD && isPendingShowKeyboard_) {
        ShowKeyboard();
        isPendingShowKeyboard_ = false;
    }
    return flag ? ErrorCode::NO_ERROR : ErrorCode::ERROR_OPERATE_PANEL;
}

int32_t InputMethodAbility::DestroyPanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel)
{
    std::lock_guard<std::recursive_mutex> lock(keyboardCmdLock_);
    IMSA_HILOGI("InputMethodAbility start.");
    if (inputMethodPanel == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    auto ret = inputMethodPanel->DestroyPanel();
    if (ret == ErrorCode::NO_ERROR) {
        PanelType panelType = inputMethodPanel->GetPanelType();
        panels_.Erase(panelType);
    }
    return ret;
}

int32_t InputMethodAbility::ShowPanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel)
{
    std::lock_guard<std::recursive_mutex> lock(keyboardCmdLock_);
    if (inputMethodPanel == nullptr) {
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    return ShowPanel(inputMethodPanel, inputMethodPanel->GetPanelFlag(), Trigger::IME_APP);
}

int32_t InputMethodAbility::HidePanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel)
{
    std::lock_guard<std::recursive_mutex> lock(keyboardCmdLock_);
    if (inputMethodPanel == nullptr) {
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    return HidePanel(inputMethodPanel, inputMethodPanel->GetPanelFlag(), Trigger::IME_APP, false);
}

int32_t InputMethodAbility::ShowPanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel, PanelFlag flag,
    Trigger trigger)
{
    if (inputMethodPanel == nullptr) {
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    if (trigger == Trigger::IME_APP && GetInputDataChannelProxy() == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    if (flag == FLG_FIXED && inputMethodPanel->GetPanelType() == SOFT_KEYBOARD) {
        auto ret = inputMethodPanel->SetTextFieldAvoidInfo(positionY_, height_);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("failed to set keyBoard, ret: %{public}d!", ret);
        }
    }
    auto keyboardSize = inputMethodPanel->GetKeyboardSize();
    SysPanelStatus sysPanelStatus = { false, flag, keyboardSize.width, keyboardSize.height };
    NotifyPanelStatus(inputMethodPanel, sysPanelStatus);
    auto ret = inputMethodPanel->ShowPanel();
    if (ret == ErrorCode::NO_ERROR) {
        NotifyPanelStatusInfo({ { inputMethodPanel->GetPanelType(), flag }, true, trigger });
    }
    return ret;
}

int32_t InputMethodAbility::HidePanel(const std::shared_ptr<InputMethodPanel> &inputMethodPanel, PanelFlag flag,
                                      Trigger trigger, bool isForce)
{
    if (inputMethodPanel == nullptr) {
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    auto ret = inputMethodPanel->HidePanel(isForce);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGD("failed, ret: %{public}d", ret);
        return ret;
    }
    NotifyPanelStatusInfo({ { inputMethodPanel->GetPanelType(), flag }, false, trigger });
    // finish previewing text when soft keyboard hides
    if (inputMethodPanel->GetPanelType() == PanelType::SOFT_KEYBOARD) {
        FinishTextPreview(true);
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodAbility::NotifyPanelStatus(
    const std::shared_ptr<InputMethodPanel> &inputMethodPanel, SysPanelStatus &sysPanelStatus)
{
    if (inputMethodPanel->GetPanelType() != SOFT_KEYBOARD) {
        return ErrorCode::NO_ERROR;
    }
    // If it is not binding, do not need to notify the panel
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        return ErrorCode::NO_ERROR;
    }
    bool isSecurity = GetInputAttribute().GetSecurityFlag();
    sysPanelStatus.isSecurity = isSecurity;
    auto systemChannel = GetSystemCmdChannelProxy();
    if (systemChannel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return systemChannel->NotifyPanelStatus(sysPanelStatus);
}

void InputMethodAbility::SetInputAttribute(const InputAttribute &inputAttribute)
{
    std::lock_guard<std::mutex> lock(inputAttrLock_);
    inputAttribute_ = inputAttribute;
}

void InputMethodAbility::ClearInputAttribute()
{
    std::lock_guard<std::mutex> lock(inputAttrLock_);
    inputAttribute_ = {};
}

InputAttribute InputMethodAbility::GetInputAttribute()
{
    std::lock_guard<std::mutex> lock(inputAttrLock_);
    return inputAttribute_;
}

int32_t InputMethodAbility::HideKeyboard(Trigger trigger, bool isForce)
{
    InputMethodSyncTrace tracer("IMA_HideKeyboard");
    if (imeListener_ == nullptr) {
        IMSA_HILOGE("imeListener_ is nullptr!");
        return ErrorCode::ERROR_IME;
    }
    IMSA_HILOGD("IMA, trigger: %{public}d.", static_cast<int32_t>(trigger));
    if (panels_.Contains(SOFT_KEYBOARD)) {
        auto panel = GetSoftKeyboardPanel();
        if (panel == nullptr) {
            IMSA_HILOGE("panel is nullptr!");
            return ErrorCode::ERROR_IME;
        }
        auto flag = panel->GetPanelFlag();
        imeListener_->OnKeyboardStatus(false);
        if (flag == FLG_CANDIDATE_COLUMN) {
            IMSA_HILOGI("panel flag is candidate, no need to hide.");
            return ErrorCode::NO_ERROR;
        }
        return HidePanel(panel, flag, trigger, isForce);
    }
    IMSA_HILOGI("panel is not created.");
    imeListener_->OnKeyboardStatus(false);
    auto channel = GetInputDataChannelProxy();
    if (channel != nullptr) {
        channel->SendKeyboardStatus(KeyboardStatus::HIDE);
    }
    auto controlChannel = GetInputControlChannel();
    if (controlChannel != nullptr && trigger == Trigger::IME_APP) {
        controlChannel->HideKeyboardSelf();
    }
    return ErrorCode::NO_ERROR;
}

std::shared_ptr<InputMethodPanel> InputMethodAbility::GetSoftKeyboardPanel()
{
    auto result = panels_.Find(SOFT_KEYBOARD);
    if (!result.first) {
        return nullptr;
    }
    auto panel = result.second;
    if (!BlockRetry(FIND_PANEL_RETRY_INTERVAL, MAX_RETRY_TIMES, [panel]() -> bool {
            return panel != nullptr && panel->windowId_ != InputMethodPanel::INVALID_WINDOW_ID;
        })) {
        return nullptr;
    }
    return panel;
}

bool InputMethodAbility::IsCurrentIme()
{
    IMSA_HILOGD("InputMethodAbility start.");
    if (isCurrentIme_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(imeCheckMutex_);
    if (isCurrentIme_) {
        return true;
    }
    auto proxy = GetImsaProxy();
    if (proxy == nullptr) {
        IMSA_HILOGE("failed to get imsa proxy!");
        return false;
    }
    if (proxy->IsCurrentIme()) {
        isCurrentIme_ = true;
        return true;
    }
    return false;
}

bool InputMethodAbility::IsDefaultIme()
{
    IMSA_HILOGD("InputMethodAbility start");
    if (isDefaultIme_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(defaultImeCheckMutex_);
    if (isDefaultIme_) {
        return true;
    }
    auto proxy = GetImsaProxy();
    if (proxy == nullptr) {
        IMSA_HILOGE("failed to get imsa proxy!");
        return false;
    }
    auto ret = proxy->IsDefaultIme();
    if (ret == ErrorCode::NO_ERROR) {
        isDefaultIme_ = true;
        return true;
    }
    IMSA_HILOGE("call IsDefaultIme failed, ret: %{public}d!", ret);
    return false;
}

bool InputMethodAbility::IsEnable()
{
    if (imeListener_ == nullptr) {
        return false;
    }
    return imeListener_->IsEnable();
}

int32_t InputMethodAbility::ExitCurrentInputType()
{
    IMSA_HILOGD("InputMethodAbility start.");
    auto proxy = GetImsaProxy();
    if (proxy == nullptr) {
        IMSA_HILOGE("failed to get imsa proxy!");
        return false;
    }
    return proxy->ExitCurrentInputType();
}

int32_t InputMethodAbility::IsPanelShown(const PanelInfo &panelInfo, bool &isShown)
{
    isShown = false;
    auto result = panels_.Find(panelInfo.panelType);
    if (!result.first) {
        IMSA_HILOGI("panel type: %{public}d not found.", static_cast<int32_t>(panelInfo.panelType));
        return ErrorCode::NO_ERROR;
    }
    auto panel = result.second;
    if (panel->GetPanelType() == PanelType::SOFT_KEYBOARD && panel->GetPanelFlag() != panelInfo.panelFlag) {
        IMSA_HILOGI("queried flag: %{public}d, current flag: %{public}d, panel not found.",
            static_cast<int32_t>(panelInfo.panelFlag), static_cast<int32_t>(panel->GetPanelFlag()));
        return ErrorCode::NO_ERROR;
    }
    isShown = panel->IsShowing();
    IMSA_HILOGI("type: %{public}d, flag: %{public}d, result: %{public}d.", static_cast<int32_t>(panelInfo.panelType),
        static_cast<int32_t>(panelInfo.panelFlag), isShown);
    return ErrorCode::NO_ERROR;
}

void InputMethodAbility::OnClientInactive(const sptr<IRemoteObject> &channel)
{
    IMSA_HILOGI("client inactive.");
    if (imeListener_ != nullptr) {
        imeListener_->OnInputFinish();
    }
    panels_.ForEach([this](const PanelType &panelType, const std::shared_ptr<InputMethodPanel> &panel) {
        if (panelType != PanelType::SOFT_KEYBOARD || panel->GetPanelFlag() != PanelFlag::FLG_FIXED) {
            HidePanel(panel);
        }
        return false;
    });
    ClearDataChannel(channel);
}

void InputMethodAbility::NotifyKeyboardHeight(uint32_t panelHeight, PanelFlag panelFlag)
{
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return;
    }
    IMSA_HILOGD("notify panel height: %{public}u, flag: %{public}d.", panelHeight, static_cast<int32_t>(panelFlag));
    if (panelFlag != PanelFlag::FLG_FIXED) {
        channel->NotifyKeyboardHeight(0);
        return;
    }
    channel->NotifyKeyboardHeight(panelHeight);
}

int32_t InputMethodAbility::SendPrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    if (!IsDefaultIme()) {
        IMSA_HILOGE("current is not default ime.");
        return ErrorCode::ERROR_NOT_DEFAULT_IME;
    }
    if (!TextConfig::IsPrivateCommandValid(privateCommand)) {
        IMSA_HILOGE("privateCommand is limit 32KB, count limit 5!");
        return ErrorCode::ERROR_INVALID_PRIVATE_COMMAND_SIZE;
    }
    if (TextConfig::IsSystemPrivateCommand(privateCommand)) {
        auto systemChannel = GetSystemCmdChannelProxy();
        if (systemChannel == nullptr) {
            IMSA_HILOGE("channel is nullptr!");
            return ErrorCode::ERROR_SYSTEM_CMD_CHANNEL_ERROR;
        }
        return systemChannel->SendPrivateCommand(privateCommand);
    } else {
        auto channel = GetInputDataChannelProxy();
        if (channel == nullptr) {
            IMSA_HILOGE("channel is nullptr!");
            return ErrorCode::ERROR_CLIENT_NULL_POINTER;
        }
        return channel->SendPrivateCommand(privateCommand);
    }
}

int32_t InputMethodAbility::ReceivePrivateCommand(
    const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    if (!IsDefaultIme()) {
        IMSA_HILOGE("current is not default ime!");
        return ErrorCode::ERROR_NOT_DEFAULT_IME;
    }
    if (imeListener_ == nullptr) {
        IMSA_HILOGE("imeListener is nullptr!");
        return ErrorCode::ERROR_IME;
    }
    imeListener_->ReceivePrivateCommand(privateCommand);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodAbility::SetPreviewText(const std::string &text, const Range &range)
{
    InputMethodSyncTrace tracer("IMA_SetPreviewText");
    auto dataChannel = GetInputDataChannelProxy();
    if (dataChannel == nullptr) {
        IMSA_HILOGE("dataChannel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return dataChannel->SetPreviewText(text, range);
}

int32_t InputMethodAbility::FinishTextPreview(bool isAsync)
{
    InputMethodSyncTrace tracer("IMA_FinishTextPreview");
    auto dataChannel = GetInputDataChannelProxy();
    if (dataChannel == nullptr) {
        IMSA_HILOGE("dataChannel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    return dataChannel->FinishTextPreview(isAsync);
}

int32_t InputMethodAbility::GetCallingWindowInfo(CallingWindowInfo &windowInfo)
{
    IMSA_HILOGD("IMA start.");
    auto channel = GetInputDataChannelProxy();
    if (channel == nullptr) {
        IMSA_HILOGE("channel is nullptr!");
        return ErrorCode::ERROR_CLIENT_NOT_FOUND;
    }
    auto panel = GetSoftKeyboardPanel();
    if (panel == nullptr) {
        IMSA_HILOGE("panel not found!");
        return ErrorCode::ERROR_PANEL_NOT_FOUND;
    }
    TextTotalConfig textConfig;
    int32_t ret = GetTextConfig(textConfig);
    if (ret != ErrorCode::NO_ERROR || textConfig.windowId == ANCO_INVALID_WINDOW_ID) {
        IMSA_HILOGE("failed to get window id, ret: %{public}d!", ret);
        return ErrorCode::ERROR_GET_TEXT_CONFIG;
    }
    ret = panel->SetCallingWindow(textConfig.windowId);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to set calling window, ret: %{public}d!", ret);
        return ret;
    }
    ret = panel->GetCallingWindowInfo(windowInfo);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get calling window, ret: %{public}d", ret);
    }
    return ret;
}
} // namespace MiscServices
} // namespace OHOS