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
#include "input_method_ability.h"
#include "string_ex.h"
#include "input_method_agent_proxy.h"
#include "input_method_agent_stub.h"
#include "message_parcel.h"
#include "system_ability_definition.h"
#include "input_method_utils.h"
#include "iservice_registry.h"
#include "input_method_core_proxy.h"
#include "input_method_core_stub.h"

namespace OHOS {
namespace MiscServices {
    class MessageHandler;
    using namespace MessageID;
    sptr<InputMethodAbility> InputMethodAbility::instance_;
    std::mutex InputMethodAbility::instanceLock_;

    InputMethodAbility::InputMethodAbility() : stop_(false)
    {
        writeInputChannel = nullptr;
        Initialize();
    }

    InputMethodAbility::~InputMethodAbility()
    {
        IMSA_HILOGI("InputMethodAbility::~InputMethodAbility");
        instance_ = nullptr;
        if (msgHandler) {
            delete msgHandler;
            msgHandler = nullptr;
        }
        stop_ = true;
    }

    sptr<InputMethodAbility> InputMethodAbility::GetInstance()
    {
        IMSA_HILOGI("InputMethodAbility::GetInstance");
        if (!instance_) {
            std::lock_guard<std::mutex> autoLock(instanceLock_);
            if (!instance_) {
                IMSA_HILOGI("InputMethodAbility::GetInstance need new IMA");
                instance_ = new InputMethodAbility();
            }
        }
        return instance_;
    }

    sptr<InputMethodSystemAbilityProxy> InputMethodAbility::GetImsaProxy()
    {
        IMSA_HILOGI("InputMethodAbility::GetImsaProxy");
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (!systemAbilityManager) {
            IMSA_HILOGI("InputMethodAbility::GetImsaProxy systemAbilityManager is nullptr");
            return nullptr;
        }

        auto systemAbility = systemAbilityManager->GetSystemAbility(INPUT_METHOD_SYSTEM_ABILITY_ID, "");
        if (!systemAbility) {
            IMSA_HILOGI("InputMethodAbility::GetImsaProxy systemAbility is nullptr");
            return nullptr;
        }

        sptr<InputMethodSystemAbilityProxy> iface = new InputMethodSystemAbilityProxy(systemAbility);
        return iface;
    }

    void InputMethodAbility::SetCoreAndAgent()
    {
        IMSA_HILOGI("InputMethodAbility::SetCoreAndAgent");
        mImms = GetImsaProxy();
        if (!mImms) {
            IMSA_HILOGI("InputMethodAbility::SetCoreAndAgent() mImms is nullptr");
            return;
        }
        sptr<InputMethodCoreStub> stub = new InputMethodCoreStub(0);
        stub->SetMessageHandler(msgHandler);
        sptr<IInputMethodCore> stub2 = stub;

        sptr<InputMethodAgentStub> inputMethodAgentStub(new InputMethodAgentStub());
        inputMethodAgentStub->SetMessageHandler(msgHandler);
        sptr<IInputMethodAgent> inputMethodAgent = sptr(new InputMethodAgentProxy(inputMethodAgentStub));

        MessageParcel data;
        if (!(data.WriteInterfaceToken(mImms->GetDescriptor())
            && data.WriteRemoteObject(stub2->AsObject())
            && data.WriteRemoteObject(inputMethodAgent->AsObject()))) {
            return;
        }
        mImms->SetCoreAndAgent(data);
    }

    void InputMethodAbility::Initialize()
    {
        IMSA_HILOGI("InputMethodAbility::Initialize");
        msgHandler = new MessageHandler();
        workThreadHandler = std::thread([this] {
            WorkThread();
        });

        SetCoreAndAgent();
    }

    void InputMethodAbility::setImeListener(std::shared_ptr<InputMethodEngineListener> imeListener)
    {
        IMSA_HILOGI("InputMethodAbility::setImeListener");
        if (imeListener_ == nullptr) {
            imeListener_ = imeListener;
        }
    }

    void InputMethodAbility::setKdListener(std::shared_ptr<KeyboardListener> kdListener)
    {
        IMSA_HILOGI("InputMethodAbility::setKdListener");
        if (kdListener_ == nullptr) {
            kdListener_ = kdListener;
        }
    }

    void InputMethodAbility::WorkThread()
    {
        while (!stop_) {
            Message *msg = msgHandler->GetMessage();
            switch (msg->msgId_) {
                case MSG_ID_INITIALIZE_INPUT: {
                    OnInitialInput(msg);
                    break;
                }
                case MSG_ID_INIT_INPUT_CONTROL_CHANNEL: {
                    OnInitInputControlChannel(msg);
                    break;
                }
                case MSG_ID_SET_CLIENT_STATE: {
                    MessageParcel *data = msg->msgContent_;
                    isBindClient = data->ReadBool();
                    break;
                }
                case MSG_ID_START_INPUT: {
                    OnStartInput(msg);
                    break;
                }
                case MSG_ID_STOP_INPUT: {
                    OnStopInput(msg);
                    break;
                }
                case MSG_ID_SHOW_KEYBOARD: {
                    OnShowKeyboard(msg);
                    break;
                }
                case MSG_ID_HIDE_KEYBOARD: {
                    OnHideKeyboard(msg);
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
                case MSG_ID_STOP_INPUT_SERVICE:{
                    MessageParcel *data = msg->msgContent_;
                    std::string imeId = Str16ToStr8(data->ReadString16());
                    if (imeListener_) {
                        imeListener_->OnInputStop(imeId);
                    }
                    break;
                }
                default: {
                    break;
                }
            }
            delete msg;
            msg = nullptr;
        }
    }

    void InputMethodAbility::OnInitialInput(Message *msg)
    {
        IMSA_HILOGI("InputMethodAbility::OnInitialInput");
        MessageParcel *data = msg->msgContent_;
        displyId = data->ReadInt32();
        sptr<IRemoteObject> channelObject = data->ReadRemoteObject();
        if (channelObject == nullptr) {
            IMSA_HILOGI("InputMethodAbility::OnInitialInput channelObject is nullptr");
            return;
        }
        SetInputControlChannel(channelObject);
    }

    void InputMethodAbility::OnInitInputControlChannel(Message *msg)
    {
        IMSA_HILOGI("InputMethodAbility::OnInitInputControlChannel");
        MessageParcel *data = msg->msgContent_;
        sptr<IRemoteObject> channelObject = data->ReadRemoteObject();
        if (channelObject == nullptr) {
            IMSA_HILOGI("InputMethodAbility::OnInitInputControlChannel channelObject is nullptr");
            return;
        }
        SetInputControlChannel(channelObject);
    }

    void InputMethodAbility::OnStartInput(Message *msg)
    {
        IMSA_HILOGI("InputMethodAbility::OnStartInput");
        MessageParcel *data = msg->msgContent_;
        sptr<IRemoteObject> channelObject = data->ReadRemoteObject();
        if (channelObject == nullptr) {
            IMSA_HILOGI("InputMethodAbility::OnStartInput channelObject is nullptr");
            return;
        }
        SetInputDataChannel(channelObject);
        editorAttribute = data->ReadParcelable<InputAttribute>();
        if (!editorAttribute) {
            IMSA_HILOGI("InputMethodAbility::OnStartInput editorAttribute is nullptr");
        }
        mSupportPhysicalKbd = data->ReadBool();
    }

    void InputMethodAbility::OnShowKeyboard(Message *msg)
    {
        IMSA_HILOGI("InputMethodAbility::OnShowKeyboard");
        MessageParcel *data = msg->msgContent_;
        sptr<IRemoteObject> channelObject = data->ReadRemoteObject();
        if (channelObject == nullptr) {
            IMSA_HILOGI("InputMethodAbility::OnShowKeyboard channelObject is nullptr");
            return;
        }
        SetInputDataChannel(channelObject);
        bool isShowKeyboard = data->ReadBool();
        ShowInputWindow(isShowKeyboard);
    }

    void InputMethodAbility::OnHideKeyboard(Message *msg)
    {
        IMSA_HILOGI("InputMethodAbility::OnHideKeyboard");
        DissmissInputWindow();
    }

    void InputMethodAbility::OnStopInput(Message *msg)
    {
        IMSA_HILOGI("InputMethodAbility::OnStopInput");
        if (writeInputChannel) {
            delete writeInputChannel;
            writeInputChannel = nullptr;
        }
    }

    bool InputMethodAbility::DispatchKeyEvent(int32_t keyCode, int32_t keyStatus)
    {
        IMSA_HILOGI("InputMethodAbility::DispatchKeyEvent: key = %{public}d, status = %{public}d", keyCode, keyStatus);
        if (!isBindClient) {
            IMSA_HILOGI("InputMethodAbility::DispatchKeyEvent abort. no client");
            return false;
        }
        if (!kdListener_) {
            IMSA_HILOGI("InputMethodAbility::DispatchKeyEvent kdListener_ is nullptr");
            return false;
        }
        return kdListener_->OnKeyEvent(keyCode, keyStatus);
    }

    void InputMethodAbility::SetCallingWindow(uint32_t windowId)
    {
        IMSA_HILOGI("InputMethodAbility::SetCallingWindow");

        if (!imeListener_) {
            IMSA_HILOGI("InputMethodAbility::SetCallingWindow imeListener_ is nullptr");
            return;
        }
        imeListener_->OnSetCallingWindow(windowId);
        return;
    }

 
    void InputMethodAbility::OnCursorUpdate(Message *msg)
    {
        IMSA_HILOGI("InputMethodAbility::OnCursorUpdate");
        MessageParcel *data = msg->msgContent_;
        int32_t positionX = data->ReadInt32();
        int32_t positionY = data->ReadInt32();
        int32_t height = data->ReadInt32();
        if (!kdListener_) {
            IMSA_HILOGI("InputMethodAbility::OnCursorUpdate kdListener_ is nullptr");
            return;
        }
        kdListener_->OnCursorUpdate(positionX, positionY, height);
    }

    void InputMethodAbility::OnSelectionChange(Message *msg)
    {
        IMSA_HILOGI("InputMethodAbility::OnSelectionChange");
        MessageParcel *data = msg->msgContent_;
        std::string text = Str16ToStr8(data->ReadString16());
        int32_t oldBegin = data->ReadInt32();
        int32_t oldEnd = data->ReadInt32();
        int32_t newBegin = data->ReadInt32();
        int32_t newEnd = data->ReadInt32();

        if (!kdListener_) {
            IMSA_HILOGI("InputMethodAbility::OnSelectionChange kdListener_ is nullptr");
            return;
        }
        kdListener_->OnTextChange(text);

        kdListener_->OnSelectionChange(oldBegin, oldEnd, newBegin, newEnd);
    }

    void InputMethodAbility::ShowInputWindow(bool isShowKeyboard)
    {
        IMSA_HILOGI("InputMethodAbility::ShowInputWindow");
        if (!imeListener_) {
            IMSA_HILOGI("InputMethodAbility::ShowInputWindow imeListener_ is nullptr");
            return;
        }
        imeListener_->OnInputStart();
        if (!isShowKeyboard) {
            IMSA_HILOGI("InputMethodAbility::ShowInputWindow will not show keyboard");
            return;
        }
        imeListener_->OnKeyboardStatus(true);
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::ShowInputWindow channel is nullptr");
            return;
        }
        channel->SendKeyboardStatus(KEYBOARD_SHOW);
    }

    void InputMethodAbility::DissmissInputWindow()
    {
        IMSA_HILOGI("InputMethodAbility::DissmissInputWindow");
        if (!imeListener_) {
            IMSA_HILOGI("InputMethodAbility::DissmissInputWindow imeListener_ is nullptr");
            return;
        }
        imeListener_->OnKeyboardStatus(false);
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::DissmissInputWindow channel is nullptr");
            return;
        }
        channel->SendKeyboardStatus(KEYBOARD_HIDE);
    }

    bool InputMethodAbility::InsertText(const std::string text)
    {
        IMSA_HILOGI("InputMethodAbility::InsertText");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::InsertText channel is nullptr");
            return false;
        }
        return channel->InsertText(Utils::to_utf16(text));
    }

    void InputMethodAbility::DeleteForward(int32_t length)
    {
        IMSA_HILOGI("InputMethodAbility::DeleteForward");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::DeleteForward channel is nullptr");
            return;
        }
        channel->DeleteForward(length);
    }

    void InputMethodAbility::DeleteBackward(int32_t length)
    {
        IMSA_HILOGI("InputMethodAbility::DeleteBackward");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::DeleteBackward channel is nullptr");
            return;
        }
        channel->DeleteBackward(length);
    }

    void InputMethodAbility::SendFunctionKey(int32_t funcKey)
    {
        IMSA_HILOGI("InputMethodAbility::SendFunctionKey");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::SendFunctionKey channel is nullptr");
            return;
        }
        channel->SendFunctionKey(funcKey);
    }

    void InputMethodAbility::HideKeyboardSelf()
    {
        IMSA_HILOGI("InputMethodAbility::HideKeyboardSelf");
        std::shared_ptr<InputControlChannelProxy> controlChannel = GetInputControlChannel();
        if (controlChannel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::HideKeyboardSelf controlChannel is nullptr");
            return;
        }
        controlChannel->hideKeyboardSelf(1);
    }

    std::u16string InputMethodAbility::GetTextBeforeCursor(int32_t number)
    {
        IMSA_HILOGI("InputMethodAbility::GetTextBeforeCursor");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::GetTextBeforeCursor channel is nullptr");
            return u"";
        }
        return channel->GetTextBeforeCursor(number);
    }

    std::u16string InputMethodAbility::GetTextAfterCursor(int32_t number)
    {
        IMSA_HILOGI("InputMethodAbility::GetTextAfterCursor");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::GetTextAfterCursor channel is nullptr");
            return u"";
        }
        return channel->GetTextAfterCursor(number);
    }

    void InputMethodAbility::MoveCursor(int32_t keyCode)
    {
        IMSA_HILOGI("InputMethodAbility::MoveCursor");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::MoveCursor channel is nullptr");
            return;
        }

        channel->MoveCursor(keyCode);
        return;
    }

    int32_t InputMethodAbility::GetEnterKeyType()
    {
        IMSA_HILOGI("InputMethodAbility::GetEnterKeyType");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::GetEnterKeyType channel is nullptr");
            return 0;
        }
        return channel->GetEnterKeyType();
    }

    int32_t InputMethodAbility::GetInputPattern()
    {
        IMSA_HILOGI("InputMethodAbility::GetInputPattern");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::GetInputPattern channel is nullptr");
            return 0;
        }
        return channel->GetInputPattern();
    }

    void InputMethodAbility::StopInput()
    {
        IMSA_HILOGI("InputMethodAbility::StopInput");
        std::shared_ptr<InputDataChannelProxy> channel = GetInputDataChannel();
        if (channel == nullptr) {
            IMSA_HILOGI("InputMethodAbility::StopInput channel is nullptr");
            return;
        }
        channel->StopInput();
    }

    void InputMethodAbility::SetInputDataChannel(sptr<IRemoteObject> &object)
    {
        IMSA_HILOGI("run in SetInputDataChannel");
        std::lock_guard<std::mutex> lock(dataChannelLock_);
        std::shared_ptr<InputDataChannelProxy> channalProxy = std::make_shared<InputDataChannelProxy>(object);
        if (channalProxy == nullptr) {
            IMSA_HILOGI("InputMethodAbility::SetInputDataChannel inputDataChannel is nullptr");
            return;
        }
        dataChannel_ = channalProxy;
    }

    std::shared_ptr<InputDataChannelProxy> InputMethodAbility::GetInputDataChannel()
    {
        std::lock_guard<std::mutex> lock(dataChannelLock_);
        return dataChannel_;
    }

    void InputMethodAbility::SetInputControlChannel(sptr<IRemoteObject> &object)
    {
        IMSA_HILOGI("run in SetInputControlChannel");
        std::lock_guard<std::mutex> lock(controlChannelLock_);
        std::shared_ptr<InputControlChannelProxy> channalProxy = std::make_shared<InputControlChannelProxy>(object);
        if (channalProxy == nullptr) {
            IMSA_HILOGI("InputMethodAbility::SetInputControlChannel inputDataChannel is nullptr");
            return;
        }
        controlChannel_ = channalProxy;
    }

    std::shared_ptr<InputControlChannelProxy> InputMethodAbility::GetInputControlChannel()
    {
        std::lock_guard<std::mutex> lock(controlChannelLock_);
        return controlChannel_;
    }
} // namespace MiscServices
} // namespace OHOS
