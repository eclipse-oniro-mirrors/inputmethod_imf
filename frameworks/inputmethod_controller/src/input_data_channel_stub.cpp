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

#include "input_data_channel_stub.h"
#include "string_ex.h"

namespace OHOS {
namespace MiscServices {
    InputDataChannelStub::InputDataChannelStub() : msgHandler(nullptr)
    {
    }

    InputDataChannelStub::~InputDataChannelStub()
    {
        if (msgHandler != nullptr) {
            delete msgHandler;
            msgHandler = nullptr;
        }
    }

    int32_t InputDataChannelStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option)
    {
        IMSA_HILOGI("InputDataChannelStub::OnRemoteRequest code = %{public}d", code);
        auto descriptorToken = data.ReadInterfaceToken();
        if (descriptorToken != GetDescriptor()) {
            return ErrorCode::ERROR_STATUS_UNKNOWN_TRANSACTION;
        }
        switch (code) {
            case INSERT_TEXT: {
                auto text = data.ReadString16();
                InsertText(text);
                break;
            }
            case DELETE_FORWARD: {
                auto length = data.ReadInt32();
                DeleteForward(length);
                break;
            }
            case DELETE_BACKWARD: {
                auto length = data.ReadInt32();
                DeleteBackward(length);
                break;
            }
            case CLOSE: {
                Close();
                break;
            }
            case GET_TEXT_BEFORE_CURSOR: {
                reply.WriteString16(GetTextBeforeCursor());
                break;
            }
            case GET_TEXT_AFTER_CURSOR: {
                reply.WriteString16(GetTextAfterCursor());
                break;
            }
            case SEND_KEYBOARD_STATUS: {
                auto status = data.ReadInt32();
                SendKeyboardStatus(status);
                break;
            }
            case SEND_FUNCTION_KEY: {
                auto funcKey = data.ReadInt32();
                SendFunctionKey(funcKey);
                break;
            }
            case MOVE_CURSOR: {
                auto keyCode = data.ReadInt32();
                MoveCursor(keyCode);
            }
            default:
                return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
        return NO_ERROR;
    }

    bool InputDataChannelStub::InsertText(const std::u16string& text)
    {
        IMSA_HILOGI("InputDataChannelStub::InsertText");
        if (msgHandler != nullptr) {
            MessageParcel *parcel = new MessageParcel;
            parcel->WriteString16(text);
            Message *msg = new Message(MessageID::MSG_ID_INSERT_CHAR, parcel);
            msgHandler->SendMessage(msg);
            IMSA_HILOGI("InputDataChannelStub::InsertText return true");
            return true;
        }
        return false;
    }

    bool InputDataChannelStub::DeleteForward(int32_t length)
    {
        IMSA_HILOGI("InputDataChannelStub::DeleteForward");
        if (msgHandler == nullptr) {
            return false;
        }
        MessageParcel *parcel = new MessageParcel;
        parcel->WriteInt32(length);
        Message *msg = new Message(MessageID::MSG_ID_DELETE_FORWARD, parcel);
        msgHandler->SendMessage(msg);

        return true;
    }

    bool InputDataChannelStub::DeleteBackward(int32_t length)
    {
        IMSA_HILOGI("InputDataChannelStub::DeleteBackward");
        if (msgHandler != nullptr) {
            MessageParcel *parcel = new MessageParcel;
            parcel->WriteInt32(length);
            Message *msg = new Message(MessageID::MSG_ID_DELETE_BACKWARD, parcel);
            msgHandler->SendMessage(msg);
            return true;
        }
        return false;
    }

    void InputDataChannelStub::Close()
    {
    }

    std::u16string InputDataChannelStub::GetTextBeforeCursor()
    {
        IMSA_HILOGI("InputDataChannelStub::GetTextBeforeCursor");
        return InputMethodController::GetInstance()->GetTextBeforeCursor();
    }

    std::u16string InputDataChannelStub::GetTextAfterCursor()
    {
        IMSA_HILOGI("InputDataChannelStub::GetTextAfterCursor");
        return InputMethodController::GetInstance()->GetTextAfterCursor();
    }

    void InputDataChannelStub::SendKeyboardStatus(int32_t status)
    {
        IMSA_HILOGI("InputDataChannelStub::SendKeyboardStatus");
        if (msgHandler != nullptr) {
            MessageParcel *parcel = new MessageParcel;
            parcel->WriteInt32(status);
            Message *msg = new Message(MessageID::MSG_ID_SEND_KEYBOARD_STATUS, parcel);
            msgHandler->SendMessage(msg);
        }
    }

    void InputDataChannelStub::SendFunctionKey(int32_t funcKey)
    {
        IMSA_HILOGI("InputDataChannelStub::SendFunctionKey");
        if (msgHandler != nullptr) {
            MessageParcel *parcel = new MessageParcel;
            parcel->WriteInt32(funcKey);
            Message *msg = new Message(MessageID::MSG_ID_SEND_FUNCTION_KEY, parcel);
            msgHandler->SendMessage(msg);
        }
    }

    void InputDataChannelStub::MoveCursor(int32_t keyCode)
    {
        IMSA_HILOGI("InputDataChannelStub::MoveCursor");
        if (msgHandler != nullptr) {
            MessageParcel *parcel = new MessageParcel;
            parcel->WriteInt32(keyCode);
            Message *msg = new Message(MessageID::MSG_ID_MOVE_CURSOR, parcel);
            msgHandler->SendMessage(msg);
        }
    }

    void InputDataChannelStub::SetHandler(MessageHandler *handler)
    {
        msgHandler = handler;
    }
}
}