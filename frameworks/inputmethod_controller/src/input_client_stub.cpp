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

#include "input_client_stub.h"

#include "global.h"
#include "ipc_object_stub.h"
#include "ipc_types.h"
#include "itypes_util.h"
#include "message.h"

namespace OHOS {
namespace MiscServices {
    InputClientStub::InputClientStub()
    {
    }

    InputClientStub::~InputClientStub()
    {
    }

    int32_t InputClientStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                             MessageOption &option)
    {
        IMSA_HILOGI("InputClientStub::OnRemoteRequest. code = %{public}u", code);
        auto descriptorToken = data.ReadInterfaceToken();
        if (descriptorToken != GetDescriptor()) {
            return ErrorCode::ERROR_STATUS_UNKNOWN_TRANSACTION;
        }
        switch (code) {
            case ON_INPUT_READY: {
                if (!msgHandler) {
                    break;
                }
                MessageParcel *parcel = new MessageParcel();
                parcel->WriteRemoteObject(data.ReadRemoteObject());

                Message *msg = new Message(MessageID::MSG_ID_ON_INPUT_READY, parcel);
                msgHandler->SendMessage(msg);
                break;
            }
            case ON_INPUT_RELEASED: {
                if (!msgHandler) {
                    break;
                }
                MessageParcel *parcel = new MessageParcel();
                parcel->WriteInt32(data.ReadInt32());
                Message *msg = new Message(MessageID::MSG_ID_EXIT_SERVICE, parcel);
                msgHandler->SendMessage(msg);
                break;
            }
            case SET_DISPLAY_MODE: {
                if (!msgHandler) {
                    break;
                }
                MessageParcel *parcel = new MessageParcel();
                parcel->WriteInt32(data.ReadInt32());
                Message *msg = new Message(MessageID::MSG_ID_SET_DISPLAY_MODE, parcel);
                msgHandler->SendMessage(msg);
                break;
            }
            case ON_SWITCH_INPUT: {
                OnSwitchInputOnRemote(data, reply);
                break;
            }
            default:
                return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
        return NO_ERROR;
    }

    void InputClientStub::OnSwitchInputOnRemote(MessageParcel &data, MessageParcel &reply)
    {
        IMSA_HILOGI("InputClientStub::OnSwitchInputOnRemote");
        auto *parcel = new (std::nothrow) MessageParcel();
        if (parcel == nullptr) {
            IMSA_HILOGE("parcel is nullptr");
            reply.WriteInt32(ErrorCode::ERROR_EX_NULL_POINTER);
            return;
        }
        Property property;
        SubProperty subProperty;
        if (!ITypesUtil::Unmarshal(data, property, subProperty)) {
            IMSA_HILOGE("read message parcel failed");
            reply.WriteInt32(ErrorCode::ERROR_EX_PARCELABLE);
            return;
        }
        if (!ITypesUtil::Marshal(*parcel, property, subProperty)) {
            IMSA_HILOGE("write message parcel failed");
            reply.WriteInt32(ErrorCode::ERROR_EX_PARCELABLE);
            return;
        }
        auto *msg = new (std::nothrow) Message(MessageID::MSG_ID_ON_SWITCH_INPUT, parcel);
        if (msg == nullptr) {
            IMSA_HILOGE("msg is nullptr");
            delete parcel;
            reply.WriteInt32(ErrorCode::ERROR_EX_NULL_POINTER);
            return;
        }
        MessageHandler::Instance()->SendMessage(msg);
        reply.WriteInt32(ErrorCode::NO_ERROR);
    }

    int32_t InputClientStub::onInputReady(const sptr<IInputMethodAgent>& agent)
    {
        return ErrorCode::NO_ERROR;
    }

    int32_t InputClientStub::onInputReleased(int32_t retValue)
    {
        return ErrorCode::NO_ERROR;
    }

    int32_t InputClientStub::setDisplayMode(int32_t mode)
    {
        return ErrorCode::NO_ERROR;
    }

    void InputClientStub::SetHandler(MessageHandler *handler)
    {
        msgHandler = handler;
    }
} // namespace MiscServices
} // namespace OHOS
