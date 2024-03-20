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

#ifndef FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_I_INPUT_METHOD_AGENT_H
#define FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_I_INPUT_METHOD_AGENT_H

#include "global.h"
#include "i_keyevent_consumer.h"
#include "input_method_utils.h"
#include "iremote_broker.h"
#include "key_event.h"

/**
 * brief Definition of interface IInputMethodAgent
 * It defines the remote calls from input client to input method service
 */
namespace OHOS {
namespace MiscServices {
class IInputMethodAgent : public IRemoteBroker {
public:
    enum {
        DISPATCH_KEY_EVENT = FIRST_CALL_TRANSACTION,
        ON_CURSOR_UPDATE,
        ON_SELECTION_CHANGE,
        SET_CALLING_WINDOW_ID,
        SEND_PRIVATE_COMMAND,
        ON_CONFIGURATION_CHANGE,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.miscservices.inputmethod.IInputMethodAgent");

    virtual int32_t DispatchKeyEvent(
        const std::shared_ptr<MMI::KeyEvent> &keyEvent, sptr<IKeyEventConsumer> &consumer) = 0;
    virtual void OnCursorUpdate(int32_t positionX, int32_t positionY, int height) = 0;
    virtual void OnSelectionChange(
        std::u16string text, int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd) = 0;
    virtual void SetCallingWindow(uint32_t windowId) = 0;
    virtual void OnConfigurationChange(const Configuration &config) = 0;
    virtual int32_t SendPrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) = 0;
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_ABILITY_INCLUDE_I_INPUT_METHOD_AGENT_H
