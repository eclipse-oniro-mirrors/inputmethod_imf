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

#ifndef FM_IMMS_PROJECT_INPUTMETHODABILITY_H
#define FM_IMMS_PROJECT_INPUTMETHODABILITY_H

#include <thread>
#include "js_input_method_engine_listener.h"
#include "iremote_object.h"
#include "i_input_control_channel.h"
#include "i_input_method_core.h"
#include "i_input_data_channel.h"
#include "i_input_method_agent.h"
#include "input_method_core_stub.h"
#include "input_control_channel_proxy.h"
#include "input_attribute.h"
#include "message_handler.h"
#include "input_channel.h"
#include "message.h"
#include "utils.h"
#include "input_method_system_ability_proxy.h"

namespace OHOS {
namespace MiscServices {
    class JsInputMethodEngineListener;
    class MessageHandler;
    class InputMethodAbility : public RefBase {
    public:
        InputMethodAbility();
        ~InputMethodAbility();
        static sptr<InputMethodAbility> GetInstance();
        sptr<IInputMethodCore> OnConnect();
        bool InsertText(const std::string text);
        void setImeListener(sptr<JsInputMethodEngineListener> &imeListener);
        void DeleteForward(int32_t length);
        void DeleteBackward(int32_t length);
        void HideKeyboardSelf();
        std::u16string GetTextBeforeCursor();
        std::u16string GetTextAfterCursor();
        void SendFunctionKey(int32_t funcKey);
        void MoveCursor(int32_t keyCode);
        bool DispatchKeyEvent(int32_t keyCode, int32_t keyStatus);

    private:
        std::thread workThreadHandler;
        MessageHandler *msgHandler;
        bool mSupportPhysicalKbd = false;
        InputAttribute *editorAttribute;
        int32_t displyId = 0;
        sptr<IRemoteObject> startInputToken;
        InputChannel *writeInputChannel;
        bool stop_;
        int32_t KEYBOARD_HIDE = 1;
        int32_t KEYBOARD_SHOW = 2;
        bool isBindClient = false;

        // communicating with IMSA
        sptr<IInputControlChannel> inputControlChannel;
        void SetCoreAndAgent();

        // communicating with IMC
        sptr<IInputDataChannel> inputDataChannel;
        sptr<JsInputMethodEngineListener> imeListener_;
        static std::mutex instanceLock_;
        static sptr<InputMethodAbility> instance_;
        sptr<InputMethodSystemAbilityProxy> mImms;
        sptr<InputMethodSystemAbilityProxy> GetImsaProxy();

        void Initialize();
        void WorkThread();

        // the message from IMSA
        void OnInitialInput(Message *msg);
        void OnStartInput(Message *msg);
        void OnStopInput(Message *msg);
        void OnSetKeyboardType(Message *msg);
        void OnShowKeyboard(Message *msg);
        void OnHideKeyboard(Message *msg);
        void OnInitInputControlChannel(Message *msg);

        // the message from IMC
        void OnCursorUpdate(Message *msg);
        void OnSelectionChange(Message *msg);

        // control inputwindow
        void InitialInputWindow();
        void ShowInputWindow();
        void DissmissInputWindow();
    };
}
}
#endif // FM_IMMS_PROJECT_INPUTMETHODABILITY_H