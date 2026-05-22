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
#include <cinttypes>
#include <iostream>
#include <string>

#include "input_method_ability_interface.h"
#include "input_method_types.h"
#include "sys_cfg_parser.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::MiscServices;

class InputMethodEngineListenerImpl : public InputMethodEngineListener {
public:
    InputMethodEngineListenerImpl() = default;
    ~InputMethodEngineListenerImpl() = default;

    void OnKeyboardStatus(bool isShow) override
    {
        std::cout << "[ImeProxyLog] OnKeyboardStatus: isShow=" << (isShow ? "true" : "false") << std::endl;
    }

    void OnInputStart() override
    {
        std::cout << "[ImeProxyLog] OnInputStart triggered " << std::endl;
    }

    int32_t OnInputStop() override
    {
        std::cout << "[ImeProxyLog] OnInputStop triggered" << std::endl;
        return 0;
    }

    void OnInputFinish() override
    {
        std::cout << "[ImeProxyLog] OnInputFinish triggered, count=" << std::endl;
    }

    void OnSetCallingWindow(uint32_t windowId) override
    {
        std::cout << "[ImeProxyLog] OnSetCallingWindow: windowId=" << windowId << std::endl;
    }

    void OnSetSubtype(const SubProperty &property) override
    {
        std::cout << "[ImeProxyLog] OnSetSubtype: id=" << property.id
                  << ", name=" << property.name
                  << ", locale=" << property.locale << std::endl;
    }

    void ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) override
    {
        std::cout << "[ImeProxyLog] ReceivePrivateCommand: commandSize=" << privateCommand.size() << std::endl;
        for (const auto &entry : privateCommand) {
            std::cout << "[ImeProxyLog] key=" << entry.first << std::endl;
        }
    }
};

class KeyboardListenerImpl : public KeyboardListener {
public:
    KeyboardListenerImpl() = default;
    ~KeyboardListenerImpl() = default;

    bool OnDealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId,
        const sptr<IRemoteObject> &channelObject) override
    {
        return false;
    }

    bool OnKeyEvent(int32_t keyCode, int32_t keyStatus, OHOS::sptr<KeyEventConsumerProxy> &consumer) override
    {
        return false;
    }

    bool OnKeyEvent(const std::shared_ptr<OHOS::MMI::KeyEvent> &keyEvent,
        OHOS::sptr<KeyEventConsumerProxy> &consumer) override
    {
        return false;
    }

    void OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height) override
    {
        std::cout << "[ImeProxyLog] OnCursorUpdate: positionX=" << positionX
                  << ", positionY=" << positionY
                  << ", height=" << height << std::endl;
    }

    void OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd) override
    {
        std::cout << "[ImeProxyLog] OnSelectionChange: oldBegin=" << oldBegin
                  << ", oldEnd=" << oldEnd
                  << ", newBegin=" << newBegin
                  << ", newEnd=" << newEnd << std::endl;
    }

    void OnTextChange(const std::string &text) override
    {
        std::cout << "[ImeProxyLog] OnTextChange: text=" << text << std::endl;
    }

    void OnEditorAttributeChange(const InputAttribute &inputAttribute) override
    {
        std::cout << "[ImeProxyLog] OnEditorAttributeChange: " << inputAttribute.ToString() << std::endl;
    }

    void OnFunctionKey(int32_t funcKey) override
    {
        if (funcKey < 0 || funcKey > static_cast<int32_t>(EnterKeyType::NEW_LINE)) {
            std::cout << "[ImeProxyLog] OnFunctionKey: invalid funcKey=" << funcKey << std::endl;
            return;
        }
        std::cout << "[ImeProxyLog] OnFunctionKey: funcKey=" << funcKey << std::endl;
    }
};

int32_t GetAgentUid()
{
    SystemConfig systemConfig;
    SysCfgParser::ParseSystemConfig(systemConfig);
    if (systemConfig.proxyImeUidList.empty()) {
        std::cout << "[ImeProxyLog] No proxy IME UID found in system config" << std::endl;
        return -1;
    }
    int32_t uid = *systemConfig.proxyImeUidList.begin();
    std::cout << "[ImeProxyLog] Got agent UID: " << uid << std::endl;
    return uid;
}

std::string GetUnRegisteredTypeName(UnRegisteredType type)
{
    switch (type) {
        case UnRegisteredType::REMOVE_PROXY_IME:
            return "REMOVE_PROXY_IME";
        case UnRegisteredType::SWITCH_PROXY_IME_TO_IME:
            return "SWITCH_PROXY_IME_TO_IME";
        default:
            return "UNKNOWN";
    }
}

void PrintHelp()
{
    std::cout << "[ImeProxyLog] ========== Command Help ==========" << std::endl;
    std::cout << "[ImeProxyLog] q  - Quit the demo" << std::endl;
    std::cout << "[ImeProxyLog] on - Register proxy IME (requires displayId)" << std::endl;
    std::cout << "[ImeProxyLog] off- Unregister proxy IME (requires displayId and type)" << std::endl;
    std::cout << "[ImeProxyLog]     type values: 0=REMOVE_PROXY_IME, 1=SWITCH_PROXY_IME_TO_IME" << std::endl;
    std::cout << "[ImeProxyLog] i  - Insert text (requires text string)" << std::endl;
    std::cout << "[ImeProxyLog] dl - Delete forward (requires length)" << std::endl;
    std::cout << "[ImeProxyLog] dr - Delete backward (requires length)" << std::endl;
    std::cout << "[ImeProxyLog] m  - Move cursor (requires direction: 1=up, 2=down, 3=left, 4=right)" << std::endl;
    std::cout << "[ImeProxyLog] s  - Select by range (requires start and end)" << std::endl;
    std::cout << "[ImeProxyLog] ====================================" << std::endl;
}

int main()
{
    std::cout << "[ImeProxyLog] ========================================" << std::endl;
    std::cout << "[ImeProxyLog]    Proxy IME Test Demo Starting..." << std::endl;
    std::cout << "[ImeProxyLog] ========================================" << std::endl;

    // Create and set listeners
    std::shared_ptr<InputMethodEngineListenerImpl> imeListener = make_shared<InputMethodEngineListenerImpl>();
    auto instance = InputMethodAbilityInterface::GetInstance();
    instance.SetImeListener(imeListener);
    std::shared_ptr<KeyboardListenerImpl> kdListener = make_shared<KeyboardListenerImpl>();
    instance.SetKdListener(kdListener);

    // Get agent UID and setuid
    int32_t uid = GetAgentUid();
    if (uid == -1) {
        std::cout << "[ImeProxyLog] GetAgentUid failed, please check system config" << std::endl;
        return 0;
    }
    if (setuid(uid) != 0) {
        std::cout << "[ImeProxyLog] Failed to setuid to " << uid << std::endl;
        return 0;
    }
    std::cout << "[ImeProxyLog] Successfully setuid to " << uid << std::endl;

    PrintHelp();

    std::string input;
    int32_t ret = 0;

    while (true) {
        std::cout << "\n[ImeProxyLog] Please enter command (q/on/off/i/dl/dr/m/s): ";
        std::cout.flush();
        std::cin >> input;

        if (input == "q") {
            std::cout << "[ImeProxyLog] Quiting..." << std::endl;
            break;
        } else if (input == "on") {
            uint64_t displayId = 0;
            std::cout << "[ImeProxyLog] Please enter displayId: ";
            std::cout.flush();
            std::cin >> displayId;
            std::cout << "[ImeProxyLog] Calling RegisterProxyIme with displayId=" << displayId << std::endl;

            ret = instance.RegisterProxyIme(displayId);
            std::cout << "[ImeProxyLog] RegisterProxyIme finished, ret=" << ret << std::endl;
        } else if (input == "off") {
            uint64_t displayId = 0;
            int32_t typeValue = 0;

            std::cout << "[ImeProxyLog] Please enter displayId: ";
            std::cout.flush();
            std::cin >> displayId;

            std::cout << "[ImeProxyLog] Please enter UnRegisteredType (0=REMOVE_PROXY_IME, "
                         "1=SWITCH_PROXY_IME_TO_IME): ";
            std::cout.flush();
            std::cin >> typeValue;
            UnRegisteredType type = static_cast<UnRegisteredType>(typeValue);
            std::cout << "[ImeProxyLog] Calling UnregisterProxyIme with displayId=" << displayId
                      << ", type=" << GetUnRegisteredTypeName(type) << " (" << typeValue << ")" << std::endl;

            ret = instance.UnregisterProxyIme(displayId, type);
            std::cout << "[ImeProxyLog] UnregisterProxyIme finished, ret=" << ret << std::endl;
        } else if (input == "i") {
            std::string text;
            std::cout << "[ImeProxyLog] Please enter text to insert: ";
            std::cout.flush();
            std::cin.ignore(); // Clear the newline character from the buffer
            std::getline(std::cin, text);
            std::cout << "[ImeProxyLog] Calling InsertText with text=\"" << text << "\"" << std::endl;

            ret = instance.InsertText(text);
            std::cout << "[ImeProxyLog] InsertText finished, ret=" << ret << std::endl;
        } else if (input == "dl") {
            int32_t length = 0;
            std::cout << "[ImeProxyLog] Please enter delete length: ";
            std::cout.flush();
            std::cin >> length;
            std::cout << "[ImeProxyLog] Calling DeleteForward with length=" << length << std::endl;

            ret = instance.DeleteForward(length);
            std::cout << "[ImeProxyLog] DeleteForward finished, ret=" << ret << std::endl;
        } else if (input == "dr") {
            int32_t length = 0;
            std::cout << "[ImeProxyLog] Please enter delete length: ";
            std::cout.flush();
            std::cin >> length;
            std::cout << "[ImeProxyLog] Calling DeleteBackward with length=" << length << std::endl;

            ret = instance.DeleteBackward(length);
            std::cout << "[ImeProxyLog] DeleteBackward finished, ret=" << ret << std::endl;
        } else if (input == "m") {
            int32_t keyCode = 0;
            std::cout << "[ImeProxyLog] Please enter direction (1=up, 2=down, 3=left, 4=right): ";
            std::cout.flush();
            std::cin >> keyCode;
            std::string directionName;
            switch (keyCode) {
                case 1:
                    directionName = "UP";
                    break;
                case 2:
                    directionName = "DOWN";
                    break;
                case 3:
                    directionName = "LEFT";
                    break;
                case 4:
                    directionName = "RIGHT";
                    break;
                default:
                    directionName = "UNKNOWN";
                    break;
            }
            std::cout << "[ImeProxyLog] Calling MoveCursor with keyCode=" << keyCode
                      << " (" << directionName << ")" << std::endl;

            ret = instance.MoveCursor(keyCode);
            std::cout << "[ImeProxyLog] MoveCursor finished, ret=" << ret << std::endl;
        } else if (input == "s") {
            int32_t start = 0;
            int32_t end = 0;
            std::cout << "[ImeProxyLog] Please enter start position: ";
            std::cout.flush();
            std::cin >> start;

            std::cout << "[ImeProxyLog] Please enter end position: ";
            std::cout.flush();
            std::cin >> end;
            std::cout << "[ImeProxyLog] Calling SelectByRange with start=" << start
                      << ", end=" << end << std::endl;

            ret = instance.SelectByRange(start, end);
            std::cout << "[ImeProxyLog] SelectByRange finished, ret=" << ret << std::endl;
        } else {
            std::cout << "[ImeProxyLog] Unknown command: " << input << std::endl;
            PrintHelp();
        }
    }
    std::cout << "[ImeProxyLog] Demo exited." << std::endl;
    return 0;
}
