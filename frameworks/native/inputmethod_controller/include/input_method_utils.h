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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_METHOD_UTILS_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_METHOD_UTILS_H

#include <stdint.h>
#include <variant>

#include "global.h"
#include "input_attribute.h"
#include "iremote_object.h"
#include "panel_info.h"
#include "key_event.h"

namespace OHOS {
namespace MiscServices {
constexpr uint32_t INVALID_WINDOW_ID = 0;
constexpr int32_t INVALID_VALUE = -1;
constexpr size_t MAX_PRIVATE_COMMAND_SIZE = 32 * 1024; // 32K
constexpr size_t MAX_PRIVATE_COMMAND_COUNT = 5;
constexpr size_t MAX_VALUE_MAP_COUNT = 256;
constexpr size_t MAX_ARRAY_BUFFER_MSG_ID_SIZE = 256; // 256B
constexpr size_t MAX_ARRAY_BUFFER_MSG_PARAM_SIZE = 128 * 1024; // 128KB
static constexpr uint64_t INVALID_DISPLAY_ID = -1ULL;
const constexpr char *SYSTEM_CMD_KEY = "sys_cmd";
enum class EnterKeyType {
    UNSPECIFIED = 0,
    NONE,
    GO,
    SEARCH,
    SEND,
    NEXT,
    DONE,
    PREVIOUS,
    NEW_LINE,
};

enum class TextInputType {
    NONE = -1,
    TEXT = 0,
    MULTILINE,
    NUMBER,
    PHONE,
    DATETIME,
    EMAIL_ADDRESS,
    URL,
    VISIBLE_PASSWORD,
    NUMBER_PASSWORD,
    SCREEN_LOCK_PASSWORD,
    USER_NAME,
    NEW_PASSWORD,
    NUMBER_DECIMAL,
    ONE_TIME_CODE,
};

enum class Direction {
    NONE = 0,
    UP = 1,
    DOWN,
    LEFT,
    RIGHT,
};

enum class SecurityMode : int32_t {
    BASIC = 0,
    FULL = 1,
};

enum class ExtendAction {
    SELECT_ALL = 0,
    CUT = 3,
    COPY,
    PASTE,
};

enum class CapacityType: int32_t {
    IMMERSIVE_EFFECT,
    END,
};

class Configuration {
public:
    EnterKeyType GetEnterKeyType() const
    {
        return enterKeyType;
    }

    void SetEnterKeyType(EnterKeyType keyType)
    {
        enterKeyType = keyType;
    }

    TextInputType GetTextInputType() const
    {
        return textInputType;
    }

    void SetTextInputType(TextInputType textType)
    {
        textInputType = textType;
    }

private:
    EnterKeyType enterKeyType = EnterKeyType::UNSPECIFIED;
    TextInputType textInputType = TextInputType::TEXT;
};

struct CursorInfo {
    double left = -1.0;
    double top = -1.0;
    double width = -1.0;
    double height = -1.0;
    bool operator==(const CursorInfo &info) const
    {
        return (left == info.left && top == info.top && width == info.width && height == info.height);
    }
};

struct CursorInfoInner : public Parcelable {
    double left = -1.0;
    double top = -1.0;
    double width = -1.0;
    double height = -1.0;
    bool operator==(const CursorInfoInner &info) const
    {
        return (left == info.left && top == info.top && width == info.width && height == info.height);
    }

    bool ReadFromParcel(Parcel &in)
    {
        left = in.ReadDouble();
        top = in.ReadDouble();
        width = in.ReadDouble();
        height = in.ReadDouble();
        return true;
    }

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteDouble(left)) {
            return false;
        }
    
        if (!out.WriteDouble(top)) {
            return false;
        }
    
        if (!out.WriteDouble(width)) {
            return false;
        }
    
        if (!out.WriteDouble(height)) {
            return false;
        }
        return true;
    }

    static CursorInfoInner *Unmarshalling(Parcel &in)
    {
        CursorInfoInner *data = new (std::nothrow) CursorInfoInner();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
};

class KeyEvent { };

enum class KeyboardStatus : int32_t {
    NONE = 0,
    HIDE,
    SHOW
}; // soft keyboard

enum Trigger : int32_t {
    IME_APP,
    IMF,
    END
};

struct PanelStatusInfo {
    PanelInfo panelInfo;
    bool visible { false };
    Trigger trigger { END };
    uint32_t sessionId { 0 };
    bool operator==(const PanelStatusInfo &info) const
    {
        return info.panelInfo.panelFlag == panelInfo.panelFlag && info.panelInfo.panelType == panelInfo.panelType &&
            info.visible == visible && info.trigger == trigger;
    }
};

struct PanelStatusInfoInner : public Parcelable {
    PanelInfo panelInfo;
    bool visible { false };
    Trigger trigger { END };
    uint32_t sessionId { 0 };
    bool operator==(const PanelStatusInfoInner &info) const
    {
        return info.panelInfo.panelFlag == panelInfo.panelFlag && info.panelInfo.panelType == panelInfo.panelType &&
            info.visible == visible && info.trigger == trigger;
    }

    bool ReadFromParcel(Parcel &in);
    bool Marshalling(Parcel &out) const;
    static PanelStatusInfoInner *Unmarshalling(Parcel &in);
};

class FunctionKey {
public:
    EnterKeyType GetEnterKeyType() const
    {
        return enterKeyType;
    }

    void SetEnterKeyType(EnterKeyType keyType)
    {
        enterKeyType = keyType;
    }

private:
    EnterKeyType enterKeyType = EnterKeyType::UNSPECIFIED;
};

struct Range {
    int32_t start = INVALID_VALUE;
    int32_t end = INVALID_VALUE;
    bool operator==(const Range &range) const
    {
        return start == range.start && end == range.end;
    }
};

struct RangeInner : public Parcelable {
    int32_t start = INVALID_VALUE;
    int32_t end = INVALID_VALUE;
    bool operator==(const RangeInner &range) const
    {
        return start == range.start && end == range.end;
    }
    bool ReadFromParcel(Parcel &in)
    {
        start = in.ReadInt32();
        end = in.ReadInt32();
        return true;
    }
    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteInt32(start)) {
            return false;
        }
    
        if (!out.WriteInt32(end)) {
            return false;
        }
        return true;
    }
    static RangeInner *Unmarshalling(Parcel &in)
    {
        RangeInner *data = new (std::nothrow) RangeInner();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
};

struct TextSelection {
    int32_t oldBegin = INVALID_VALUE;
    int32_t oldEnd = INVALID_VALUE;
    int32_t newBegin = INVALID_VALUE;
    int32_t newEnd = INVALID_VALUE;
};

struct TextSelectionInner : public Parcelable {
    int32_t oldBegin = INVALID_VALUE;
    int32_t oldEnd = INVALID_VALUE;
    int32_t newBegin = INVALID_VALUE;
    int32_t newEnd = INVALID_VALUE;

    bool ReadFromParcel(Parcel &in);
    bool Marshalling(Parcel &out) const;
    static TextSelectionInner *Unmarshalling(Parcel &in);
};

enum PrivateDataValueType : int32_t {
    VALUE_TYPE_STRING = 0,
    VALUE_TYPE_BOOL,
    VALUE_TYPE_NUMBER
};
using PrivateDataValue = std::variant<std::string, bool, int32_t>;
using ValueMap = std::unordered_map<std::string, PrivateDataValue>;

struct Value : public Parcelable {
    Value(const std::unordered_map<std::string, PrivateDataValue>& map) : valueMap(map) {}
    Value() = default;
    bool ReadFromParcel(Parcel &in);
    bool Marshalling(Parcel &out) const override;
    static Value *Unmarshalling(Parcel &in);

    ValueMap valueMap;
};

struct KeyEventValue : public Parcelable {
    bool ReadFromParcel(Parcel &in);
    bool Marshalling(Parcel &out) const override;
    static KeyEventValue *Unmarshalling(Parcel &in);

    std::shared_ptr<MMI::KeyEvent> event;
};

enum class RequestKeyboardReason : int32_t {
    NONE = 0,          // no event reason
    MOUSE = 1,         // user triggered mouse event
	TOUCH = 2,         // user triggered touch event
    OTHER = 20         // other reason
};

struct TextTotalConfig {
public:
    InputAttribute inputAttribute = {};
    CursorInfo cursorInfo = {};
    TextSelection textSelection = {};
    uint32_t windowId = INVALID_WINDOW_ID;
    double positionY = 0;
    double height = 0;
    std::unordered_map<std::string, PrivateDataValue> privateCommand = {};
    RequestKeyboardReason requestKeyboardReason = RequestKeyboardReason::NONE;
    sptr<IRemoteObject> abilityToken { nullptr };
    bool isSimpleKeyboardEnabled { false }; // indicates enable basic keyboard or not

    std::string ToString() const
    {
        std::string config;
        config.append("pattern/enterKey/preview: " + std::to_string(inputAttribute.inputPattern) + "/" +
            std::to_string(inputAttribute.enterKeyType) + "/" + std::to_string(inputAttribute.isTextPreviewSupported));
        config.append(" windowId/y/height: " + std::to_string(windowId) + "/" + std::to_string(positionY) + "/" +
            std::to_string(height));
        config.append(
            " oldRange: " + std::to_string(textSelection.oldBegin) + "/" + std::to_string(textSelection.oldEnd));
        config.append(
            " newRange: " + std::to_string(textSelection.newBegin) + "/" + std::to_string(textSelection.newEnd));
        config.append(" cursor: " + std::to_string(cursorInfo.left) + "/" + std::to_string(cursorInfo.top) + "/" +
            std::to_string(cursorInfo.width) + "/" + std::to_string(cursorInfo.height));
        return config;
    }
};

struct TextTotalConfigInner : public Parcelable  {
public:
    InputAttributeInner inputAttribute = {};
    CursorInfoInner cursorInfo = {};
    TextSelectionInner textSelection = {};
    uint32_t windowId = INVALID_WINDOW_ID;
    double positionY = 0;
    double height = 0;
    Value commandValue;
    RequestKeyboardReason requestKeyboardReason = RequestKeyboardReason::NONE;
    bool isSimpleKeyboardEnabled = false;
    sptr<IRemoteObject> abilityToken { nullptr };

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static TextTotalConfigInner *Unmarshalling(Parcel &parcel);

    std::string ToString() const
    {
        std::string config;
        config.append("pattern/enterKey/preview: " + std::to_string(inputAttribute.inputPattern) + "/" +
            std::to_string(inputAttribute.enterKeyType) + "/" + std::to_string(inputAttribute.isTextPreviewSupported));
        config.append(" windowId/y/height: " + std::to_string(windowId) + "/" + std::to_string(positionY) + "/" +
            std::to_string(height));
        config.append(
            " oldRange: " + std::to_string(textSelection.oldBegin) + "/" + std::to_string(textSelection.oldEnd));
        config.append(
            " newRange: " + std::to_string(textSelection.newBegin) + "/" + std::to_string(textSelection.newEnd));
        config.append(" cursor: " + std::to_string(cursorInfo.left) + "/" + std::to_string(cursorInfo.top) + "/" +
            std::to_string(cursorInfo.width) + "/" + std::to_string(cursorInfo.height));
        return config;
    }
};
struct TextConfig {
    InputAttribute inputAttribute = {};
    CursorInfo cursorInfo = {};
    Range range = {};
    uint32_t windowId = INVALID_WINDOW_ID;
    double positionY = 0;
    double height = 0;
    bool newEditBox = false;
    std::unordered_map<std::string, PrivateDataValue> privateCommand = {};
    sptr<IRemoteObject> abilityToken { nullptr };

    std::string ToString() const
    {
        std::string config;
        config.append("pattern/enterKey/preview: " + std::to_string(inputAttribute.inputPattern) + "/" +
            std::to_string(inputAttribute.enterKeyType) + "/" + std::to_string(inputAttribute.isTextPreviewSupported));
        config.append(" windowId/y/height: " + std::to_string(windowId) + "/" + std::to_string(positionY) + "/" +
            std::to_string(height));
        config.append(" range: " + std::to_string(range.start) + "/" + std::to_string(range.end));
        config.append(" cursor: " + std::to_string(cursorInfo.left) + "/" + std::to_string(cursorInfo.top) + "/" +
            std::to_string(cursorInfo.width) + "/" + std::to_string(cursorInfo.height));
        return config;
    }

    static bool IsPrivateCommandValid(const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
    {
        size_t privateCommandSize = privateCommand.size();
        size_t maxSize =
            IsSystemPrivateCommand(privateCommand) ? (MAX_PRIVATE_COMMAND_COUNT + 1) : MAX_PRIVATE_COMMAND_COUNT;
        if (privateCommandSize == 0 || privateCommandSize > maxSize) {
            IMSA_HILOGE("privateCommand size must more than 0 and less than 5.");
            return false;
        }
        size_t totalSize = 0;
        for (const auto &iter : privateCommand) {
            size_t keySize = iter.first.size();
            size_t idx = iter.second.index();
            size_t valueSize = 0;

            if (idx == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_STRING)) {
                auto stringValue = std::get_if<std::string>(&iter.second);
                if (stringValue == nullptr) {
                    IMSA_HILOGE("get stringValue failed.");
                    return false;
                }
                valueSize = (*stringValue).size();
            } else if (idx == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_BOOL)) {
                valueSize = sizeof(bool);
            } else if (idx == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_NUMBER)) {
                valueSize = sizeof(int32_t);
            }
            totalSize = totalSize + keySize + valueSize;
        }
        if (totalSize > MAX_PRIVATE_COMMAND_SIZE) {
            IMSA_HILOGE("totalSize : %{public}zu", totalSize);
            return false;
        }
        return true;
    }
    static bool IsSystemPrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
    {
        IMSA_HILOGD("in.");
        size_t privateCommandSize = privateCommand.size();
        if (privateCommandSize == 0 || privateCommandSize > MAX_PRIVATE_COMMAND_COUNT) {
            IMSA_HILOGE("privateCommand size must more than 0 and less than 5.");
            return false;
        }
        auto it = privateCommand.find(SYSTEM_CMD_KEY);
        if (it != privateCommand.end()) {
            // if privateCommand has the key system_cmd and value is 1, it's a system privateCommand.
            if (it->second.index() == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_NUMBER)) {
                auto numberValue = std::get_if<int32_t>(&it->second);
                if (numberValue == nullptr) {
                    IMSA_HILOGE("get stringValue failed.");
                    return false;
                }
                return *numberValue == 1;
            }
        }
        return false;
    }
};

enum class InputType : int32_t {
    NONE = -1,
    CAMERA_INPUT = 0,
    SECURITY_INPUT,
    VOICE_INPUT,
    VOICEKB_INPUT,
    ONE_TIME_CODE = 13,
    END
};

enum class SwitchTrigger : uint32_t {
    CURRENT_IME = 0,
    SYSTEM_APP,
    IMSA,
    NATIVE_SA
};

struct ArrayBuffer : public Parcelable {
    size_t jsArgc = 0;
    std::string msgId;
    std::vector<uint8_t> msgParam;
    static bool IsSizeValid(const ArrayBuffer &arrayBuffer)
    {
        if (arrayBuffer.msgId.size() > MAX_ARRAY_BUFFER_MSG_ID_SIZE) {
            IMSA_HILOGE("Invalid msgId size: %{public}zu.", arrayBuffer.msgId.size());
            return false;
        }
        if (arrayBuffer.msgParam.size() > MAX_ARRAY_BUFFER_MSG_PARAM_SIZE) {
            IMSA_HILOGE("Invalid msgParam size: %{public}zu.", arrayBuffer.msgParam.size());
            return false;
        }
        return true;
    }
    bool operator==(const ArrayBuffer &arrayBuffer) const
    {
        return jsArgc == arrayBuffer.jsArgc && msgId == arrayBuffer.msgId && msgParam == arrayBuffer.msgParam;
    }

    bool ReadFromParcel(Parcel &in);
    bool Marshalling(Parcel &out) const;
    static ArrayBuffer *Unmarshalling(Parcel &in);
};

struct AttachOptions {
    bool isShowKeyboard = false;
    bool isSimpleKeyboardEnabled = false;
    RequestKeyboardReason requestKeyboardReason { RequestKeyboardReason::NONE };
};
struct ImfCallingWindowInfo {
    uint32_t windowId = INVALID_WINDOW_ID;
    uint64_t displayId = 0;
};

struct DetachOptions {
    uint32_t sessionId{ 0 };
    bool isUnbindFromClient{ false };
    bool isInactiveClient{ false };
    bool isNotifyClientAsync{ false };
};

enum class ResponseDataType : uint64_t { NONE_TYPE = 0, STRING_TYPE, INT32_TYPE };

using ResponseData = std::variant<std::monostate, std::string, int32_t>;

struct ResponseDataInner : public Parcelable {
    bool ReadFromParcel(Parcel &in);
    bool Marshalling(Parcel &out) const override;
    static ResponseDataInner *Unmarshalling(Parcel &in)
    {
        ResponseDataInner *data = new (std::nothrow) ResponseDataInner();
        if (data != nullptr && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
    ResponseData rspData = std::monostate{};
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_METHOD_UTILS_H
