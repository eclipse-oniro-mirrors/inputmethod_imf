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

#ifndef SERVICES_INCLUDE_INPUT_ATTRIBUTE_H
#define SERVICES_INCLUDE_INPUT_ATTRIBUTE_H

#include <cstdint>
#include <sstream>

#include "extra_config.h"
#include "parcel.h"

namespace OHOS {
namespace MiscServices {
enum class CapitalizeMode : int32_t {
    NONE = 0,
    SENTENCES,
    WORDS,
    CHARACTERS
};

struct ExtraConfigInner : public Parcelable {
    CustomSettings customSettings = {};
    bool ReadFromParcel(Parcel &in)
    {
        uint32_t size = in.ReadUint32();
        if (size == 0) {
            return true;
        }
        customSettings.clear();

        for (uint32_t index = 0; index < size; index++) {
            std::string key = in.ReadString();
            int32_t valueType = in.ReadInt32();
            if (valueType == static_cast<int32_t>(CustomValueTypeValue::CUSTOM_VALUE_TYPE_STRING)) {
                std::string strValue = in.ReadString();
                customSettings.insert(std::make_pair(key, strValue));
            } else if (valueType == static_cast<int32_t>(CustomValueTypeValue::CUSTOM_VALUE_TYPE_BOOL)) {
                bool boolValue = false;
                boolValue = in.ReadBool();
                customSettings.insert(std::make_pair(key, boolValue));
            } else if (valueType == static_cast<int32_t>(CustomValueTypeValue::CUSTOM_VALUE_TYPE_NUMBER)) {
                int32_t intValue = 0;
                intValue = in.ReadInt32();
                customSettings.insert(std::make_pair(key, intValue));
            }
        }
        return true;
    }

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteUint32(customSettings.size())) {
            return false;
        }
        if (customSettings.size() == 0) {
            return true;
        }
        for (auto &it : customSettings) {
            std::string key = it.first;
            if (!out.WriteString(key)) {
                return false;
            }
            auto value = it.second;
            bool ret = false;
            int32_t valueType = static_cast<int32_t>(value.index());
            if (!out.WriteInt32(valueType)) {
                return false;
            }
            if (valueType == static_cast<int32_t>(CustomValueTypeValue::CUSTOM_VALUE_TYPE_STRING)) {
                auto stringValue = std::get_if<std::string>(&value);
                if (stringValue != nullptr) {
                    ret = out.WriteString(*stringValue);
                }
            } else if (valueType == static_cast<int32_t>(CustomValueTypeValue::CUSTOM_VALUE_TYPE_BOOL)) {
                auto boolValue = std::get_if<bool>(&value);
                if (boolValue != nullptr) {
                    ret = out.WriteBool(*boolValue);
                }
            } else if (valueType == static_cast<int32_t>(CustomValueTypeValue::CUSTOM_VALUE_TYPE_NUMBER)) {
                auto numberValue = std::get_if<int32_t>(&value);
                if (numberValue != nullptr) {
                    ret = out.WriteInt32(*numberValue);
                }
            }
            if (ret == false) {
                return ret;
            }
        }
        return true;
    }

    bool IsMarshallingPass()
    {
        Parcel parcel;
        return Marshalling(parcel);
    }

    static ExtraConfigInner *Unmarshalling(Parcel &in)
    {
        ExtraConfigInner *data = new (std::nothrow) ExtraConfigInner();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
    bool operator==(const ExtraConfigInner &info) const
    {
        return customSettings == info.customSettings;
    }
};

struct InputAttribute {
    static const int32_t PATTERN_TEXT = 0x00000001;
    static const int32_t PATTERN_PASSWORD = 0x00000007;
    static const int32_t PATTERN_PASSWORD_NUMBER = 0x00000008;
    static const int32_t PATTERN_PASSWORD_SCREEN_LOCK = 0x00000009;
    static const int32_t PATTERN_NEWPASSWORD = 0x0000000b;
    static const int32_t PATTERN_ONE_TIME_CODE = 0x0000000d;
    int32_t inputPattern = 0;
    int32_t enterKeyType = 0;
    int32_t inputOption = 0;
    bool isTextPreviewSupported { false };
    std::string bundleName { "" };
    int32_t immersiveMode = 0;
    int32_t gradientMode { 0 };
    int32_t fluidLightMode { 0 };
    uint64_t displayId = 0;        // editor in
    uint32_t windowId = 0;         // keyboard in
    uint64_t callingDisplayId = 0; // keyboard in
    uint64_t displayGroupId = 0;   // keyboard in
    uint64_t callingScreenId = 0;  // keyboard in
    std::u16string placeholder { u"" };
    std::u16string abilityName { u"" };
    CapitalizeMode capitalizeMode = CapitalizeMode::NONE;
    bool needAutoInputNumkey { false }; // number keys need to be automatically handled by imf
    ExtraConfig extraConfig = {};

    bool GetSecurityFlag() const
    {
        return inputPattern == PATTERN_PASSWORD || inputPattern == PATTERN_PASSWORD_SCREEN_LOCK ||
            PATTERN_PASSWORD_NUMBER == inputPattern || PATTERN_NEWPASSWORD == inputPattern;
    }

    bool IsOneTimeCodeFlag() const
    {
        return inputPattern == PATTERN_ONE_TIME_CODE;
    }

    bool IsSecurityImeFlag() const
    {
        return GetSecurityFlag();
    }

    bool operator==(const InputAttribute &info) const
    {
        return inputPattern == info.inputPattern && enterKeyType == info.enterKeyType &&
            inputOption == info.inputOption && isTextPreviewSupported == info.isTextPreviewSupported;
    }

    inline std::string ToString() const
    {
        std::stringstream ss;
        ss << "[" << "inputPattern:" << inputPattern
        << "enterKeyType:" << enterKeyType << "inputOption:" << inputOption
        << "isTextPreviewSupported:" << isTextPreviewSupported << "bundleName:" << bundleName
        << "immersiveMode:" << immersiveMode << "windowId:" << windowId
        << "callingDisplayId:" << callingDisplayId
        << "needNumInput: " << needAutoInputNumkey
        << "extraConfig.customSettings.size: " << extraConfig.customSettings.size()
        << "]";
        return ss.str();
    }

    inline std::string InfoLog() const
    {
        std::string info;
        info.append("pattern/enterKey:" + std::to_string(inputPattern) + "/" + std::to_string(enterKeyType));
        info.append(" windowId/displayId/displayGroupId:" + std::to_string(windowId) + "/"
                    + std::to_string(callingDisplayId) + "/" + std::to_string(displayGroupId));
        info.append(" textPreview/immersiveMode:" + std::to_string(static_cast<int32_t>(isTextPreviewSupported)) + "/"
                    + std::to_string(immersiveMode));
        return info;
    }
};

struct InputAttributeInner : public Parcelable {
    static const int32_t PATTERN_TEXT = 0x00000001;
    static const int32_t PATTERN_PASSWORD = 0x00000007;
    static const int32_t PATTERN_PASSWORD_NUMBER = 0x00000008;
    static const int32_t PATTERN_PASSWORD_SCREEN_LOCK = 0x00000009;
    static const int32_t PATTERN_NEWPASSWORD = 0x0000000b;
    int32_t inputPattern = 0;
    int32_t enterKeyType = 0;
    int32_t inputOption = 0;
    bool isTextPreviewSupported { false };
    std::string bundleName { "" };
    int32_t immersiveMode = 0;
    int32_t gradientMode { 0 };
    int32_t fluidLightMode { 0 };
    uint32_t windowId = 0;         // keyboard in
    uint64_t callingDisplayId = 0; // keyboard in
    uint64_t displayGroupId = 0;   // keyboard in
    std::u16string placeholder { u"" };
    std::u16string abilityName { u"" };
    CapitalizeMode capitalizeMode = CapitalizeMode::NONE;
    bool needAutoInputNumkey { false }; // number keys need to be automatically handled by imf
    ExtraConfigInner extraConfig;

    bool ReadFromParcel(Parcel &in)
    {
        inputPattern = in.ReadInt32();
        enterKeyType = in.ReadInt32();
        inputOption = in.ReadInt32();
        isTextPreviewSupported = in.ReadBool();
        bundleName = in.ReadString();
        immersiveMode = in.ReadInt32();
        windowId = in.ReadUint32();
        callingDisplayId = in.ReadUint64();
        displayGroupId = in.ReadUint64();
        placeholder = in.ReadString16();
        abilityName = in.ReadString16();
        int32_t readCapitalizeMode = in.ReadInt32();
        if (readCapitalizeMode < static_cast<int32_t>(CapitalizeMode::NONE) ||
            readCapitalizeMode > static_cast<int32_t>(CapitalizeMode::CHARACTERS)) {
            readCapitalizeMode = 0;
        }
        capitalizeMode = static_cast<CapitalizeMode>(readCapitalizeMode);
        needAutoInputNumkey = in.ReadBool();
        gradientMode = in.ReadInt32();
        fluidLightMode = in.ReadInt32();
        std::unique_ptr<ExtraConfigInner> extraConfigInfo(in.ReadParcelable<ExtraConfigInner>());
        if (extraConfigInfo == nullptr) {
            return false;
        }
        extraConfig = *extraConfigInfo;
        return true;
    }

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteInt32(inputPattern)) {
            return false;
        }
        if (!out.WriteInt32(enterKeyType)) {
            return false;
        }
        if (!out.WriteInt32(inputOption)) {
            return false;
        }
        if (!out.WriteBool(isTextPreviewSupported)) {
            return false;
        }
        if (!out.WriteString(bundleName)) {
            return false;
        }
        if (!out.WriteInt32(immersiveMode)) {
            return false;
        }
        if (!out.WriteUint32(windowId)) {
            return false;
        }
        if (!out.WriteUint64(callingDisplayId)) {
            return false;
        }
        if (!out.WriteUint64(displayGroupId)) {
            return false;
        }
        auto ret = out.WriteString16(placeholder) && out.WriteString16(abilityName);
        ret = ret && out.WriteInt32(static_cast<int32_t>(capitalizeMode));
        ret = ret && out.WriteBool(needAutoInputNumkey);
        ret = ret && out.WriteInt32(gradientMode);
        ret = ret && out.WriteInt32(fluidLightMode);
        if (!out.WriteParcelable(&extraConfig)) {
            return false;
        }
        return ret;
    }

    static InputAttributeInner *Unmarshalling(Parcel &in)
    {
        InputAttributeInner *data = new (std::nothrow) InputAttributeInner();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }

    bool operator==(const InputAttributeInner &info) const
    {
        return inputPattern == info.inputPattern && enterKeyType == info.enterKeyType &&
            inputOption == info.inputOption && isTextPreviewSupported == info.isTextPreviewSupported;
    }

    bool GetSecurityFlag() const
    {
        return inputPattern == PATTERN_PASSWORD || inputPattern == PATTERN_PASSWORD_SCREEN_LOCK ||
            PATTERN_PASSWORD_NUMBER == inputPattern || PATTERN_NEWPASSWORD == inputPattern;
    }
};
} // namespace MiscServices
} // namespace OHOS

#endif // SERVICES_INCLUDE_INPUT_ATTRIBUTE_H
