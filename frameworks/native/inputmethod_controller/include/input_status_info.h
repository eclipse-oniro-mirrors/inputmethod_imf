/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_STATUS_INFO_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_STATUS_INFO_H

#include <cstdint>
#include <string>

#include "global.h"
#include "input_window_info.h"
#include "parcel.h"

namespace OHOS {
namespace MiscServices {
enum class InputStartScene : uint32_t {
    ATTACH,
    SHOW_KEYBOARD,
    WINDOW_CHANGED,
    DISPLAY_CHANGED,
    NONE,
};

struct BoundImeInfo : public Parcelable {
    InputWindowStatus status{ InputWindowStatus::HIDE };
    PanelFlag panelFlag{ PanelFlag::FLG_NONE };
    uint64_t displayId{ ImfCommonConst::DEFAULT_DISPLAY_ID };
    bool operator==(const BoundImeInfo &info) const
    {
        return status == info.status && panelFlag == info.panelFlag && displayId == info.displayId;
    }
    std::string ToString() const
    {
        std::string info;
        info.append("[status]: " + std::to_string(static_cast<uint32_t>(status)) + "/");
        info.append("[panelFlag]: " + std::to_string(panelFlag) + "/");
        info.append("[displayId]: " + std::to_string(displayId) + "/");
        return info;
    }

    bool ReadFromParcel(Parcel &in)
    {
        auto statusTmp = in.ReadUint32();
        status = static_cast<InputWindowStatus>(statusTmp);
        auto panelFlagTmp = in.ReadInt32();
        panelFlag = static_cast<PanelFlag>(panelFlagTmp);
        displayId = in.ReadUint64();
        return true;
    }

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteUint32(static_cast<uint32_t>(status))) {
            return false;
        }
        if (!out.WriteInt32(static_cast<int32_t>(panelFlag))) {
            return false;
        }
        return out.WriteUint64(displayId);
    }

    static BoundImeInfo *Unmarshalling(Parcel &in)
    {
        BoundImeInfo *data = new (std::nothrow) BoundImeInfo();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
};

struct BoundClientInfo : public Parcelable {
    uint64_t displayId{ ImfCommonConst::DEFAULT_DISPLAY_ID };
    uint32_t rawWindowId{ ImfCommonConst::INVALID_WINDOW_ID };  // only used in inner
    uint32_t windowId{ ImfCommonConst::INVALID_WINDOW_ID };
    int32_t requestKeyboardReason = 0;
    bool isShowKeyboard{ true }; // only valid in InputStartScene::ATTACH
    std::string ToString() const
    {
        std::string info;
        info.append("[displayId]: " + std::to_string(displayId) + "/");
        info.append("[rawWindowId]: " + std::to_string(rawWindowId) + "/");
        info.append("[windowId]: " + std::to_string(windowId) + "/");
        info.append("[requestKeyboardReason]: " + std::to_string(requestKeyboardReason) + "/");
        info.append("[isShowKeyboard]: " + std::to_string(isShowKeyboard));
        return info;
    }

    bool ReadFromParcel(Parcel &in)
    {
        displayId = in.ReadUint64();
        rawWindowId = in.ReadUint32();
        windowId = in.ReadUint32();
        requestKeyboardReason = in.ReadInt32();
        isShowKeyboard = in.ReadBool();
        return true;
    }

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteUint64(displayId)) {
            return false;
        }
        if (!out.WriteUint32(rawWindowId)) {
            return false;
        }
        if (!out.WriteUint32(windowId)) {
            return false;
        }
        if (!out.WriteInt32(requestKeyboardReason)) {
            return false;
        }
        return out.WriteBool(isShowKeyboard);
    }

    static BoundClientInfo *Unmarshalling(Parcel &in)
    {
        BoundClientInfo *data = new (std::nothrow) BoundClientInfo();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
};

struct InputStartInfo : public Parcelable {
public:
    int32_t userId{ ImfCommonConst::DEFAULT_USER_ID };
    InputStartScene scene{ InputStartScene::NONE };
    BoundClientInfo clientInfo;
    BoundImeInfo imeInfo;
    bool isNewCb = false;  // only used in inner

    bool ReadFromParcel(Parcel &in)
    {
        userId = in.ReadInt32();
        auto sceneTmp = in.ReadUint32();
        scene = static_cast<InputStartScene>(sceneTmp);
        isNewCb = in.ReadBool();
        std::unique_ptr<BoundClientInfo> clientInfoTmp(in.ReadParcelable<BoundClientInfo>());
        if (clientInfoTmp == nullptr) {
            return false;
        }
        clientInfo = *clientInfoTmp;
        std::unique_ptr<BoundImeInfo> imeInfoTmp(in.ReadParcelable<BoundImeInfo>());
        if (imeInfoTmp == nullptr) {
            return false;
        }
        imeInfo = *imeInfoTmp;
        return true;
    }

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteInt32(userId)) {
            return false;
        }
        if (!out.WriteUint32(static_cast<uint32_t>(scene))) {
            return false;
        }
        if (!out.WriteBool(isNewCb)) {
            return false;
        }
        if (!out.WriteParcelable(&clientInfo)) {
            return false;
        }
        return out.WriteParcelable(&imeInfo);
    }

    static InputStartInfo *Unmarshalling(Parcel &in)
    {
        InputStartInfo *data = new (std::nothrow) InputStartInfo();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }

    std::string ToString() const
    {
        std::string info;
        info.append("[userId]: " + std::to_string(userId) + "/");
        info.append("[scene]: " + std::to_string(static_cast<uint32_t>(scene)) + "/");
        info.append("[isNewCb]: " + std::to_string(isNewCb) + "/");
        info.append("[clientInfo]: " + clientInfo.ToString() + "/");
        info.append("[imeInfo]: " + imeInfo.ToString());
        return info;
    }
};

enum class InputStopScene : uint32_t {
    CLIENT_TRIGGER,
    IMSA_DIED,
    IME_DIED,
    NONE,
};

struct InputStopInfo : public Parcelable {
public:
    InputStopScene scene{ InputStopScene::NONE };
    // if scene is IMSA_DIED, the below param is invalid
    int32_t userId{ ImfCommonConst::DEFAULT_USER_ID };
    uint64_t displayId{ ImfCommonConst::DEFAULT_DISPLAY_ID };
    uint64_t displayGroupId{ ImfCommonConst::DEFAULT_DISPLAY_GROUP_ID }; // only used in inner
    bool isRealIme{ true };                                              // only used in inner

    bool ReadFromParcel(Parcel &in)
    {
        auto sceneTmp = in.ReadUint32();
        scene = static_cast<InputStopScene>(sceneTmp);
        userId = in.ReadInt32();
        displayId = in.ReadUint64();
        displayGroupId = in.ReadUint64();
        isRealIme = in.ReadBool();
        return true;
    }

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteUint32(static_cast<uint32_t>(scene))) {
            return false;
        }
        if (!out.WriteInt32(userId)) {
            return false;
        }
        if (!out.WriteUint64(displayId)) {
            return false;
        }
        if (!out.WriteUint64(displayGroupId)) {
            return false;
        }
        return out.WriteBool(isRealIme);
    }

    static InputStopInfo *Unmarshalling(Parcel &in)
    {
        InputStopInfo *data = new (std::nothrow) InputStopInfo();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }

    std::string ToString() const
    {
        std::string info;
        info.append("[scene]: " + std::to_string(static_cast<uint32_t>(scene)) + "/");
        info.append("[userId]: " + std::to_string(userId) + "/");
        info.append("[displayId]: " + std::to_string(displayId) + "/");
        info.append("[displayGroupId]: " + std::to_string(displayGroupId) + "/");
        info.append("[isRealIme]: " + std::to_string(isRealIme));
        return info;
    }
};
} // namespace MiscServices
} // namespace OHOS

#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_STATUS_INFO_H
