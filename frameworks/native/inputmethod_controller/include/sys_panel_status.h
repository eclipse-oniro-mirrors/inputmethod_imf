/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_SYS_PANEL_STATUS_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_SYS_PANEL_STATUS_H

#include <cstdint>

#include "input_method_utils.h"
#include "parcel.h"
#include "panel_info.h"

namespace OHOS {
namespace MiscServices {
struct Shadow : public Parcelable {
    double radius;
    std::string color;
    double offsetX;
    double offsetY;
    Shadow(double radius, std::string color, double offsetX, double offsetY) : radius(radius),
        color(color), offsetX(offsetX), offsetY(offsetY) {}
 
    Shadow() = default;
 
    bool ReadFromParcel(Parcel &in)
    {
        radius = in.ReadDouble();
        color = in.ReadString();
        offsetX = in.ReadDouble();
        offsetY = in.ReadDouble();
        return true;
    }
 
    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteDouble(radius)) {
            return false;
        }
        if (!out.WriteString(color)) {
            return false;
        }
        if (!out.WriteDouble(offsetX)) {
            return false;
        }
        if (!out.WriteDouble(offsetY)) {
            return false;
        }
        return true;
    }
 
    static Shadow *Unmarshalling(Parcel &in)
    {
        Shadow *data = new (std::nothrow) Shadow();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
};

struct SysPanelStatus : public Parcelable {
    InputType inputType = InputType::NONE;
    int32_t flag = FLG_FIXED;
    uint32_t width = 0;
    uint32_t height = 0;
    bool isPanelRaised = true;
    bool needFuncButton = true;

    SysPanelStatus(InputType sysType, int32_t sysFlag, uint32_t sysWidth, uint32_t sysHeight) : inputType(sysType),
        flag(sysFlag), width(sysWidth), height(sysHeight) {}

    SysPanelStatus() = default;

    bool ReadFromParcel(Parcel &in)
    {
        int32_t inputTypeData = in.ReadInt32();
        inputType = static_cast<InputType>(inputTypeData);
        flag = in.ReadInt32();
        width = in.ReadUint32();
        height = in.ReadUint32();
        isPanelRaised = in.ReadBool();
        needFuncButton = in.ReadBool();
        return true;
    }

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteInt32(static_cast<int32_t>(inputType))) {
            return false;
        }
        if (!out.WriteInt32(flag)) {
            return false;
        }
        if (!out.WriteUint32(width)) {
            return false;
        }
        if (!out.WriteUint32(height)) {
            return false;
        }
        if (!out.WriteBool(isPanelRaised)) {
            return false;
        }
        if (!out.WriteBool(needFuncButton)) {
            return false;
        }
        return true;
    }

    static SysPanelStatus *Unmarshalling(Parcel &in)
    {
        SysPanelStatus *data = new (std::nothrow) SysPanelStatus();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
};
} // namespace MiscServices
} // namespace OHOS

#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_SYS_PANEL_STATUS_H
