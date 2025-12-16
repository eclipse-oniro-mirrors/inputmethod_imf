/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ani_common_engine.h"

#include <cinttypes>

#include "global.h"

namespace OHOS {
namespace MiscServices {
SecurityMode_t CommonConvert::ConvertSecurityMode(SecurityMode mode)
{
    switch (mode) {
        case SecurityMode::BASIC:
            return SecurityMode_t::key_t::BASIC;
        case SecurityMode::FULL:
            return SecurityMode_t::key_t::FULL;
        default:
            return SecurityMode_t::key_t::BASIC;
    }
}

ImmersiveMode_t CommonConvert::ConvertMode(ImmersiveMode mode)
{
    switch (mode) {
        case ImmersiveMode::NONE_IMMERSIVE:
            return ImmersiveMode_t::key_t::NONE_IMMERSIVE;
        case ImmersiveMode::IMMERSIVE:
            return ImmersiveMode_t::key_t::IMMERSIVE;
        case ImmersiveMode::LIGHT_IMMERSIVE:
            return ImmersiveMode_t::key_t::LIGHT_IMMERSIVE;
        case ImmersiveMode::DARK_IMMERSIVE:
            return ImmersiveMode_t::key_t::DARK_IMMERSIVE;
        default:
            return ImmersiveMode_t::key_t::NONE_IMMERSIVE;
    }
}

CapitalizeMode_t CommonConvert::ConvertCapMode(CapitalizeMode mode)
{
    switch (mode) {
        case CapitalizeMode::NONE:
            return CapitalizeMode_t::key_t::NONE;
        case CapitalizeMode::SENTENCES:
            return CapitalizeMode_t::key_t::SENTENCES;
        case CapitalizeMode::WORDS:
            return CapitalizeMode_t::key_t::WORDS;
        case CapitalizeMode::CHARACTERS:
            return CapitalizeMode_t::key_t::CHARACTERS;
        default:
            return CapitalizeMode_t::key_t::NONE;
    }
}

GradientMode_t CommonConvert::ConvertGraMode(GradientMode mode)
{
    switch (mode) {
        case GradientMode::NONE:
            return GradientMode_t::key_t::NONE;
        case GradientMode::LINEAR_GRADIENT:
            return GradientMode_t::key_t::LINEAR_GRADIENT;
        default:
            return GradientMode_t::key_t::NONE;
    }
}

FluidLightMode_t CommonConvert::ConvertFLMode(FluidLightMode mode)
{
    switch (mode) {
        case FluidLightMode::NONE:
            return FluidLightMode_t::key_t::NONE;
        case FluidLightMode::BACKGROUND_FLUID_LIGHT:
            return FluidLightMode_t::key_t::BACKGROUND_FLUID_LIGHT;
        default:
            return FluidLightMode_t::key_t::NONE;
    }
}

EditorAttribute_t CommonConvert::NativeAttributeToAni(const InputAttribute &inputAttribute)
{
    EditorAttribute_t result {};
    result.inputPattern = inputAttribute.inputPattern;
    result.enterKeyType = inputAttribute.enterKeyType;
    result.isTextPreviewSupported = inputAttribute.isTextPreviewSupported;
    result.bundleName = taihe::optional<taihe::string>(std::in_place_t{}, inputAttribute.bundleName);
    result.immersiveMode = taihe::optional<ImmersiveMode_t>(std::in_place_t{},
        ConvertMode(static_cast<ImmersiveMode>(inputAttribute.immersiveMode)));
    result.windowId = taihe::optional<int32_t>(std::in_place_t{}, inputAttribute.windowId);
    result.displayId = taihe::optional<uint64_t>(std::in_place_t{}, inputAttribute.callingDisplayId);
    result.placeholder = taihe::optional<taihe::string>(std::in_place_t{},
        std::string(Str16ToStr8(inputAttribute.placeholder)));
    result.abilityName = taihe::optional<taihe::string>(std::in_place_t{},
        std::string(Str16ToStr8(inputAttribute.abilityName)));
    result.capitalizeMode = taihe::optional<CapitalizeMode_t>(std::in_place_t{},
        ConvertCapMode(static_cast<CapitalizeMode>(inputAttribute.capitalizeMode)));
    result.gradientMode = taihe::optional<GradientMode_t>(std::in_place_t{},
        ConvertGraMode(static_cast<GradientMode>(inputAttribute.gradientMode)));
    result.fluidLightMode = taihe::optional<FluidLightMode_t>(std::in_place_t{},
        ConvertFLMode(static_cast<FluidLightMode>(inputAttribute.fluidLightMode)));
    return result;
}

RequestKeyboardReason_t CommonConvert::ConvertReason(RequestKeyboardReason reason)
{
    switch (reason) {
        case RequestKeyboardReason::NONE:
            return RequestKeyboardReason_t::key_t::NONE;
        case RequestKeyboardReason::MOUSE:
            return RequestKeyboardReason_t::key_t::MOUSE;
        case RequestKeyboardReason::TOUCH:
            return RequestKeyboardReason_t::key_t::TOUCH;
        default:
            return RequestKeyboardReason_t::key_t::OTHER;
    }
}

AttachOptions_t CommonConvert::NativeAttachOptionsToAni(const AttachOptions &opts)
{
    AttachOptions_t result {};
    result.requestKeyboardReason =
        taihe::optional<RequestKeyboardReason_t>(std::in_place_t{}, ConvertReason(opts.requestKeyboardReason));
    result.isSimpleKeyboardEnabled = taihe::optional<bool>(std::in_place_t{}, opts.isSimpleKeyboardEnabled);
    return result;
}

ImmersiveEffect CommonConvert::AniConvertEffectToNative(ImmersiveEffect_t const& effect)
{
    ImmersiveEffect result {};
    result.gradientHeight = effect.gradientHeight;
    auto gradientMode = effect.gradientMode.get_value();
    if (gradientMode < static_cast<int32_t>(GradientMode::NONE) ||
        gradientMode >= static_cast<int32_t>(GradientMode::END)) {
        IMSA_HILOGW("gradientMode is invalid");
        result.gradientMode = GradientMode::NONE;
    } else {
        result.gradientMode = static_cast<GradientMode>(gradientMode);
    }
    if (effect.fluidLightMode.has_value()) {
        auto fluidLightMode = effect.fluidLightMode.value().get_value();
        if (fluidLightMode < static_cast<int32_t>(FluidLightMode::NONE) ||
            fluidLightMode >= static_cast<int32_t>(FluidLightMode::END)) {
            IMSA_HILOGW("fluidLightMode is invalid");
            result.fluidLightMode = FluidLightMode::NONE;
        } else {
            result.fluidLightMode = static_cast<FluidLightMode>(fluidLightMode);
        }
    }
    return result;
}

ValueMap CommonConvert::AniConvertPCommandToNative(taihe::map_view<taihe::string, CommandDataType_t> commandData)
{
    ValueMap valueMap;
    for (auto &item : commandData) {
        if (item.first.empty()) {
            continue;
        }
        PrivateDataValue value;
        switch (item.second.get_tag()) {
            case CommandDataType_t::tag_t::type_Int:
                value = item.second.get_type_Int_ref();
                break;
            case CommandDataType_t::tag_t::type_String:
                value = std::string(item.second.get_type_String_ref());
                break;
            case CommandDataType_t::tag_t::type_Bool:
                value = item.second.get_type_Bool_ref();
                break;
            default:
                break;
        }
        valueMap.insert(std::make_pair(std::string(item.first), value));
    }
    return valueMap;
}

CommandDataType_t CommonConvert::ConvertToDataType(const PrivateDataValue &value)
{
    size_t idx = value.index();
    if (idx == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_STRING)) {
        auto stringValue = std::get_if<std::string>(&value);
        if (stringValue != nullptr) {
            return CommandDataType_t::make_type_String(*stringValue);
        }
    } else if (idx == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_BOOL)) {
        auto boolValue = std::get_if<bool>(&value);
        if (boolValue != nullptr) {
            return CommandDataType_t::make_type_Bool(*boolValue);
        }
    } else if (idx == static_cast<size_t>(PrivateDataValueType::VALUE_TYPE_NUMBER)) {
        auto numberValue = std::get_if<int32_t>(&value);
        if (numberValue != nullptr) {
            return CommandDataType_t::make_type_Int(*numberValue);
        }
    }
    return CommandDataType_t::make_type_Bool(true);
}

taihe::map<taihe::string, CommandDataType_t> CommonConvert::NativeConvertPCommandToAni(const ValueMap &valueMap)
{
    taihe::map<taihe::string, CommandDataType_t> result(valueMap.size());
    for (const auto &[key, value] : valueMap) {
        result.emplace(key, ConvertToDataType(value));
    }
    return result;
}

PanelInfo CommonConvert::AniConvertPanelInfoToNative(PanelInfo_t panel)
{
    PanelInfo info{};
    info.panelType = static_cast<PanelType>(panel.type.get_value());
    if (panel.flag.has_value()) {
        info.panelFlag = static_cast<PanelFlag>(panel.flag.value().get_value());
    }
    return info;
}

Key_t CommonConvert::ToTaiheKey(const std::optional<OHOS::MMI::KeyEvent::KeyItem> &in)
{
    bool isNull = (in == std::nullopt);
    int32_t keyCode = isNull ? OHOS::MMI::KeyEvent::KEYCODE_UNKNOWN : in->GetKeyCode();
    Key_t out = {
        .code = KeyCode_t::from_value(keyCode),
        .pressedTime = isNull ? 0 : in->GetDownTime(),
        .deviceId = isNull ? 0 : in->GetDeviceId(),
    };
    return out;
}

taihe::array<Key_t> CommonConvert::ToTaiheKeys(const std::vector<OHOS::MMI::KeyEvent::KeyItem> &in)
{
    std::vector<Key_t> resultVec;
    for (const auto &item : in) {
        Key_t result = ToTaiheKey(item);
        resultVec.emplace_back(result);
    }
    return taihe::array<Key_t>(resultVec);
}

InputEvent_t CommonConvert::ToTaiheInputEvent(const std::shared_ptr<OHOS::MMI::KeyEvent> &in)
{
    auto key = in->GetKeyItem();
    bool isNull = (key == std::nullopt);
    InputEvent_t out = {
        .id = isNull ? 0 : in->GetKeyItem()->GetKeyCode(),
        .deviceId = isNull ? 0 : in->GetKeyItem()->GetDeviceId(),
        .actionTime = isNull ? 0 : in->GetKeyItem()->GetDownTime(),
        .screenId = 0,
        .windowId = 0,
    };
    return out;
}

KeyEvent_t CommonConvert::ToTaiheKeyEvent(const std::shared_ptr<OHOS::MMI::KeyEvent> &in)
{
    auto key = in->GetKeyItem();
    int32_t unicodeChar = (key == std::nullopt) ? 0 : static_cast<int32_t>(key->GetUnicode());
    KeyEvent_t out = {
        .base = ToTaiheInputEvent(in),
        .action = Action_t::from_value(in->GetKeyAction()),
        .key = ToTaiheKey(key),
        .unicodeChar = unicodeChar,
        .keys = ToTaiheKeys(in->GetKeyItems()),
        .ctrlKey = in->GetKeyItem(MMI::KeyEvent::KEYCODE_CTRL_RIGHT).has_value(),
        .altKey = in->GetKeyItem(MMI::KeyEvent::KEYCODE_ALT_RIGHT).has_value(),
        .shiftKey = in->GetKeyItem(MMI::KeyEvent::KEYCODE_SHIFT_RIGHT).has_value(),
        .logoKey = in->GetKeyItem(MMI::KeyEvent::KEYCODE_META_RIGHT).has_value(),
        .fnKey = in->GetKeyItem(MMI::KeyEvent::KEYCODE_FN).has_value(),
        .capsLock = in->GetFunctionKey(OHOS::MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY),
        .numLock = in->GetFunctionKey(OHOS::MMI::KeyEvent::NUM_LOCK_FUNCTION_KEY),
        .scrollLock = in->GetFunctionKey(OHOS::MMI::KeyEvent::SCROLL_LOCK_FUNCTION_KEY),
    };
    return out;
}

ani_object CommonConvert::Uint8ArrayToObject(ani_env *env, const std::vector<uint8_t> values)
{
    ani_object aniObject = nullptr;
    ani_class arrayClass;
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return aniObject;
    }
    ani_status retCode = env->FindClass("escompat.Uint8Array", &arrayClass);
    if (retCode != ANI_OK) {
        IMSA_HILOGE("Failed: env->FindClass()");
        return aniObject;
    }
    ani_method arrayCtor;
    retCode = env->Class_FindMethod(arrayClass, "<ctor>", "i:", &arrayCtor);
    if (retCode != ANI_OK) {
        IMSA_HILOGE("Failed: env->Class_FindMethod()");
        return aniObject;
    }
    auto valueSize = values.size();
    retCode = env->Object_New(arrayClass, arrayCtor, &aniObject, valueSize);
    if (retCode != ANI_OK) {
        IMSA_HILOGE("Failed: env->Object_New()");
        return aniObject;
    }
    ani_ref buffer;
    env->Object_GetFieldByName_Ref(aniObject, "buffer", &buffer);
    void *bufData;
    size_t bufLength;
    retCode = env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &bufData, &bufLength);
    if (retCode != ANI_OK) {
        IMSA_HILOGE("Failed: env->ArrayBuffer_GetInfo()");
    }
    if (bufLength < values.size()) {
        IMSA_HILOGE("Buffer overflow prevented: required=%{public}zu, available=%{public}zu",
            values.size(), bufLength);
        return nullptr;
    }
    auto ret = memcpy_s(bufData, bufLength, values.data(), values.size());
    if (ret != 0) {
        IMSA_HILOGE("Failed: memcpy_s");
        return nullptr;
    }
    return aniObject;
}

ani_object CommonConvert::CreateAniUndefined(ani_env* env)
{
    ani_ref aniRef;
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return nullptr;
    }
    env->GetUndefined(&aniRef);
    return static_cast<ani_object>(aniRef);
}

ani_status CommonConvert::CallAniMethodVoid(ani_env *env, ani_object object, ani_class cls,
    const char* method, const char* signature, ...)
{
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return ANI_ERROR;
    }
    ani_method aniMethod;
    ani_status ret = env->Class_FindMethod(cls, method, signature, &aniMethod);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] method:%{public}s not found", method);
        return ret;
    }
    va_list args;
    va_start(args, signature);
    ret = env->Object_CallMethod_Void_V(object, aniMethod, args);
    va_end(args);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] fail to call method:%{public}s", method);
    }
    return ret;
}

ani_object CommonConvert::CreateAniSize(ani_env* env, uint32_t width, uint32_t height)
{
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return nullptr;
    }
    ani_class aniClass;
    ani_status ret = env->FindClass("@ohos.window.window.SizeInternal", &aniClass);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] class not found");
        return CommonConvert::CreateAniUndefined(env);
    }
    ani_method aniCtor;
    ret = env->Class_FindMethod(aniClass, "<ctor>", nullptr, &aniCtor);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] ctor not found");
        return CommonConvert::CreateAniUndefined(env);
    }
    ani_object aniRect;
    ret = env->Object_New(aniClass, aniCtor, &aniRect);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] fail to new obj");
        return CommonConvert::CreateAniUndefined(env);
    }
    CallAniMethodVoid(env, aniRect, aniClass, "<set>width", nullptr, ani_int(width));
    CallAniMethodVoid(env, aniRect, aniClass, "<set>height", nullptr, ani_int(height));
    return aniRect;
}

bool CommonConvert::GetIntObject(ani_env* env, const char* propertyName,
    ani_object object, int32_t& result)
{
    if (env == nullptr || propertyName == nullptr) {
        IMSA_HILOGE("invalid param");
        return false;
    }
    ani_int value;
    ani_status ret = env->Object_GetPropertyByName_Int(object, propertyName, &value);
    if (ret != ANI_OK) {
        IMSA_HILOGE("Object_GetPropertyByName_Int %{public}s Failed, ret : %{public}u",
            propertyName, static_cast<int32_t>(ret));
        return false;
    }
    result = static_cast<int32_t>(value);
    return true;
}

bool CommonConvert::ParseRect(ani_env *env, ani_object rect, Rosen::Rect &result)
{
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return false;
    }
    if (rect == nullptr) {
        IMSA_HILOGE("AniObject is null");
        return false;
    }

    int32_t posX = 0;
    int32_t posY = 0;
    int32_t width = 0;
    int32_t height = 0;
    bool ret_bool = GetIntObject(env, "left", rect, posX);
    ret_bool |= GetIntObject(env, "top", rect, posY);
    ret_bool |= GetIntObject(env, "width", rect, width);
    ret_bool |= GetIntObject(env, "height", rect, height);
    if (!ret_bool) {
        IMSA_HILOGE("GetIntObject Failed");
        return false;
    }
    result.posX_ = posX;
    result.posY_ = posY;
    result.width_ = static_cast<uint32_t>(width);
    result.height_ = static_cast<uint32_t>(height);
    IMSA_HILOGD("rect is [%{public}d, %{public}d, %{public}u, %{public}u]",
        result.posX_, result.posY_, result.width_, result.height_);
    return true;
}

bool CommonConvert::ParseRects(ani_object aniRects, std::vector<Rosen::Rect> &rects, int32_t maxNum)
{
    ani_status status = ANI_ERROR;
    auto *env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("Failed to get ani env");
        return false;
    }
    ani_array aniArray = reinterpret_cast<ani_array>(aniRects);
    if (aniArray == nullptr) {
        IMSA_HILOGE("Failed to change ani array");
        return false;
    }
    ani_size size;
    if ((status = env->Array_GetLength(aniArray, &size)) != ANI_OK) {
        IMSA_HILOGE("Failed to get ani array length, status:%{public}d.", status);
        return false;
    }

    if (size <= 0 || size > static_cast<ani_size>(maxNum)) {
        IMSA_HILOGE("Exceed maximum rects limit, rects size: %{public}zu", size);
        return false;
    }

    for (ani_size i = 0; i < size; i++) {
        ani_ref rectRef;
        status = env->Array_Get(aniArray, i, &rectRef);
        if (status != ANI_OK) {
            IMSA_HILOGE("Get rect ref failed, i:%{public}zu ret: %{public}d", i, status);
            return false;
        }
        Rosen::Rect per;
        if (!ParseRect(env, static_cast<ani_object>(rectRef), per)) {
            IMSA_HILOGE("Parse rect failed, i:%{public}zu", i);
            return false;
        }
        rects.push_back(per);
    }
    return true;
}

bool CommonConvert::ParseWindowRect(ani_env *env, const char* propertyName, ani_object obj, Rosen::Rect &result)
{
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return false;
    }
    ani_ref windowRect;
    ani_status ret = env->Object_GetPropertyByName_Ref(obj, propertyName, &windowRect);
    if (ret != ANI_OK) {
        IMSA_HILOGE("Object_GetPropertyByName_Ref %{public}s Failed, ret : %{public}u",
            propertyName, static_cast<int32_t>(ret));
        return false;
    }

    int32_t posX = 0;
    int32_t posY = 0;
    int32_t width = 0;
    int32_t height = 0;
    bool ret_bool = GetIntObject(env, "left", static_cast<ani_object>(windowRect), posX);
    ret_bool |= GetIntObject(env, "top", static_cast<ani_object>(windowRect), posY);
    ret_bool |= GetIntObject(env, "width", static_cast<ani_object>(windowRect), width);
    ret_bool |= GetIntObject(env, "height", static_cast<ani_object>(windowRect), height);
    if (!ret_bool) {
        IMSA_HILOGE("GetIntObject Failed");
        return false;
    }
    result.posX_ = posX;
    result.posY_ = posY;
    result.width_ = static_cast<uint32_t>(width);
    result.height_ = static_cast<uint32_t>(height);
    IMSA_HILOGD("rect is [%{public}d, %{public}d, %{public}u, %{public}u]",
        result.posX_, result.posY_, result.width_, result.height_);
    return true;
}

bool CommonConvert::ParsePanelRect(ani_env* env, PanelRect_t const& rect, LayoutParams& param)
{
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr");
        return false;
    }
    ani_object obj = static_cast<ani_object>(::taihe::into_ani<PanelRect_t>(env, rect));
    ani_boolean isUndefined;
    ani_status ret = env->Reference_IsUndefined(obj, &isUndefined);
    if (ret != ANI_OK) {
        IMSA_HILOGE("Check PanelRect isUndefined failed, ret: %{public}d", ret);
        return false;
    }
    if (isUndefined) {
        IMSA_HILOGE("PanelRect is undefined");
        return false;
    }
    Rosen::Rect landscapeRect;
    bool ret_bool = ParseWindowRect(env, "landscapeRect", obj, landscapeRect);
    if (!ret_bool) {
        IMSA_HILOGE("ParseRect landscapeRect failed");
        return false;
    }
    Rosen::Rect portraitRect;
    ret_bool = ParseWindowRect(env, "portraitRect", obj, portraitRect);
    if (!ret_bool) {
        IMSA_HILOGE("ParseRect portraitRect failed");
        return false;
    }
    param.landscapeRect = landscapeRect;
    param.portraitRect = portraitRect;
    return true;
}

bool CommonConvert::GetBooleanOrUndefined(ani_env* env, ani_object param, const char* name, bool& res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return false;
    }
    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        IMSA_HILOGD("%{public}s : undefined", name);
        return false;
    }

    ani_boolean result = 0;
    if ((status = env->Object_CallMethodByName_Boolean(
        reinterpret_cast<ani_object>(obj), "unboxed", nullptr, &result)) != ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }

    res = static_cast<bool>(result);
    return true;
}

bool CommonConvert::GetIntOrUndefined(ani_env* env, ani_object param, const char* name, int32_t& res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return false;
    }
    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        IMSA_HILOGD("%{public}s : undefined", name);
        return false;
    }

    ani_int result = 0;
    if ((status = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(obj), "unboxed", nullptr, &result)) !=
        ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }

    res = result;
    return true;
}

bool CommonConvert::GetRectOrUndefined(ani_env* env, ani_object param, const char* name, Rosen::Rect& rect)
{
    ani_ref ref = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return false;
    }
    if ((status = env->Object_GetPropertyByName_Ref(param, name, &ref)) != ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(ref, &isUndefined)) != ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        IMSA_HILOGD("%{public}s : undefined", name);
        return false;
    }
    ani_object obj = static_cast<ani_object>(ref);
    if (!ParseWindowRect(env, name, obj, rect)) {
        IMSA_HILOGD("Parse %{public}s failed", name);
        return false;
    }
    return true;
}

bool CommonConvert::GetRegionOrUndefined(ani_env* env, ani_object param, const char* name,
    std::vector<Rosen::Rect>& rect)
{
    ani_ref ref = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return false;
    }
    if ((status = env->Object_GetPropertyByName_Ref(param, name, &ref)) != ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(ref, &isUndefined)) != ANI_OK) {
        IMSA_HILOGE("status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        IMSA_HILOGD("%{public}s : undefined", name);
        return false;
    }
    ani_object obj = static_cast<ani_object>(ref);
    if (!ParseRects(obj, rect, MAX_INPUT_REGION_LEN)) {
        IMSA_HILOGD("Parse keyboardHotArea failed");
        return false;
    }

    return true;
}

bool CommonConvert::ParseEnhancedPanelRect(ani_env* env, EnhancedPanelRect_t const& rect,
    EnhancedLayoutParams& param, HotAreas& hotAreas)
{
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr");
        return false;
    }
    ani_object obj = ::taihe::into_ani<EnhancedPanelRect_t>(env, rect);
    ani_boolean isUndefined;
    ani_status ret = env->Reference_IsUndefined(obj, &isUndefined);
    if (ret != ANI_OK || isUndefined) {
        IMSA_HILOGE("EnhancedPanelRect isUndefined failed or undefined ret: %{public}d", ret);
        return false;
    }

    // Get the isFullScreen
    bool isFullScreen = false;
    if (GetBooleanOrUndefined(env, obj, "fullScreenMode", isFullScreen)) {
        param.isFullScreen = isFullScreen;
    }

    if (isFullScreen) {
        IMSA_HILOGD("full screen mode, no need to parse rect");
    } else {
        // Get the landscape rect
        Rosen::Rect result;
        if (GetRectOrUndefined(env, obj, "landscapeRect", result)) {
            param.landscape.rect = result;
        }
        // Get the portrait rect
        if (GetRectOrUndefined(env, obj, "portraitRect", result)) {
            param.portrait.rect = result;
        }
    }

    // Get the landscape avoidY
    int32_t landAvoidY;
    if (GetIntOrUndefined(env, obj, "landscapeAvoidY", landAvoidY)) {
        param.landscape.avoidY = landAvoidY;
    }
    // Get the portrait avoidY
    int32_t portAvoidY;
    if (GetIntOrUndefined(env, obj, "portraitAvoidY", portAvoidY)) {
        param.portrait.avoidY = portAvoidY;
    }
    // has landscapeInputRegion -> Get the hotAreas
    std::vector<Rosen::Rect> landRects;
    if (GetRegionOrUndefined(env, obj, "landscapeInputRegion", landRects)) {
        hotAreas.landscape.keyboardHotArea = landRects;
    } else {
        hotAreas.landscape.keyboardHotArea.clear();
    }

    // has portraitInputRegion -> Get the hotAreas
    std::vector<Rosen::Rect> portRects;
    if (GetRegionOrUndefined(env, obj, "portraitInputRegion", portRects)) {
        hotAreas.portrait.keyboardHotArea = portRects;
    } else {
        hotAreas.portrait.keyboardHotArea.clear();
    }
    return true;
}

ani_enum_item CommonConvert::CreateAniWindowStatus(ani_env* env, Rosen::WindowStatus status)
{
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr");
        return nullptr;
    }
    ani_ref aniRef;
    env->GetUndefined(&aniRef);
    ani_enum_item undef = static_cast<ani_enum_item>(aniRef);

    ani_enum enumType;
    ani_status ret = env->FindEnum("@ohos.window.window.WindowStatusType", &enumType);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] WindowStatusType not found");
        return undef;
    }
    ani_enum_item enumItem;
    ret = env->Enum_GetEnumItemByIndex(enumType, ani_int(status), &enumItem);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] get enum item failed");
        return undef;
    }

    return enumItem;
}

ani_object CommonConvert::CreateAniRect(ani_env* env, Rosen::Rect rect)
{
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr");
        return CreateAniUndefined(env);
    }
    ani_class aniClass;
    ani_status ret = env->FindClass("@ohos.window.window.RectInternal", &aniClass);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] class not found");
        return CreateAniUndefined(env);
    }
    ani_method aniCtor;
    ret = env->Class_FindMethod(aniClass, "<ctor>", ":V", &aniCtor);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] ctor not found");
        return CreateAniUndefined(env);
    }
    ani_object aniRect;
    ret = env->Object_New(aniClass, aniCtor, &aniRect);
    if (ret != ANI_OK) {
        IMSA_HILOGE("[ANI] fail to create new obj");
        return CreateAniUndefined(env);
    }
    CallAniMethodVoid(env, aniRect, aniClass, "<set>left", nullptr, ani_int(rect.posX_));
    CallAniMethodVoid(env, aniRect, aniClass, "<set>top", nullptr, ani_int(rect.posY_));
    CallAniMethodVoid(env, aniRect, aniClass, "<set>width", nullptr, ani_int(rect.width_));
    CallAniMethodVoid(env, aniRect, aniClass, "<set>height", nullptr, ani_int(rect.height_));
    return aniRect;
}

WindowInfo_t CommonConvert::NativeWindowInfoToAni(ani_env* env, MiscServices::CallingWindowInfo &windowInfo)
{
    WindowInfo_t info {};
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr");
        return info;
    }
    ani_class cls;
    if (env->FindClass("@ohos.inputMethodEngine.inputMethodEngine._taihe_WindowInfo_inner", &cls) != ANI_OK) {
        IMSA_HILOGE("[ANI] class not found");
        return info;
    }
    ani_method ctor;
    if (env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor) != ANI_OK) {
        IMSA_HILOGE("[ANI] ctor not found");
        return info;
    }
    ani_object aniInfo;
    if (env->Object_New(cls, ctor, &aniInfo) != ANI_OK) {
        IMSA_HILOGE("[ANI] fail to new obj");
        return info;
    }
    CallAniMethodVoid(env, aniInfo, cls, "<set>rect", nullptr, CreateAniRect(env, windowInfo.rect));
    CallAniMethodVoid(env, aniInfo, cls, "<set>status", nullptr, CreateAniWindowStatus(env, windowInfo.status));
    info = taihe::from_ani<WindowInfo_t>(env, aniInfo);
    return info;
}
} // namespace MiscServices
} // namespace OHOS