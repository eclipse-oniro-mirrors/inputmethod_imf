/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INPUT_METHOD_TAIHE_ANI_COMMON_ENGINE_H
#define INPUT_METHOD_TAIHE_ANI_COMMON_ENGINE_H

#include "input_method_property.h"
#include "input_method_utils.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "ohos.inputMethod.ExtraConfig.proj.hpp"
#include "ohos.inputMethod.ExtraConfig.impl.hpp"
#include "ohos.inputMethodEngine.PanelRect.ani.1.hpp"
#include "ohos.inputMethodEngine.EnhancedPanelRect.ani.1.hpp"
#include "ohos.inputMethodEngine.WindowInfo.ani.1.hpp"
#include "taihe/runtime.hpp"
#include "ani.h"
#include "string_ex.h"
#include "panel_info.h"
#include "wm_common.h"
#include "panel_common.h"
#include "calling_window_info.h"
#include "sys_panel_status.h"
#include "extra_config.h"

using InputMethodSubtype_t = ohos::InputMethodSubtype::InputMethodSubtype;
using EnhancedPanelRect_t = ohos::inputMethodEngine::EnhancedPanelRect;
using ImmersiveMode_t = ohos::inputMethodEngine::ImmersiveMode;
using KeyboardArea_t = ohos::inputMethodEngine::KeyboardArea;
using Movement_t = ohos::inputMethodEngine::Movement;
using Range_t = ohos::inputMethodEngine::Range;
using EditorAttribute_t = ohos::inputMethodEngine::EditorAttribute;
using CapitalizeMode_t = ohos::inputMethodEngine::CapitalizeMode;
using GradientMode_t = ohos::inputMethodEngine::GradientMode;
using FluidLightMode_t = ohos::inputMethodEngine::FluidLightMode;
using CommandDataType_t = ohos::inputMethodEngine::CommandDataType;
using SecurityMode_t = ohos::inputMethodEngine::SecurityMode;
using KeyEventType_t = ohos::inputMethodEngine::KeyEvent;
using KeyEvent_t = ohos::multimodalInput::keyEvent::KeyEvent;
using Action_t = ohos::multimodalInput::keyEvent::Action;
using InputEvent_t = ohos::multimodalInput::inputEvent::InputEvent;
using Key_t = ohos::multimodalInput::keyEvent::Key;
using KeyCode_t = ohos::multimodalInput::keyCode::KeyCode;
using PanelInfo_t = ohos::inputMethodEngine::PanelInfo;
using PanelFlag_t = ohos::inputMethodEngine::PanelFlag;
using PanelRect_t = ohos::inputMethodEngine::PanelRect;
using KeyboardController_t = ohos::inputMethodEngine::weak::KeyboardController;
using InputClient_t = ohos::inputMethodEngine::weak::InputClient;
using Panel_t = ohos::inputMethodEngine::weak::Panel;
using RequestKeyboardReason_t = ohos::inputMethodEngine::RequestKeyboardReason;
using AttachOptions_t = ohos::inputMethodEngine::AttachOptions;
using ImmersiveEffect_t = ohos::inputMethodEngine::ImmersiveEffect;
using ExtendAction_t = ohos::inputMethodEngine::ExtendAction;
using UndefinedType_t = ohos::inputMethodEngine::UndefinedType;
using WindowInfo_t = ohos::inputMethodEngine::WindowInfo;
using SystemPanelInsets_t = ohos::inputMethodEngine::SystemPanelInsets;
using SystemPanelInsetsData_t = ohos::inputMethodEngine::SystemPanelInsetsData;
using FillColorData_t = ohos::inputMethodEngine::FillColorData;
using BackgroundColorData_t = ohos::inputMethodEngine::BackgroundColorData;
using CustomValueType_t = ohos::inputMethod::ExtraConfig::CustomValueType;
using InputMethodExtraConfig_t = ohos::inputMethod::ExtraConfig::InputMethodExtraConfig;
namespace OHOS {
namespace MiscServices {
using ValueMap = std::unordered_map<std::string, PrivateDataValue>;
static constexpr int32_t MAX_INPUT_REGION_LEN = 4;
class TaiheConverter {
public:
    static InputMethodSubtype_t ConvertSubProperty(const SubProperty &property)
    {
        return ConvertSubPropertyImpl(property);
    }

private:
    static InputMethodSubtype_t ConvertSubPropertyImpl(const SubProperty &property)
    {
        InputMethodSubtype_t result {};
        result.name = property.name;
        result.id = property.id;
        result.locale = property.locale;
        result.language = property.language;
        result.label = taihe::optional<taihe::string>(std::in_place_t{}, property.label);
        result.labelId = taihe::optional<double>(std::in_place_t{}, property.labelId);
        result.icon = taihe::optional<taihe::string>(std::in_place_t{}, property.icon);
        result.iconId = taihe::optional<double>(std::in_place_t{}, property.iconId);
        result.mode = taihe::optional<taihe::string>(std::in_place_t{}, property.mode);
        return result;
    }
};

using callbackTypes = std::variant<taihe::callback<void(int32_t)>,
    taihe::callback<void(taihe::map_view<taihe::string, CommandDataType_t>)>, taihe::callback<void(SecurityMode_t)>,
    taihe::callback<void(InputMethodSubtype_t const&)>, taihe::callback<void(KeyboardController_t, InputClient_t)>,
    taihe::callback<void(double, double, double)>, taihe::callback<void(int32_t, int32_t, int32_t, int32_t)>,
    taihe::callback<bool(KeyEventType_t const&)>, taihe::callback<bool(KeyEvent_t const&)>,
    taihe::callback<void(taihe::string_view)>, taihe::callback<void(EditorAttribute_t const&)>,
    taihe::callback<void(uintptr_t, taihe::optional_view<KeyboardArea_t>)>,
    taihe::callback<void(uintptr_t, KeyboardArea_t const&)>, taihe::callback<void(AttachOptions_t const&)>,
    taihe::callback<void(UndefinedType_t const&)>>;

struct CallbackObjects {
    CallbackObjects(callbackTypes cb, ani_ref ref) : callback(cb), ref(ref)
    {
    }
    void Release()
    {
        taihe::env_guard guard;
        if (auto *env = guard.get_env()) {
            env->GlobalReference_Delete(ref);
        }
    }
    callbackTypes callback;
    ani_ref ref;
};

class GlobalRefGuards {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuards(ani_env *env, ani_object obj) : env_(env)
    {
        if (!env_)
            return;
        if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
            ref_ = nullptr;
        }
    }
    explicit operator bool() const
    {
        return ref_ != nullptr;
    }
    ani_ref get() const
    {
        return ref_;
    }
    ~GlobalRefGuards()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
        }
    }

    GlobalRefGuards(const GlobalRefGuards &) = delete;
    GlobalRefGuards &operator=(const GlobalRefGuards &) = delete;
};

class CommonConvert {
public:
    static SecurityMode_t ConvertSecurityMode(SecurityMode mode);
    static ImmersiveMode_t ConvertMode(ImmersiveMode mode);
    static CapitalizeMode_t ConvertCapMode(CapitalizeMode mode);
    static GradientMode_t ConvertGraMode(GradientMode mode);
    static FluidLightMode_t ConvertFLMode(FluidLightMode mode);
    static EditorAttribute_t NativeAttributeToAni(const InputAttribute &inputAttribute);
    static RequestKeyboardReason_t ConvertReason(RequestKeyboardReason reason);
    static AttachOptions_t NativeAttachOptionsToAni(const AttachOptions &opts);
    static ImmersiveEffect AniConvertEffectToNative(ImmersiveEffect_t const& effect);
    static ValueMap AniConvertPCommandToNative(taihe::map_view<taihe::string, CommandDataType_t> commandData);
    static CommandDataType_t ConvertToDataType(const PrivateDataValue &value);
    static taihe::map<taihe::string, CommandDataType_t> NativeConvertPCommandToAni(const ValueMap &valueMap);
    static PanelInfo AniConvertPanelInfoToNative(PanelInfo_t panel);
    static Key_t ToTaiheKey(const std::optional<OHOS::MMI::KeyEvent::KeyItem> &in);
    static taihe::array<Key_t> ToTaiheKeys(const std::vector<OHOS::MMI::KeyEvent::KeyItem> &in);
    static InputEvent_t ToTaiheInputEvent(const std::shared_ptr<OHOS::MMI::KeyEvent> &in);
    static KeyEvent_t ToTaiheKeyEvent(const std::shared_ptr<OHOS::MMI::KeyEvent> &in);
    static ani_object Uint8ArrayToObject(ani_env *env, const std::vector<uint8_t> values);
    static ani_object CreateAniUndefined(ani_env* env);
    static ani_status CallAniMethodVoid(ani_env *env, ani_object object, ani_class cls,
        const char* method, const char* signature, ...);
    static ani_object CreateAniSize(ani_env* env, uint32_t width, uint32_t height);
    static bool GetBooleanOrUndefined(ani_env* env, ani_object param, const char* name, bool& res);
    static bool GetIntObject(ani_env* env, const char* propertyName, ani_object object, int32_t& result);
    static bool GetIntOrUndefined(ani_env* env, ani_object param, const char* name, int32_t& res);
    static bool GetRectOrUndefined(ani_env* env, ani_object param, const char* name, Rosen::Rect& rect);
    static bool GetRegionOrUndefined(ani_env* env, ani_object param, const char* name, std::vector<Rosen::Rect>& rect);
    static bool ParseRect(ani_env *env, ani_object rect, Rosen::Rect &result);
    static bool ParseRects(ani_object aniRects, std::vector<Rosen::Rect> &rects, int32_t maxNum);
    static bool ParseWindowRect(ani_env *env, const char* propertyName, ani_object obj, Rosen::Rect &result);
    static bool ParsePanelRect(ani_env* env, PanelRect_t const& rect, LayoutParams& param);
    static bool ParseEnhancedPanelRect(ani_env* env, EnhancedPanelRect_t const& rect,
        EnhancedLayoutParams& param, HotAreas& hotAreas);
    static ani_enum_item CreateAniWindowStatus(ani_env* env, Rosen::WindowStatus type);
    static ani_object CreateAniRect(ani_env* env, Rosen::Rect rect);
    static SystemPanelInsets_t NativeInsetsToAni(const SystemPanelInsets &insets);
    static Shadow AniConvertShadowToNative(double radius, taihe::string_view color, double offsetX, double offsetY);
    static bool AniFillColorDataToNative(FillColorData_t const &in, std::string &out);
    static bool AniBackgroundColorDataToNative(BackgroundColorData_t const &in, std::string &out);
    static CustomValueType_t ConvertToDataValue(const CustomValueType &value);
    static InputMethodExtraConfig_t NativeCommandToAni(const CustomSettings &valueMap);
};
} // namespace MiscServices
} // namespace OHOS
#endif // INPUT_METHOD_TAIHE_ANI_COMMON_ENGINE_H