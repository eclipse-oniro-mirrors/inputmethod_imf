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

#ifndef INPUT_METHOD_TAIHE_ANI_COMMON_H
#define INPUT_METHOD_TAIHE_ANI_COMMON_H

#include "securec.h"

#include "input_method_property.h"
#include "input_method_utils.h"
#include "imc_inner_listener.h"
#include "ohos.inputMethod.impl.hpp"
#include "ohos.inputMethod.proj.hpp"
#include "taihe/runtime.hpp"
#include "ui_content.h"
using InputMethodProperty_t = ohos::inputMethod::InputMethodProperty;
using InputMethodSubtype_t = ohos::InputMethodSubtype::InputMethodSubtype;
using PanelInfo_t = ohos::inputMethod::Panel::PanelInfo;
using InputWindowInfo_t = ohos::inputMethod::InputWindowInfo;
using RequestKeyboardReason_t = ohos::inputMethod::RequestKeyboardReason;
using TextConfig_t = ohos::inputMethod::TextConfig;
using Range_t = ohos::inputMethod::Range;
using Movement_t = ohos::inputMethod::Movement;
using KeyboardStatus_t = ohos::inputMethod::KeyboardStatus;
using FunctionKey_t = ohos::inputMethod::FunctionKey;
using ExtendAction_t = ohos::inputMethod::ExtendAction;
using EnterKeyType_t = ohos::inputMethod::EnterKeyType;
using Direction_t = ohos::inputMethod::Direction;
using EnabledState_t = ::ohos::inputMethod::EnabledState;
using MessageHandler_t = ::ohos::inputMethod::MessageHandler;
using InputAttribute_t = ::ohos::inputMethod::InputAttribute;
using UndefinedType_t = ::ohos::inputMethod::UndefinedType;
using AttachFailureReason_t = ohos::inputMethod::AttachFailureReason;
using AttachOptions_t = ohos::inputMethod::AttachOptions;
namespace OHOS {
namespace MiscServices {
constexpr const int32_t SELECT_ALL = 0;
constexpr const int32_t CUT = 3;
constexpr const int32_t COPY = 4;
constexpr const int32_t PASTE = 5;

using callbackType = std::variant<taihe::callback<int32_t()>, taihe::callback<taihe::string(int32_t)>,
    taihe::callback<void(int32_t)>, taihe::callback<void(taihe::string_view)>,
    taihe::callback<void(Range_t const &)>, taihe::callback<void(Movement_t const &)>,
    taihe::callback<void(KeyboardStatus_t const)>, taihe::callback<void(Direction_t const)>,
    taihe::callback<void(FunctionKey_t const &)>, taihe::callback<void(EnterKeyType_t const)>,
    taihe::callback<void(ExtendAction_t const)>, taihe::callback<void(taihe::array_view<InputWindowInfo_t>)>,
    taihe::callback<void(InputMethodProperty_t const &, InputMethodSubtype_t const &)>,
    taihe::callback<void(InputMethodProperty_t const &, InputMethodSubtype_t const &, int32_t)>,
    taihe::callback<void(::taihe::string_view text, ::ohos::inputMethod::Range const& range)>,
    taihe::callback<void(UndefinedType_t const&)>, taihe::callback<void(AttachFailureReason_t)>>;

struct CallbackObject {
    CallbackObject(callbackType cb, ani_ref ref) : callback(cb), ref(ref)
    {
    }
    void Release()
    {
        taihe::env_guard guard;
        if (auto *env = guard.get_env()) {
            env->GlobalReference_Delete(ref);
        }
    }
    callbackType callback;
    ani_ref ref;
};

class GlobalRefGuard {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuard(ani_env *env, ani_object obj) : env_(env)
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
    ~GlobalRefGuard()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
        }
    }

    GlobalRefGuard(const GlobalRefGuard &) = delete;
    GlobalRefGuard &operator=(const GlobalRefGuard &) = delete;
};

class EnumConvert {
public:
    static Direction_t ConvertDirection(Direction direction)
    {
        switch (direction) {
            case Direction::UP:
                return Direction_t::key_t::CURSOR_UP;
            case Direction::DOWN:
                return Direction_t::key_t::CURSOR_DOWN;
            case Direction::LEFT:
                return Direction_t::key_t::CURSOR_LEFT;
            case Direction::RIGHT:
                return Direction_t::key_t::CURSOR_RIGHT;
            default:
                return Direction_t::key_t::CURSOR_UP;
        }
    }

    static ExtendAction_t ConvertExtendAction(int32_t action)
    {
        switch (action) {
            case SELECT_ALL:
                return ExtendAction_t::key_t::SELECT_ALL;
            case CUT:
                return ExtendAction_t::key_t::CUT;
            case COPY:
                return ExtendAction_t::key_t::COPY;
            case PASTE:
                return ExtendAction_t::key_t::PASTE;
            default:
                return ExtendAction_t::key_t::SELECT_ALL;
        }
    }

    static EnterKeyType_t ConvertEnterKeyType(EnterKeyType type)
    {
        switch (type) {
            case EnterKeyType::UNSPECIFIED:
                return EnterKeyType_t::key_t::UNSPECIFIED;
            case EnterKeyType::NONE:
                return EnterKeyType_t::key_t::NONE;
            case EnterKeyType::GO:
                return EnterKeyType_t::key_t::GO;
            case EnterKeyType::SEARCH:
                return EnterKeyType_t::key_t::SEARCH;
            case EnterKeyType::SEND:
                return EnterKeyType_t::key_t::SEND;
            case EnterKeyType::NEXT:
                return EnterKeyType_t::key_t::NEXT;
            case EnterKeyType::DONE:
                return EnterKeyType_t::key_t::DONE;
            case EnterKeyType::PREVIOUS:
                return EnterKeyType_t::key_t::PREVIOUS;
            case EnterKeyType::NEW_LINE:
                return EnterKeyType_t::key_t::NEWLINE;
            default:
                return EnterKeyType_t::key_t::UNSPECIFIED;
        }
    }

    static KeyboardStatus_t ConvertKeyboardStatus(KeyboardStatus status)
    {
        switch (status) {
            case KeyboardStatus::NONE:
                return KeyboardStatus_t::key_t::NONE;
            case KeyboardStatus::SHOW:
                return KeyboardStatus_t::key_t::SHOW;
            case KeyboardStatus::HIDE:
                return KeyboardStatus_t::key_t::HIDE;
            default:
                return KeyboardStatus_t::key_t::NONE;
        }
    }

    static EnabledState_t ConvertEnabledStatus(OHOS::MiscServices::EnabledStatus status)
    {
        switch (status) {
            case EnabledStatus::DISABLED:
                return EnabledState_t::key_t::DISABLED;
            case EnabledStatus::BASIC_MODE:
                return EnabledState_t::key_t::BASIC_MODE;
            case EnabledStatus::FULL_EXPERIENCE_MODE:
                return EnabledState_t::key_t::FULL_EXPERIENCE_MODE;
            default:
                return EnabledState_t::key_t::DISABLED;
        }
    }

    static AttachFailureReason_t ConvertAttachFailureReason(AttachFailureReason reason)
    {
        switch (reason) {
            case AttachFailureReason::CALLER_NOT_FOCUSED:
                return AttachFailureReason_t::key_t::CALLER_NOT_FOCUSED;
            case AttachFailureReason::IME_ABNORMAL:
                return AttachFailureReason_t::key_t::IME_ABNORMAL;
            case AttachFailureReason::SERVICE_ABNORMAL:
                return AttachFailureReason_t::key_t::SERVICE_ABNORMAL;
            default:
                return AttachFailureReason_t::key_t::CALLER_NOT_FOCUSED;
        }
    }

    static ani_object Uint8ArrayToObject(ani_env *env, const std::vector<uint8_t> values)
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

    static void AniTextConfigToNative(TextConfig_t const &textConfig, TextConfig &config)
    {
        config.inputAttribute.inputPattern = textConfig.inputAttribute.textInputType.get_value();
        config.inputAttribute.enterKeyType = textConfig.inputAttribute.enterKeyType.get_value();
        if (textConfig.inputAttribute.placeholder.has_value()) {
            config.inputAttribute.placeholder = Str8ToStr16(std::string(textConfig.inputAttribute.placeholder.value()));
        }
        if (textConfig.inputAttribute.abilityName.has_value()) {
            config.inputAttribute.abilityName = Str8ToStr16(std::string(textConfig.inputAttribute.abilityName.value()));
        }
        if (textConfig.cursorInfo.has_value()) {
            config.cursorInfo.left = textConfig.cursorInfo.value().left;
            config.cursorInfo.top = textConfig.cursorInfo.value().top;
            config.cursorInfo.width = textConfig.cursorInfo.value().width;
            config.cursorInfo.height = textConfig.cursorInfo.value().height;
        }
        if (textConfig.selection.has_value()) {
            config.range.start = textConfig.selection.value().start;
            config.range.end = textConfig.selection.value().end;
        }
        if (textConfig.windowId.has_value()) {
            config.windowId = textConfig.windowId.value();
        }
        if (textConfig.newEditBox.has_value()) {
            config.newEditBox = textConfig.newEditBox.value();
        }
        if (textConfig.capitalizeMode.has_value()) {
            config.inputAttribute.capitalizeMode =
                static_cast<CapitalizeMode>(textConfig.capitalizeMode.value().get_value());
        }
    }

    static bool ParseUiContextGetWindowId(ani_env* env, ani_object uiContext, uint32_t &windowId)
    {
        ani_class cls;
        if (env == nullptr) {
            IMSA_HILOGE("env is nullptr");
            return false;
        }
        ani_int intNum = 0;
        if (ANI_OK != env->Object_GetPropertyByName_Int(uiContext, "instanceId_", &intNum)) {
            IMSA_HILOGE("get instanceId_ failed");
            return false;
        }
        int32_t id = Ace::UIContent::GetUIContentWindowID(intNum);
        if (id < 0) {
            IMSA_HILOGE("failed to get windowId with instanceId: %{public}d", intNum);
            return false;
        }
        windowId = static_cast<uint32_t>(id);
        IMSA_HILOGI("windowId: %{public}u, instanceId: %{public}d", windowId, intNum);
        return true;
    }

    static AttachOptions AniAttachOptionsToNative(const AttachOptions_t &opts)
    {
        AttachOptions options {};
        if (opts.showKeyboard.has_value()) {
            options.isShowKeyboard = opts.showKeyboard.value();
        }
        if (opts.requestKeyboardReason.has_value()) {
            options.requestKeyboardReason =
                static_cast<RequestKeyboardReason>(opts.requestKeyboardReason.value().get_value());
        }
        return options;
    }
};

class PropertyConverter {
public:
    static InputMethodProperty_t ConvertProperty(const std::shared_ptr<Property> &obj)
    {
        return ConvertPropertyImpl(*obj);
    }

    static InputMethodProperty_t ConvertProperty(const Property &obj)
    {
        return ConvertPropertyImpl(obj);
    }

    static InputMethodSubtype_t ConvertSubProperty(const std::shared_ptr<SubProperty> &obj)
    {
        return ConvertSubPropertyImpl(*obj);
    }

    static InputMethodSubtype_t ConvertSubProperty(const SubProperty &obj)
    {
        return ConvertSubPropertyImpl(obj);
    }

private:
    template<typename T>
    static InputMethodProperty_t ConvertPropertyImpl(T &&obj)
    {
        static_assert(std::is_same_v<std::decay_t<T>, Property>, "Invalid type for Property conversion");

        InputMethodProperty_t result{};
        result.name = std::forward<T>(obj).name;
        result.id = obj.id;
        result.label = taihe::optional<taihe::string>(std::in_place_t{}, obj.label);
        result.labelId = taihe::optional<int64_t>(std::in_place_t{}, static_cast<int64_t>(obj.labelId));
        result.icon = taihe::optional<taihe::string>(std::in_place_t{}, obj.icon);
        result.iconId = taihe::optional<int64_t>(std::in_place_t{}, static_cast<int64_t>(obj.iconId));
        result.enabledState = taihe::optional<EnabledState_t>(std::in_place_t{},
            EnumConvert::ConvertEnabledStatus(obj.status));
        return result;
    }

    template<typename T>
    static InputMethodSubtype_t ConvertSubPropertyImpl(T &&obj)
    {
        static_assert(std::is_same_v<std::decay_t<T>, SubProperty>, "Invalid type for SubProperty conversion");

        InputMethodSubtype_t result{};
        result.name = std::forward<T>(obj).name;
        result.id = obj.id;
        result.locale = obj.locale;
        result.language = obj.language;
        result.label = taihe::optional<taihe::string>(std::in_place_t{}, obj.label);
        result.labelId = taihe::optional<double>(std::in_place_t{}, obj.labelId);
        result.icon = taihe::optional<taihe::string>(std::in_place_t{}, obj.icon);
        result.iconId = taihe::optional<double>(std::in_place_t{}, obj.iconId);
        result.mode = taihe::optional<taihe::string>(std::in_place_t{}, obj.mode);
        return result;
    }
};
} // namespace MiscServices
} // namespace OHOS
#endif