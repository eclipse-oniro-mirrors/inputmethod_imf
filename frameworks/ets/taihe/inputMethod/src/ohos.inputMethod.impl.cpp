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

#include "ohos.inputMethod.impl.hpp"

#include "ani_common.h"
#include "common_fun_ani.h"
#include "input_method_controller.h"
#include "input_method_controller_impl.h"
#include "input_method_setting_impl.h"
#include "js_utils.h"
#include "ohos.inputMethod.proj.hpp"
#include "stdexcept"
#include "taihe/runtime.hpp"
#include "input_method_impl.h"

using namespace taihe;
using namespace ohos::inputMethod;
using namespace ohos::InputMethodSubtype;
using namespace OHOS::MiscServices;
namespace {
InputMethodSetting GetSetting()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<IMFSettingImpl, InputMethodSetting>();
}

ohos::inputMethod::InputMethodController GetController()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<IMFControllerImpl, ohos::inputMethod::InputMethodController>();
}

InputMethodProperty GetDefaultInputMethod()
{
    InputMethodProperty inputMethodProperty{};
    std::shared_ptr<Property> property;
    int32_t ret = OHOS::MiscServices::InputMethodController::GetInstance()->GetDefaultInputMethod(property);
    if (ret != ErrorCode::NO_ERROR) {
        taihe::set_business_error(JsUtils::Convert(ret), "failed to get default input method!");
        IMSA_HILOGE("failed to get default input method!");
        return inputMethodProperty;
    }
    inputMethodProperty = PropertyConverter::ConvertProperty(property);
    return inputMethodProperty;
}

InputMethodProperty GetCurrentInputMethod()
{
    InputMethodProperty inputMethodProperty{};
    std::shared_ptr<Property> property =
        OHOS::MiscServices::InputMethodController::GetInstance()->GetCurrentInputMethod();
    if (property == nullptr) {
        IMSA_HILOGE("current input method is nullptr!");
        return inputMethodProperty;
    }
    inputMethodProperty = PropertyConverter::ConvertProperty(property);
    return inputMethodProperty;
}

InputMethodSubtype GetCurrentInputMethodSubtype()
{
    InputMethodSubtype inputMethodSubtype{};
    std::shared_ptr<SubProperty> subProperty =
        OHOS::MiscServices::InputMethodController::GetInstance()->GetCurrentInputMethodSubtype();
    if (subProperty == nullptr) {
        IMSA_HILOGE("current input method subtype is nullptr!");
        return inputMethodSubtype;
    }
    inputMethodSubtype = PropertyConverter::ConvertSubProperty(subProperty);
    return inputMethodSubtype;
}

uintptr_t GetSystemInputMethodConfigAbility()
{
    OHOS::AppExecFwk::ElementName elementName;
    int32_t ret = OHOS::MiscServices::InputMethodController::GetInstance()->GetInputMethodConfig(elementName);
    if (ret != ErrorCode::NO_ERROR) {
        taihe::set_business_error(JsUtils::Convert(ret), "failed to get input method config ability!");
        IMSA_HILOGE("failed to get input method config ability!");
        return reinterpret_cast<uintptr_t>(nullptr);
    }
    ani_object obj = OHOS::AppExecFwk::CommonFunAni::ConvertElementName(taihe::get_env(), elementName);
    return reinterpret_cast<uintptr_t>(obj);
}

bool SwitchInputMethodWithTarget(InputMethodProperty const &target)
{
    std::string packageName(target.name);
    std::string id(target.id);
    if (packageName.empty() || id.empty()) {
        taihe::set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, "packageName and methodId is empty");
        IMSA_HILOGE("failed to switch input method, packageName or id is empty!");
        return false;
    }
    int32_t errCode =
        OHOS::MiscServices::InputMethodController::GetInstance()->SwitchInputMethod(SwitchTrigger::CURRENT_IME,
            packageName, "");
    if (errCode != ErrorCode::NO_ERROR) {
        int32_t code = JsUtils::Convert(errCode);
        std::string message = JsUtils::ToMessage(code);
        taihe::set_business_error(code, message);
        IMSA_HILOGE("failed to switch input method, code:%{public}d message: %{public}s", code, message.c_str());
        return false;
    }
    IMSA_HILOGI("SwitchInputMethodWithTarget success.");
    return true;
}

void SwitchInputMethodSync(string_view bundleName, optional_view<string> subtypeId)
{
    std::string id;
    if (subtypeId.has_value()) {
        id = subtypeId.value();
    }
    int32_t errCode =
        OHOS::MiscServices::InputMethodController::GetInstance()->SwitchInputMethod(SwitchTrigger::SYSTEM_APP,
            std::string(bundleName), id);
    if (errCode != ErrorCode::NO_ERROR) {
        int32_t code = JsUtils::Convert(errCode);
        std::string message = JsUtils::ToMessage(code);
        taihe::set_business_error(code, message);
        IMSA_HILOGE("failed to switch input method, code:%{public}d message: %{public}s", code, message.c_str());
        return;
    }
    IMSA_HILOGI("SwitchInputMethodSync success.");
}

bool SwitchCurrentInputMethodSubtypeSync(InputMethodSubtype const &target)
{
    std::string name(target.name);
    std::string id(target.id);
    int32_t errCode =
        OHOS::MiscServices::InputMethodController::GetInstance()->SwitchInputMethod(SwitchTrigger::CURRENT_IME, name,
            id);
    if (errCode != ErrorCode::NO_ERROR) {
        int32_t code = JsUtils::Convert(errCode);
        std::string message = JsUtils::ToMessage(code);
        taihe::set_business_error(code, message);
        IMSA_HILOGE("failed to switch Current input method subtype, code:%{public}d message: %{public}s", code,
            message.c_str());
        return false;
    }
    IMSA_HILOGI("SwitchCurrentInputMethodSubtypeSync success.");
    return true;
}

void SetSimpleKeyboardEnabled(bool enable)
{
    auto controller =  OHOS::MiscServices::InputMethodController::GetInstance();
    if (controller != nullptr) {
        auto ret = controller->SetSimpleKeyboardEnabled(enable);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("SetSimpleKeyboardEnabled failed:%{public}d.", ret);
            return;
        }
        IMSA_HILOGI("SetSimpleKeyboardEnabled success.");
        return;
    }
    IMSA_HILOGE("SetSimpleKeyboardEnabled failed, InputMethodController GetInstance failed");
}

bool SwitchCurrentInputMethodAndSubtypeSync(::ohos::inputMethod::InputMethodProperty const& inputMethodProperty,
    ::ohos::InputMethodSubtype::InputMethodSubtype const& inputMethodSubtype)
{
    std::string name(inputMethodSubtype.name);
    std::string id(inputMethodSubtype.id);
    int32_t errCode = OHOS::MiscServices::InputMethodController::GetInstance()->SwitchInputMethod(
        SwitchTrigger::CURRENT_IME, name, id);
    if (errCode != ErrorCode::NO_ERROR) {
        int32_t code = JsUtils::Convert(errCode);
        std::string message = JsUtils::ToMessage(code);
        taihe::set_business_error(code, message);
        IMSA_HILOGE("failed to switch Current input method subtype, code:%{public}d message: %{public}s", code,
            message.c_str());
        return false;
    }
    IMSA_HILOGI("SwitchCurrentInputMethodAndSubtype success.");
    return true;
}

void onAttachmentDidFailImpl(taihe::callback_view<void(AttachFailureReason_t info)> f, uintptr_t opq)
{
    InputMethodImpl::GetInstance()->RegisterListener("attachmentDidFail", f, opq);
}

void offAttachmentDidFailImpl(taihe::optional_view<uintptr_t> opq)
{
    InputMethodImpl::GetInstance()->UnRegisterListener("attachmentDidFail", opq);
}
} // namespace

TH_EXPORT_CPP_API_GetSetting(GetSetting);
TH_EXPORT_CPP_API_GetController(GetController);
TH_EXPORT_CPP_API_GetDefaultInputMethod(GetDefaultInputMethod);
TH_EXPORT_CPP_API_GetCurrentInputMethod(GetCurrentInputMethod);
TH_EXPORT_CPP_API_GetCurrentInputMethodSubtype(GetCurrentInputMethodSubtype);
TH_EXPORT_CPP_API_GetSystemInputMethodConfigAbility(GetSystemInputMethodConfigAbility);
TH_EXPORT_CPP_API_SwitchInputMethodWithTarget(SwitchInputMethodWithTarget);
TH_EXPORT_CPP_API_SwitchInputMethodSync(SwitchInputMethodSync);
TH_EXPORT_CPP_API_SwitchCurrentInputMethodSubtypeSync(SwitchCurrentInputMethodSubtypeSync);
TH_EXPORT_CPP_API_SetSimpleKeyboardEnabled(SetSimpleKeyboardEnabled);
TH_EXPORT_CPP_API_SwitchCurrentInputMethodAndSubtypeSync(SwitchCurrentInputMethodAndSubtypeSync);
TH_EXPORT_CPP_API_onAttachmentDidFailImpl(onAttachmentDidFailImpl);
TH_EXPORT_CPP_API_offAttachmentDidFailImpl(offAttachmentDidFailImpl);