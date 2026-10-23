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

#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "ani_common_engine.h"
#include "input_method_ability_impl.h"
#include "input_method_keyboard_delegate_impl.h"
#include "proxy_input_method_ability_impl.h"
#include "proxy_keyboard_delegate_impl.h"
#include "input_method_utils.h"
#include "input_method_ability.h"
#include "js_utils.h"

using namespace OHOS::MiscServices;
namespace {

ohos::inputMethodEngine::Ability GetInputMethodAbility()
{
    auto ability = taihe::make_holder<IMFAbilityImpl, ohos::inputMethodEngine::InputMethodAbility>();
    return ohos::inputMethodEngine::Ability::make_type_Ability(ability);
}

ohos::inputMethodEngine::Delegate GetKeyboardDelegate()
{
    auto delegate = taihe::make_holder<IMFKeyboardDelegateImpl, ohos::inputMethodEngine::KeyboardDelegate>();
    return ohos::inputMethodEngine::Delegate::make_type_Delegate(delegate);
}

ohos::inputMethodEngine::ProxyAbility GetProxyInputMethodAbility()
{
    if (InputMethodAbility::GetInstance().IsImeExtension()) {
        IMSA_HILOGE("IME extension not allowed");
        taihe::set_business_error(IMFErrorCode::EXCEPTION_IME_EXTENSION_NOT_ALLOWED,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_IME_EXTENSION_NOT_ALLOWED));
        return ohos::inputMethodEngine::ProxyAbility::make_type_null();
    }
    auto ability =
        taihe::make_holder<IMFProxyInputMethodAbilityImpl, ohos::inputMethodEngine::ProxyInputMethodAbility>();
    return ohos::inputMethodEngine::ProxyAbility::make_type_ProxyAbility(ability);
}

ohos::inputMethodEngine::ProxyDelegate GetProxyKeyboardDelegate()
{
    if (InputMethodAbility::GetInstance().IsImeExtension()) {
        IMSA_HILOGE("IME extension not allowed");
        taihe::set_business_error(IMFErrorCode::EXCEPTION_IME_EXTENSION_NOT_ALLOWED,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_IME_EXTENSION_NOT_ALLOWED));
        return ohos::inputMethodEngine::ProxyDelegate::make_type_null();
    }
    auto delegate =
        taihe::make_holder<IMFProxyKeyboardDelegateImpl, ohos::inputMethodEngine::ProxyKeyboardDelegate>();
    return ohos::inputMethodEngine::ProxyDelegate::make_type_ProxyDelegate(delegate);
}

bool ParseRegisterOptions(taihe::optional<RegisterOptions_t> options, RegisterOptions &out)
{
    if (!options.has_value()) {
        return true;
    }
    auto &opts = options.value();
    if (!opts.inputPatternTypes.has_value()) {
        return true;
    }
    auto &arr = opts.inputPatternTypes.value();
    if (arr.empty()) {
        IMSA_HILOGE("inputPatternTypes is empty");
        taihe::set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, "inputPatternTypes must not be empty");
        return false;
    }
    out.inputPatternTypes = std::vector<int32_t>{};
    for (size_t i = 0; i < arr.size(); ++i) {
        if (!OHOS::MiscServices::IsValidInputPattern(arr[i])) {
            IMSA_HILOGE("invalid inputPatternTypes value: %{public}d", arr[i]);
            taihe::set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, "inputPatternTypes contains invalid value");
            return false;
        }
        out.inputPatternTypes->push_back(arr[i]);
    }
    return true;
}

void RegisterInAppProxyImeAsync(taihe::optional<RegisterOptions_t> options)
{
    RegisterOptions nativeOptions;
    if (!ParseRegisterOptions(options, nativeOptions)) {
        return;
    }
    int32_t code = InputMethodAbility::GetInstance().RegisterInAppProxyIme(nativeOptions);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("RegisterInAppProxyImeAsync failed: %{public}d", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("RegisterInAppProxyImeAsync success");
}

void UnregisterInAppProxyImeAsync()
{
    int32_t code = InputMethodAbility::GetInstance().UnregisterInAppProxyIme();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("UnregisterInAppProxyImeAsync failed: %{public}d", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("UnregisterInAppProxyImeAsync success");
}

} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_GetInputMethodAbility(GetInputMethodAbility);
TH_EXPORT_CPP_API_GetKeyboardDelegate(GetKeyboardDelegate);
TH_EXPORT_CPP_API_GetProxyInputMethodAbility(GetProxyInputMethodAbility);
TH_EXPORT_CPP_API_GetProxyKeyboardDelegate(GetProxyKeyboardDelegate);
TH_EXPORT_CPP_API_RegisterInAppProxyImeAsync(RegisterInAppProxyImeAsync);
TH_EXPORT_CPP_API_UnregisterInAppProxyImeAsync(UnregisterInAppProxyImeAsync);
// NOLINTEND
