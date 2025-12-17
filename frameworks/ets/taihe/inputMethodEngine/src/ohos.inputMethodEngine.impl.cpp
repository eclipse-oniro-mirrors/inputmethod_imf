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

using namespace OHOS::MiscServices;
namespace {
// To be implemented.

ohos::inputMethodEngine::Ability GetInputMethodAbility()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    auto ability = taihe::make_holder<IMFAbilityImpl, ohos::inputMethodEngine::InputMethodAbility>();
    return ohos::inputMethodEngine::Ability::make_type_Ability(ability);
}

ohos::inputMethodEngine::Delegate GetKeyboardDelegate()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    auto delegate = taihe::make_holder<IMFKeyboardDelegateImpl, ohos::inputMethodEngine::KeyboardDelegate>();
    return ohos::inputMethodEngine::Delegate::make_type_Delegate(delegate);
}
} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_GetInputMethodAbility(GetInputMethodAbility);
TH_EXPORT_CPP_API_GetKeyboardDelegate(GetKeyboardDelegate);
// NOLINTEND
