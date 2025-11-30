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
#include "keyboard_controller_impl.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "ohos.inputMethodEngine.InputMethodAbility.ani.1.hpp"
#include "js_utils.h"
#include "input_method_ability.h"
namespace OHOS {
namespace MiscServices {
void KeyboardControllerImpl::HideAsync()
{
    int32_t ret = InputMethodAbility::GetInstance().HideKeyboardSelf();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to hide keyboard self: %{public}d!", ret);
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("hide keyboard success!");
}

void KeyboardControllerImpl::ExitCurrentInputTypeAsync()
{
    int32_t ret = InputMethodAbility::GetInstance().ExitCurrentInputType();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to exit current input type: %{public}d!", ret);
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("exit current input type success!");
}
}
}