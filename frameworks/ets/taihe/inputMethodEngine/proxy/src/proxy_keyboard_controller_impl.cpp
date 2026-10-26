/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "proxy_keyboard_controller_impl.h"
#include "js_utils.h"

namespace OHOS {
namespace MiscServices {

void IMFProxyKeyboardControllerImpl::HideSelfAsync()
{
    IMSA_HILOGI("HideSelfAsync start");
    int32_t status = InputMethodAbility::GetInstance().HideCustomKeyboardSelf();
    if (status != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("HideSelfAsync return error: %{public}d", status);
        taihe::set_business_error(JsUtils::Convert(status), JsUtils::ToMessage(JsUtils::Convert(status)));
        return;
    }
    IMSA_HILOGI("HideSelfAsync success");
}

} // namespace MiscServices
} // namespace OHOS
