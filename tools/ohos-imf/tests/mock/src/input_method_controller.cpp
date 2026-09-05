/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "input_method_controller.h"

#include <new>
namespace OHOS {
namespace MiscServices {
sptr<InputMethodController> InputMethodController::instance_;
std::mutex InputMethodController::instanceLock_;
sptr<InputMethodController> InputMethodController::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) InputMethodController();
            if (instance_ == nullptr) {
                return instance_;
            }
        }
    }
    return instance_;
}

void InputMethodController::SetTextInteractionRet(int32_t ret)
{
    textInteractionRet_ = ret;
}

int32_t InputMethodController::ExecTextInteraction(const std::string &text)
{
    return textInteractionRet_;
}
} // namespace MiscServices
} // namespace OHOS