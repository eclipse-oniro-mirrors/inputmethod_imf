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

#ifndef ETS_INPUTMETHOD_EXTENSION_LOADER_H
#define ETS_INPUTMETHOD_EXTENSION_LOADER_H

#include <memory>
#include "runtime.h"
#include "inputmethod_extension.h"

namespace OHOS {
namespace MiscServices {
AbilityRuntime::InputMethodExtension *CreateETSInputMethodExtension(
    const std::unique_ptr<AbilityRuntime::Runtime> &runtime);
} // namespace MiscServices
} // namespace OHOS

#endif // CJ_INPUTMETHOD_EXTENSION_LOADER_H
