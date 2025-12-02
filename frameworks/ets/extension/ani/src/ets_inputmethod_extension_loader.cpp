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

#include "global.h"
#include "inputmethod_extension.h"
#include "runtime.h"
#include <dlfcn.h>

namespace OHOS {
namespace MiscServices {
namespace {
constexpr char ETS_INPUTMETHOD_EXT_LIB_NAME[] = "libinputmethod_extension_ani.z.so";

using CreateFunc = AbilityRuntime::InputMethodExtension *(*)(void*);
static constexpr char ETS_INPUTMETHOD_EXT_CREATE_FUNC[] = "OHOS_ABILITY_ETSInputMethodExtension";

} // namespace

AbilityRuntime::InputMethodExtension *CreateETSInputMethodExtension(
    const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    std::unique_ptr<AbilityRuntime::Runtime>* runtimePtr = const_cast<std::unique_ptr<AbilityRuntime::Runtime>*>(
        &runtime);
    void *handle = dlopen(ETS_INPUTMETHOD_EXT_LIB_NAME, RTLD_LAZY);
    if (handle == nullptr) {
        IMSA_HILOGE("open InputMethodExtensionETS library %{public}s failed, reason: %{public}s",
            ETS_INPUTMETHOD_EXT_LIB_NAME, dlerror());
        return new AbilityRuntime::InputMethodExtension();
    }

    auto entry = reinterpret_cast<CreateFunc>(dlsym(handle, ETS_INPUTMETHOD_EXT_CREATE_FUNC));
    if (entry == nullptr) {
        dlclose(handle);
        IMSA_HILOGE("get InputMethodExtensionETS symbol %{public}s in %{public}s failed",
            ETS_INPUTMETHOD_EXT_CREATE_FUNC, ETS_INPUTMETHOD_EXT_LIB_NAME);
        return new AbilityRuntime::InputMethodExtension();
    }

    auto instance = entry(reinterpret_cast<void*>(runtimePtr));
    if (instance == nullptr) {
        dlclose(handle);
        IMSA_HILOGE("get InputMethodExtensionETS instance in %{public}s failed", ETS_INPUTMETHOD_EXT_LIB_NAME);
        return new AbilityRuntime::InputMethodExtension();
    }

    return instance;
}
} // namespace MiscServices
} // namespace OHOS