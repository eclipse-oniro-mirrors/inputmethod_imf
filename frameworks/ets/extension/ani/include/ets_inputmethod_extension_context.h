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

#ifndef ABILITY_RUNTIME_ETS_INPUTMETHOD_EXTENSION_CONTEXT_H
#define ABILITY_RUNTIME_ETS_INPUTMETHOD_EXTENSION_CONTEXT_H

#include "ani.h"
#include "ability_connect_callback.h"
#include "event_handler.h"
#include "inputmethod_extension_context.h"
#include "ipc_skeleton.h"
#include "ets_free_install_observer.h"

namespace OHOS {
namespace MiscServices {

ani_object CreateETSInputMethodExtensionContext(
    ani_env *env, std::shared_ptr<AbilityRuntime::InputMethodExtensionContext> &context);

class ETSInputMethodExtensionContext {
public:
    explicit ETSInputMethodExtensionContext(std::shared_ptr<AbilityRuntime::InputMethodExtensionContext> context)
        : context_(std::move(context)) {}
    ~ETSInputMethodExtensionContext() = default;
    static void Finalizer(ani_env *env, ani_object obj);
    static ETSInputMethodExtensionContext *GetEtsAbilityContext(ani_env *env, ani_object obj);
    static void StartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback);
    static void Destroy(ani_env *env, ani_object aniObj, ani_object callback);
    std::weak_ptr<AbilityRuntime::InputMethodExtensionContext> GetAbilityContext()
    {
        return context_;
    }
private:
    void OnStartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback);
    void OnDestroy(ani_env *env, ani_object aniObj, ani_object callback);

private:
    std::weak_ptr<AbilityRuntime::InputMethodExtensionContext> context_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // ABILITY_RUNTIME_ETS_INPUTMETHOD_EXTENSION_CONTEXT_H