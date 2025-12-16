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
#include <algorithm>
#include <iterator>
#include "ets_inputmethod_extension_context.h"
#include "ani_common_configuration.h"
#include "ani_common_want.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_extension_context.h"
#include "global.h"
#include "ets_context_utils.h"

namespace OHOS {
namespace MiscServices {
constexpr const char *INPUTMETHOD_EXTENSION_CONTEXT_CLASS_NAME =
    "@ohos.InputMethodExtensionContext.InputMethodExtensionContext";
constexpr const char *CLEANER_CLASS_NAME = "@ohos.InputMethodExtensionContext.Cleaner";
constexpr const char *CLASSNAME_ASYNC_CALLBACK_WRAPPER = "@ohos.InputMethodExtensionContext.AsyncCallbackWrapper";

bool BindNativeMethods(ani_env *env, ani_class &cls)
{
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    std::array functions = {
        ani_native_function { "nativeStartAbility",
            "C{@ohos.app.ability.Want.Want}C{@ohos.InputMethodExtensionContext.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(ETSInputMethodExtensionContext::StartAbility) },
        ani_native_function { "nativeDestroy", "C{@ohos.InputMethodExtensionContext.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(ETSInputMethodExtensionContext::Destroy) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        IMSA_HILOGE("bind method status: %{public}d", status);
        return false;
    }
    ani_class cleanerCls = nullptr;
    status = env->FindClass(CLEANER_CLASS_NAME, &cleanerCls);
    if (status != ANI_OK || cleanerCls == nullptr) {
        IMSA_HILOGE("Failed to find class, status: %{public}d", status);
        return false;
    }
    std::array CleanerMethods = {
        ani_native_function { "clean", nullptr, reinterpret_cast<void *>(ETSInputMethodExtensionContext::Finalizer) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, CleanerMethods.data(), CleanerMethods.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        IMSA_HILOGE("bind method status: %{public}d", status);
        return false;
    }
    return true;
}

bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return false;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass(CLASSNAME_ASYNC_CALLBACK_WRAPPER, &clsCall);
    if (status!= ANI_OK || clsCall == nullptr) {
        IMSA_HILOGE("FindClass status: %{public}d, or null clsCall", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "invoke", nullptr, &method)) != ANI_OK || method == nullptr) {
        IMSA_HILOGE("Class_FindMethod status: %{public}d, or null method", status);
        return false;
    }
    if (error == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        error = reinterpret_cast<ani_object>(nullRef);
    }
    if (result == nullptr) {
        ani_ref undefinedRef = nullptr;
        env->GetUndefined(&undefinedRef);
        result = reinterpret_cast<ani_object>(undefinedRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        IMSA_HILOGE("Object_CallMethod_Void status: %{public}d", status);
        return false;
    }
    return true;
}

ani_object CreateETSInputMethodExtensionContext(
    ani_env *env, std::shared_ptr<AbilityRuntime::InputMethodExtensionContext> &context)
{
    IMSA_HILOGI("CreateETSInputMethodExtensionContext call");
    if (env == nullptr || context == nullptr) {
        IMSA_HILOGE("null env or context");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(INPUTMETHOD_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        IMSA_HILOGE("Failed to find class, status: %{public}d", status);
        return nullptr;
    }
    if (!BindNativeMethods(env, cls)) {
        IMSA_HILOGE("Failed to BindNativeMethods");
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK || method == nullptr) {
        IMSA_HILOGE("Failed to find constructor, status : %{public}d", status);
        return nullptr;
    }
    std::unique_ptr<ETSInputMethodExtensionContext> workContext =
        std::make_unique<ETSInputMethodExtensionContext>(context);
    if (workContext == nullptr) {
        IMSA_HILOGE("Failed to create ETSInputMethodExtensionContext");
        return nullptr;
    }
    auto distributeContextPtr = new std::weak_ptr<AbilityRuntime::InputMethodExtensionContext> (
        workContext->GetAbilityContext());
    if (distributeContextPtr == nullptr) {
        IMSA_HILOGE("distributeContextPtr is nullptr");
        return nullptr;
    }
    ani_object contextObj = nullptr;
    if ((status = env->Object_New(cls, method, &contextObj, (ani_long)workContext.release())) != ANI_OK ||
        contextObj == nullptr) {
        IMSA_HILOGE("Failed to create object, status : %{public}d", status);
        delete distributeContextPtr;
        return nullptr;
    }
    if (!AbilityRuntime::ContextUtil::SetNativeContextLong(env, contextObj, (ani_long)(distributeContextPtr))) {
        IMSA_HILOGE("Failed to setNativeContextLong ");
        delete distributeContextPtr;
        return nullptr;
    }
    AbilityRuntime::ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);
    CreateEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    return contextObj;
}

void ETSInputMethodExtensionContext::Finalizer(ani_env *env, ani_object obj)
{
    IMSA_HILOGI("Finalizer");
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return;
    }
    ani_long nativeEtsContextPtr;
    if (env->Object_GetFieldByName_Long(obj, "nativeEtsContext", &nativeEtsContextPtr) != ANI_OK) {
        IMSA_HILOGE("Failed to get nativeEtsContext");
        return;
    }
    if (nativeEtsContextPtr != 0) {
        delete reinterpret_cast<ETSInputMethodExtensionContext *>(nativeEtsContextPtr);
    }
}

ETSInputMethodExtensionContext *ETSInputMethodExtensionContext::GetEtsAbilityContext(ani_env *env, ani_object aniObj)
{
    IMSA_HILOGD("GetEtsAbilityContext");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return nullptr;
    }
    if ((status = env->FindClass(INPUTMETHOD_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        IMSA_HILOGE("Failed to find class, status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeEtsContext", &contextField)) != ANI_OK) {
        IMSA_HILOGE("Failed to find filed, status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        IMSA_HILOGE("Failed to get filed, status : %{public}d", status);
        return nullptr;
    }
    auto weakContext = reinterpret_cast<ETSInputMethodExtensionContext *>(nativeContextLong);
    return weakContext;
}

void ETSInputMethodExtensionContext::StartAbility(
    ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback)
{
    IMSA_HILOGI("ConnectAbility");
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return;
    }
    auto etsContext = ETSInputMethodExtensionContext::GetEtsAbilityContext(env, aniObj);
    if (etsContext == nullptr) {
        IMSA_HILOGE("null ETSInputMethodExtensionContext");
        return;
    }
    etsContext->OnStartAbility(env, aniObj, wantObj, callback);
}

void ETSInputMethodExtensionContext::Destroy(ani_env *env, ani_object aniObj, ani_object callback)
{
    IMSA_HILOGI("DisconnectAbility");
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return;
    }
    auto etsContext = ETSInputMethodExtensionContext::GetEtsAbilityContext(env, aniObj);
    if (etsContext == nullptr) {
        IMSA_HILOGE("null ETSInputMethodExtensionContext");
        return;
    }
    return etsContext->OnDestroy(env, aniObj, callback);
}

void ETSInputMethodExtensionContext::OnStartAbility(
    ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback)
{
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return;
    }
    ani_object aniObject = nullptr;
    AAFwk::Want want;
    ErrCode errCode = ERR_OK;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        aniObject = AbilityRuntime::EtsErrorUtil::CreateInvalidParamError(env, "UnwrapWant filed");
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    auto context = context_.lock();
    if (context == nullptr) {
        IMSA_HILOGE("context is nullptr");
        errCode = static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = AbilityRuntime::EtsErrorUtil::CreateError(
            env, static_cast<AbilityRuntime::AbilityErrorCode>(errCode));
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    errCode = context->StartAbility(want);
    aniObject = AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, errCode);
    AsyncCallback(env, callback, aniObject, nullptr);
}

void ETSInputMethodExtensionContext::OnDestroy(ani_env *env, ani_object aniObj, ani_object callback)
{
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return;
    }
    ani_object aniObject = nullptr;
    ErrCode errCode = ERR_OK;
    auto context = context_.lock();
    if (context == nullptr) {
        IMSA_HILOGE("context is nullptr");
        errCode = static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = AbilityRuntime::EtsErrorUtil::CreateError(
            env, static_cast<AbilityRuntime::AbilityErrorCode>(errCode));
        AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    errCode = context->TerminateAbility();
    aniObject = AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, errCode);
    AsyncCallback(env, callback, aniObject, nullptr);
}
} // namespace MiscServices
} // namespace OHOS