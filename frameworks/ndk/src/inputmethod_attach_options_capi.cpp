/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "native_inputmethod_types.h"
#include "native_object_registry.h"

using namespace OHOS::MiscServices;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

InputMethod_AttachOptions *OH_AttachOptions_Create(bool showKeyboard)
{
    return NativeObjectRegistry<InputMethod_AttachOptions>::GetInstance().Register(
        new (std::nothrow) InputMethod_AttachOptions({ showKeyboard }));
}

InputMethod_AttachOptions *OH_AttachOptions_CreateWithRequestKeyboardReason(
    bool showKeyboard, InputMethod_RequestKeyboardReason requestKeyboardReason)
{
    return NativeObjectRegistry<InputMethod_AttachOptions>::GetInstance().Register(
        new (std::nothrow) InputMethod_AttachOptions({ showKeyboard, requestKeyboardReason }));
}

void OH_AttachOptions_Destroy(InputMethod_AttachOptions *options)
{
    if (options == nullptr) {
        return;
    }
    NativeObjectRegistry<InputMethod_AttachOptions>::GetInstance().Destroy(options);
}

InputMethod_ErrorCode OH_AttachOptions_IsShowKeyboard(InputMethod_AttachOptions *options, bool *showKeyboard)
{
    if (options == nullptr) {
        IMSA_HILOGE("options is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = NativeObjectRegistry<InputMethod_AttachOptions>::GetInstance().Get(options);
    if (lease == nullptr) {
        IMSA_HILOGE("InputMethod_AttachOptions is unregistered or no longer valid.");
        return IME_ERR_PARAMCHECK;
    }

    if (showKeyboard == nullptr) {
        IMSA_HILOGE("showKeyboard is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    *showKeyboard = options->showKeyboard;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_AttachOptions_GetRequestKeyboardReason(
    InputMethod_AttachOptions *options, int *requestKeyboardReason)
{
    if (options == nullptr) {
        IMSA_HILOGE("options is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = NativeObjectRegistry<InputMethod_AttachOptions>::GetInstance().Get(options);
    if (lease == nullptr) {
        IMSA_HILOGE("InputMethod_AttachOptions is unregistered or no longer valid.");
        return IME_ERR_PARAMCHECK;
    }

    if (requestKeyboardReason == nullptr) {
        IMSA_HILOGE("requestKeyboardReason is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    *requestKeyboardReason = static_cast<int>(options->requestKeyboardReason);
    return IME_ERR_OK;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */