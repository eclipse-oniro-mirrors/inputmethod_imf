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
#include "global.h"
#include "native_inputmethod_types.h"
#include "native_object_registry.h"

using namespace OHOS::MiscServices;
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
OH_InputMethod_PreviewTextStyle *OH_InputMethod_PreviewTextStyle_Create(void)
{
    return NativeObjectRegistry<OH_InputMethod_PreviewTextStyle>::GetInstance().Register(
        new (std::nothrow) OH_InputMethod_PreviewTextStyle());
}

void OH_InputMethod_PreviewTextStyle_Destroy(OH_InputMethod_PreviewTextStyle *style)
{
    if (style == nullptr) {
        return;
    }
    NativeObjectRegistry<OH_InputMethod_PreviewTextStyle>::GetInstance().Destroy(style);
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_SetUnderlineStyle(
    OH_InputMethod_PreviewTextStyle *style, OH_InputMethod_UnderlineStyle underlineStyle)
{
    if (style == nullptr) {
        IMSA_HILOGE("style is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = NativeObjectRegistry<OH_InputMethod_PreviewTextStyle>::GetInstance().Get(style);
    if (lease == nullptr) {
        IMSA_HILOGE("PreviewTextStyle is unregistered or no longer valid.");
        return IME_ERR_NULL_POINTER;
    }
    std::lock_guard<std::mutex> lock(lease->attributesMutex_);
    lease->underlineStyle = underlineStyle;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(
    OH_InputMethod_PreviewTextStyle *style, OH_InputMethod_UnderlineStyle *underlineStyle)
{
    if (style == nullptr || underlineStyle == nullptr) {
        IMSA_HILOGE("invalid parameter");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = NativeObjectRegistry<OH_InputMethod_PreviewTextStyle>::GetInstance().Get(style);
    if (lease == nullptr) {
        IMSA_HILOGE("PreviewTextStyle is unregistered or no longer valid.");
        return IME_ERR_NULL_POINTER;
    }
    std::lock_guard<std::mutex> lock(lease->attributesMutex_);
    *underlineStyle = lease->underlineStyle;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_SetUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, uint32_t underlineColor)
{
    if (style == nullptr) {
        IMSA_HILOGE("style is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = NativeObjectRegistry<OH_InputMethod_PreviewTextStyle>::GetInstance().Get(style);
    if (lease == nullptr) {
        IMSA_HILOGE("PreviewTextStyle is unregistered or no longer valid.");
        return IME_ERR_NULL_POINTER;
    }
    std::lock_guard<std::mutex> lock(lease->attributesMutex_);
    lease->underlineColor = underlineColor;
    lease->hasUnderlineColor = true;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_GetUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, uint32_t *underlineColor)
{
    if (style == nullptr || underlineColor == nullptr) {
        IMSA_HILOGE("invalid parameter");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = NativeObjectRegistry<OH_InputMethod_PreviewTextStyle>::GetInstance().Get(style);
    if (lease == nullptr) {
        IMSA_HILOGE("PreviewTextStyle is unregistered or no longer valid.");
        return IME_ERR_NULL_POINTER;
    }
    std::lock_guard<std::mutex> lock(lease->attributesMutex_);
    *underlineColor = lease->underlineColor;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_HasUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, bool *hasUnderlineColor)
{
    if (style == nullptr || hasUnderlineColor == nullptr) {
        IMSA_HILOGE("invalid parameter");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = NativeObjectRegistry<OH_InputMethod_PreviewTextStyle>::GetInstance().Get(style);
    if (lease == nullptr) {
        IMSA_HILOGE("PreviewTextStyle is unregistered or no longer valid.");
        return IME_ERR_NULL_POINTER;
    }
    std::lock_guard<std::mutex> lock(lease->attributesMutex_);
    *hasUnderlineColor = lease->hasUnderlineColor;
    return IME_ERR_OK;
}
#ifdef __cplusplus
}
#endif /* __cplusplus */
