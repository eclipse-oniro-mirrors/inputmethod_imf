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
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
OH_InputMethod_PreviewTextStyle *OH_InputMethod_PreviewTextStyle_Create(void)
{
    return new (std::nothrow) OH_InputMethod_PreviewTextStyle();
}

void OH_InputMethod_PreviewTextStyle_Destroy(OH_InputMethod_PreviewTextStyle *style)
{
    if (style == nullptr) {
        return;
    }
    delete style;
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_SetUnderlineStyle(
    OH_InputMethod_PreviewTextStyle *style, OH_InputMethod_UnderlineStyle underlineStyle)
{
    if (style == nullptr) {
        IMSA_HILOGE("style is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    style->underlineStyle = underlineStyle;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(
    OH_InputMethod_PreviewTextStyle *style, OH_InputMethod_UnderlineStyle *underlineStyle)
{
    if (style == nullptr || underlineStyle == nullptr) {
        IMSA_HILOGE("invalid parameter");
        return IME_ERR_NULL_POINTER;
    }
    *underlineStyle = style->underlineStyle;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_SetUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, uint32_t underlineColor)
{
    if (style == nullptr) {
        IMSA_HILOGE("style is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    style->underlineColor = underlineColor;
    style->hasUnderlineColor = true;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_GetUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, uint32_t *underlineColor)
{
    if (style == nullptr || underlineColor == nullptr) {
        IMSA_HILOGE("invalid parameter");
        return IME_ERR_NULL_POINTER;
    }
    *underlineColor = style->underlineColor;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_HasUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, bool *hasUnderlineColor)
{
    if (style == nullptr || hasUnderlineColor == nullptr) {
        IMSA_HILOGE("invalid parameter");
        return IME_ERR_NULL_POINTER;
    }
    *hasUnderlineColor = style->hasUnderlineColor;
    return IME_ERR_OK;
}
#ifdef __cplusplus
}
#endif /* __cplusplus */
