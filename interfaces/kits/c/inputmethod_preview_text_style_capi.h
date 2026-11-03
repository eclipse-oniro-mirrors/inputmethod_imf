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
/**
 * @addtogroup InputMethod
 * @{
 *
 * @brief InputMethod provides functions to use input methods and develop input methods.
 *
 * @since 12
 */

/**
 * @file inputmethod_preview_text_style_capi.h
 *
 * @brief Provides methods for creating, destroying, reading, and writing the preview text style objects.
 *
 * @include <inputmethod/inputmethod_preview_text_style_capi.h>
 * @library libohinputmethod.so
 * @kit IMEKit
 * @syscap SystemCapability.MiscServices.InputMethodFramework
 * @since 26.1.0
 * @version 1.0
 */
#ifndef OHOS_INPUTMETHOD_PREVIEW_TEXT_STYLE_CAPI_H
#define OHOS_INPUTMETHOD_PREVIEW_TEXT_STYLE_CAPI_H
#include <stdbool.h>
#include <stdint.h>

#include "inputmethod_types_capi.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Defines the preview text style, including the underline style and underline color.
 *
 * The actual members of this structure are defined internally and are not exposed. New members may be added
 * internally in the future without breaking compatibility. Use {@link OH_InputMethod_PreviewTextStyle_Create}
 * to create an instance, the setter function to write properties, and the getter functions to read properties.
 *
 * @since 26.1.0
 */
typedef struct OH_InputMethod_PreviewTextStyle OH_InputMethod_PreviewTextStyle;

/**
 * @brief Create a new {@link OH_InputMethod_PreviewTextStyle} instance.
 *
 * @return If the creation succeeds, a pointer to the newly created {@link OH_InputMethod_PreviewTextStyle}
 * instance is returned. If the creation fails, NULL is returned, possible cause is insufficient memory.
 * @since 26.1.0
 */
OH_InputMethod_PreviewTextStyle *OH_InputMethod_PreviewTextStyle_Create(void);

/**
 * @brief Destroy a {@link OH_InputMethod_PreviewTextStyle} instance.
 *
 * @param style Represents a pointer to an {@link OH_InputMethod_PreviewTextStyle} instance which will be destroyed.
 * @since 26.1.0
 */
void OH_InputMethod_PreviewTextStyle_Destroy(OH_InputMethod_PreviewTextStyle *style);

/**
 * @brief Set underline style into {@link OH_InputMethod_PreviewTextStyle}.
 *
 * @param style Represents a pointer to an {@link OH_InputMethod_PreviewTextStyle} instance which will be set.
 * @param underlineStyle Represents the underline style of preview text.
 * @return Returns a specific error code.
 *     <br>{@link IME_ERR_OK} - success.
 *     <br>{@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 *     <br>Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 26.1.0
 */
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_SetUnderlineStyle(
    OH_InputMethod_PreviewTextStyle *style, OH_InputMethod_UnderlineStyle underlineStyle);

/**
 * @brief Set underline color into {@link OH_InputMethod_PreviewTextStyle}.
 *
 * @param style Represents a pointer to an {@link OH_InputMethod_PreviewTextStyle} instance which will be set.
 * @param underlineColor Represents the underline color of preview text.
 * @return Returns a specific error code.
 *     <br>{@link IME_ERR_OK} - success.
 *     <br>{@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 *     <br>Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 26.1.0
 */
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_SetUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, uint32_t underlineColor);

/**
 * @brief Get underline style from {@link OH_InputMethod_PreviewTextStyle}.
 *
 * @param style Represents a pointer to an {@link OH_InputMethod_PreviewTextStyle} instance which will be get from.
 * @param underlineStyle Represents a pointer to the underline style of preview text.
 * @return Returns a specific error code.
 *     <br>{@link IME_ERR_OK} - success.
 *     <br>{@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 *     <br>Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 26.1.0
 */
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(
    OH_InputMethod_PreviewTextStyle *style, OH_InputMethod_UnderlineStyle *underlineStyle);

/**
 * @brief Get underline color from {@link OH_InputMethod_PreviewTextStyle}.
 *
 * @param style Represents a pointer to an {@link OH_InputMethod_PreviewTextStyle} instance which will be get from.
 * @param underlineColor Represents a pointer to the underline color of preview text.
 * @return Returns a specific error code.
 *     <br>{@link IME_ERR_OK} - success.
 *     <br>{@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 *     <br>Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 26.1.0
 */
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_GetUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, uint32_t *underlineColor);

/**
 * @brief Get whether the underline color is set from {@link OH_InputMethod_PreviewTextStyle}.
 *
 * @param style Represents a pointer to an {@link OH_InputMethod_PreviewTextStyle} instance which will be get from.
 * @param hasUnderlineColor Indicates whether the underline color is set.
 * @return Returns a specific error code.
 *     <br>{@link IME_ERR_OK} - success.
 *     <br>{@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 *     <br>Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 26.1.0
 */
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_HasUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, bool *hasUnderlineColor);

#ifdef __cplusplus
}
#endif /* __cplusplus */
/** @} */
#endif // OHOS_INPUTMETHOD_PREVIEW_TEXT_STYLE_CAPI_H
