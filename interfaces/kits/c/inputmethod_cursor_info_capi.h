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
#ifndef OHOS_INPUTMETHOD_CURSOR_INFO_CAPI_H
#define OHOS_INPUTMETHOD_CURSOR_INFO_CAPI_H
/**
 * @addtogroup InputMethod
 * @{
 *
 * @brief InputMethod provides functions to use input methods and develop input methods.
 *
 * @since 12
 */

/**
 * @file inputmethod_cursor_info_capi.h
 *
 * @brief Provides interfaces to manage the cursor information.
 *
 * @library libohinputmethod.so
 * @kit IMEKit
 * @syscap SystemCapability.MiscServices.InputMethodFramework
 * @since 12
 * @version 1.0
 */
#include "inputmethod_types_capi.h"
#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */
/**
 * @brief Define the InputMethod_CursorInfo structure type.
 *
 * The coordinates and width and height information of the cursor.
 *
 * Use only a live handle created by this API or a borrowed handle supplied by the framework.
 * Destroy only independently created objects. Callback objects and TextConfig child views are borrowed.
 * Accessors reject unregistered or expired handles with IME_ERR_PARAMCHECK; NULL keeps its existing error.
 * Lifetime checks do not make object fields thread-safe or identify every stale address after address reuse.
 * Clear pointers after destruction and do not retain callback objects beyond the callback.
 *
 * @since 12
 */
typedef struct InputMethod_CursorInfo InputMethod_CursorInfo;

/**
 * @brief Create a new {@link InputMethod_CursorInfo} instance.
 *
 * @param left The left point of the cursor and must be absolute coordinate of the physical screen.
 * @param top The top point of the cursor and must be absolute coordinate of the physical screen.
 * @param width The width of the cursor.
 * @param height The height of the cursor.
 * @return If the creation succeeds, a pointer to the newly created {@link InputMethod_CursorInfo}
 * instance is returned. If the creation fails, NULL is returned, possible cause is insufficient memory.
 * @since 12
 */
InputMethod_CursorInfo *OH_CursorInfo_Create(double left, double top, double width, double height);

/**
 * @brief Destroy a {@link InputMethod_CursorInfo} instance.
 * Only independently created objects are owned by the caller. A TextConfig getter returns a borrowed view;
 * passing that view here is rejected without releasing its parent. Do not use the pointer after destruction.
 *
 * @param cursorInfo Represents a pointer to an {@link InputMethod_CursorInfo} instance which will be destroyed.
 * @since 12
 */
void OH_CursorInfo_Destroy(InputMethod_CursorInfo *cursorInfo);

/**
 * @brief Set cursor info.
 *
 * @param cursorInfo Represents a pointer to an {@link InputMethod_CursorInfo} instance.
 * @param left The left point of the cursor and must be absolute coordinate of the physical screen.
 * @param top The top point of the cursor and must be absolute coordinate of the physical screen.
 * @param width The width of the cursor.
 * @param height The height of the cursor.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - the object handle is unregistered or no longer valid.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 12
 */
InputMethod_ErrorCode OH_CursorInfo_SetRect(
    InputMethod_CursorInfo *cursorInfo, double left, double top, double width, double height);

/**
 * @brief Get cursor info.
 *
 * @param cursorInfo Represents a pointer to an {@link InputMethod_CursorInfo} instance.
 * @param left The left point of the cursor and must be absolute coordinate of the physical screen.
 * @param top The top point of the cursor and must be absolute coordinate of the physical screen.
 * @param width The width of the cursor.
 * @param height The height of the cursor.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - the object handle is unregistered or no longer valid.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 12
 */
InputMethod_ErrorCode OH_CursorInfo_GetRect(
    InputMethod_CursorInfo *cursorInfo, double *left, double *top, double *width, double *height);
#ifdef __cplusplus
}
#endif /* __cplusplus */
/** @} */
#endif // OHOS_INPUTMETHOD_CURSOR_INFO_CAPI_H