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
#ifndef OHOS_INPUTMETHOD_INPUTMETHOD_PROXY_CAPI_H
#define OHOS_INPUTMETHOD_INPUTMETHOD_PROXY_CAPI_H
/**
 * @addtogroup InputMethod
 * @{
 *
 * @brief InputMethod provides functions to use input methods and develop input methods.
 *
 * @since 12
 */

/**
 * @file inputmethod_inputmethod_proxy_capi.h
 *
 * @brief Provides functions to use input methods.
 *
 * @library libohinputmethod.so
 * @kit IMEKit
 * @syscap SystemCapability.MiscServices.InputMethodFramework
 * @since 12
 * @version 1.0
 */
#include <stddef.h>

#include "inputmethod_types_capi.h"
#include "inputmethod_attach_options_capi.h"
#include "inputmethod_cursor_info_capi.h"
#include "inputmethod_private_command_capi.h"
#include "inputmethod_message_handler_proxy_capi.h"
#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */
/**
 * @brief Define the InputMethod_InputMethodProxy structure type.
 *
 * Provides methods for controlling input method.
 *
 * @since 12
 */
typedef struct InputMethod_InputMethodProxy InputMethod_InputMethodProxy;

/**
 * @brief Show keyboard.
 *
 * Serialize Controller and InputMethodProxy operations. A concurrent or callback-reentrant C session
 * operation is rejected with IME_ERR_IMCLIENT before it can affect the current session.
 * This guard is not a general thread-safety guarantee for native, ArkTS, or service-side operations.
 *
 * @param inputMethodProxy Represents a pointer to an {@link InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - inputMethodProxy does not match the current proxy.
 *     {@link IME_ERR_IMCLIENT} - input method client error, or a concurrent/reentrant C session operation.
 *     {@link IME_ERR_IMMS} - input method manager service error.
 *     {@link IME_ERR_DETACHED} - input method client detached.
 *     {@link IME_ERR_EDITABLE} - the input method client is not editable; it may still be attached.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 12
 */
InputMethod_ErrorCode OH_InputMethodProxy_ShowKeyboard(InputMethod_InputMethodProxy *inputMethodProxy);
/**
 * @brief ShowTextInput.
 *
 * @param inputMethodProxy Represents a pointer to an {@link InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @param options Represents a pointer to an {@link InputMethod_AttachOptions} instance which will be get value from.
 * options must be a live AttachOptions handle.
 * An unregistered or expired value handle returns IME_ERR_PARAMCHECK.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - inputMethodProxy does not match the current proxy.
 *     {@link IME_ERR_IMCLIENT} - input method client error, or a concurrent/reentrant C session operation.
 *     {@link IME_ERR_IMMS} - input method manager service error.
 *     {@link IME_ERR_DETACHED} - input method client detached.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 16
 */
InputMethod_ErrorCode OH_InputMethodProxy_ShowTextInput(
    InputMethod_InputMethodProxy *inputMethodProxy, InputMethod_AttachOptions *options);
/**
 * @brief Hide keyboard.
 *
 * @param inputMethodProxy Represents a pointer to an {@link InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - inputMethodProxy does not match the current proxy.
 *     {@link IME_ERR_IMCLIENT} - input method client error, or a concurrent/reentrant C session operation.
 *     {@link IME_ERR_IMMS} - input method manager service error.
 *     {@link IME_ERR_DETACHED} - input method client detached.
 *     {@link IME_ERR_EDITABLE} - the input method client is not editable; it may still be attached.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 12
 */
InputMethod_ErrorCode OH_InputMethodProxy_HideKeyboard(InputMethod_InputMethodProxy *inputMethodProxy);

/**
 * @brief Notify selection change.
 *
 * Notify selection change when text or cursor position or selected text changed.
 *
 * @param inputMethodProxy Represents a pointer to an {@link InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @param text The whole input text.
 * @param length The length of text. Max length is 8K.
 * @param start The start position of selected text.
 * @param end The end position of selected text.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - parameter check failed.
 *     {@link IME_ERR_IMCLIENT} - input method client error, or a concurrent/reentrant C session operation.
 *     {@link IME_ERR_IMMS} - input method manager service error.
 *     {@link IME_ERR_DETACHED} - input method client detached.
 *     {@link IME_ERR_EDITABLE} - the input method client is not editable; it may still be attached.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 12
 */
InputMethod_ErrorCode OH_InputMethodProxy_NotifySelectionChange(
    InputMethod_InputMethodProxy *inputMethodProxy, char16_t text[], size_t length, int start, int end);

/**
 * @brief Notify text editor configuration change.
 *
 * @param inputMethodProxy Represents a pointer to an {@link InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @param enterKey The enter key type.
 * @param textType The text input type.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - parameter check failed.
 *     {@link IME_ERR_IMCLIENT} - input method client error, or a concurrent/reentrant C session operation.
 *     {@link IME_ERR_IMMS} - input method manager service error.
 *     {@link IME_ERR_DETACHED} - input method client detached.
 *     {@link IME_ERR_EDITABLE} - the input method client is not editable; it may still be attached.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 12
 */
InputMethod_ErrorCode OH_InputMethodProxy_NotifyConfigurationChange(InputMethod_InputMethodProxy *inputMethodProxy,
    InputMethod_EnterKeyType enterKey, InputMethod_TextInputType textType);

/**
 * @brief Notify cursor update.
 *
 * @param inputMethodProxy Represents a pointer to an {@link InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @param cursorInfo Represents a pointer to an {@link InputMethod_CursorInfo} instance.
 *     The cursor information.
 * cursorInfo must be a live CursorInfo or TextConfig child view.
 * An unregistered or expired value handle returns IME_ERR_PARAMCHECK.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - parameter check failed.
 *     {@link IME_ERR_IMCLIENT} - input method client error, or a concurrent/reentrant C session operation.
 *     {@link IME_ERR_IMMS} - input method manager service error.
 *     {@link IME_ERR_DETACHED} - input method client detached.
 *     {@link IME_ERR_EDITABLE} - the input method client is not editable; it may still be attached.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 12
 */
InputMethod_ErrorCode OH_InputMethodProxy_NotifyCursorUpdate(
    InputMethod_InputMethodProxy *inputMethodProxy, InputMethod_CursorInfo *cursorInfo);

/**
 * @brief Send private command.
 *
 * @param inputMethodProxy Represents a pointer to an {@link OH_InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @param privateCommand The private commands, which is defined in {@link InputMethod_PrivateCommand}. Max size 32KB.
 * @param size The size of privateCommand. Max is 5.
 * Every privateCommand entry must be a live owned or callback-borrowed command.
 * An unregistered or expired value handle returns IME_ERR_PARAMCHECK.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - parameter check failed.
 *     {@link IME_ERR_IMCLIENT} - input method client error, or a concurrent/reentrant C session operation.
 *     {@link IME_ERR_IMMS} - input method manager service error.
 *     {@link IME_ERR_DETACHED} - input method client detached.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 12
 */
InputMethod_ErrorCode OH_InputMethodProxy_SendPrivateCommand(
    InputMethod_InputMethodProxy *inputMethodProxy, InputMethod_PrivateCommand *privateCommand[], size_t size);

/**
 * @brief Send private command.
 *
 * @param inputMethodProxy Represents a pointer to an {@link OH_InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @param msgId The ArrayBuffer.msgId, which is defined in {@link InputMethod_PrivateCommand}. Max size 256B.
 * @param msgIdLength The size of ArrayBuffer.msgId. Max is 256B.
 * @param msgParam The private commands, which is defined in {@link InputMethod_PrivateCommand}. Max size 128KB.
 * @param msgParamLength The size of ArrayBuffer.msgParam. Max is 128KB.
 * @param size The size of privateCommand. Max is 5.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - parameter check failed.
 *     {@link IME_ERR_IMCLIENT} - input method client error, or a concurrent/reentrant C session operation.
 *     {@link IME_ERR_IMMS} - input method manager service error.
 *     {@link IME_ERR_DETACHED} - input method client detached.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 16
 */
InputMethod_ErrorCode OH_InputMethodProxy_SendMessage(InputMethod_InputMethodProxy *inputMethodProxy,
    const char16_t *msgId, size_t msgIdLength, const uint8_t *msgParam, size_t msgParamLength);

/**
 * @brief Register message handler.
 *
 * @param inputMethodProxy Represents a pointer to an {@link OH_InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @param messageHandler Represents a pointer to an {@link InputMethod_MessageHandlerProxy} instance.
 *     The caller needs to manage the lifecycle of messageHandler.
 * @return Returns a specific error code.
 *     {@link IME_ERR_OK} - success.
 *     {@link IME_ERR_PARAMCHECK} - parameter check failed.
 *     {@link IME_ERR_IMCLIENT} - input method client error, or a concurrent/reentrant C session operation.
 *     {@link IME_ERR_IMMS} - input method manager service error.
 *     {@link IME_ERR_DETACHED} - input method client detached.
 *     {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 * Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 16
 */
InputMethod_ErrorCode OH_InputMethodProxy_RecvMessage(
    InputMethod_InputMethodProxy *inputMethodProxy, InputMethod_MessageHandlerProxy *messageHandler);

/**
 * @brief Request system input capability.
 *
 * @param inputMethodProxy [in] Represents a pointer to an {@link InputMethod_InputMethodProxy} instance.
 *     The inputMethodProxy is obtained from {@link OH_InputMethodController_Attach}.
 * @param type [in] Represents the input capability type. {@link OH_InputMethod_InputCapabilityType}
 * @return Returns a specific error code.
 *     - {@link IME_ERR_OK} - success.
 *     - {@link IME_ERR_PARAMCHECK} - parameter check failed.
 *     - {@link IME_ERR_IMMS} - input method manager service error.
 *     - {@link OH_INPUTMETHOD_ERR_NOT_DEFAULT_IME} - current ime is not the default ime.
 *     - {@link OH_INPUTMETHOD_INPUT_CAPABILITY_TYPE_NOT_SUPPORTED} - the input type is not supported.
 *     - {@link IME_ERR_DETACHED} - input method client detached.
 *     - {@link IME_ERR_NULL_POINTER} - unexpected null pointer.
 *     Specific error codes can be referenced {@link InputMethod_ErrorCode}.
 * @since 26.1.0
 */
InputMethod_ErrorCode OH_InputMethod_InputMethodProxy_RequestSystemInputCapability(
    InputMethod_InputMethodProxy *inputMethodProxy, OH_InputMethod_InputCapabilityType type);
#ifdef __cplusplus
}
#endif /* __cplusplus */
/** @} */
#endif // INPUTMETHOD_INPUTMETHOD_PROXY_CAP_H