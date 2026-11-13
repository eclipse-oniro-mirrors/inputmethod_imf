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
#include "input_method_controller.h"
#include "native_inputmethod_types.h"
#include "native_inputmethod_utils.h"
#include "native_message_handler_callback.h"
#include "native_session_guard.h"
#include "string_ex.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
using namespace OHOS;
using namespace OHOS::MiscServices;
constexpr size_t INVALID_MSG_ID_SIZE = 256; // 256B
constexpr size_t INVALID_MSG_PARAM_SIZE = 128 * 1024; // 128KB
static int32_t IsValidMessageHandlerProxy(const std::shared_ptr<InputMethod_MessageHandlerProxy> &messageHandler)
{
    if (messageHandler == nullptr) {
        IMSA_HILOGE("messageHandler is nullptr");
        return IME_ERR_OK;
    }
    if (messageHandler->onTerminatedFunc.load() == nullptr) {
        IMSA_HILOGE("onTerminatedFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (messageHandler->onMessageFunc.load() == nullptr) {
        IMSA_HILOGE("onMessageFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethodProxy_ShowKeyboard(InputMethod_InputMethodProxy *inputMethodProxy)
{
    NativeSessionGuard sessionGuard;
    if (!sessionGuard.IsAcquired()) {
        IMSA_HILOGE("Concurrent or reentrant C session operation rejected; wait for the current operation to finish.");
        return IME_ERR_IMCLIENT;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return ErrorCodeConvert(instance->ShowCurrentInput());
}

InputMethod_ErrorCode OH_InputMethodProxy_ShowTextInput(
    InputMethod_InputMethodProxy *inputMethodProxy, InputMethod_AttachOptions *options)
{
    NativeSessionGuard sessionGuard;
    if (!sessionGuard.IsAcquired()) {
        IMSA_HILOGE("Concurrent or reentrant C session operation rejected; wait for the current operation to finish.");
        return IME_ERR_IMCLIENT;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }

    if (options == nullptr) {
        IMSA_HILOGE("options is null; create AttachOptions with OH_AttachOptions_Create before ShowTextInput.");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = NativeObjectRegistry<InputMethod_AttachOptions>::GetInstance().Get(options);
    if (lease == nullptr) {
        IMSA_HILOGE("InputMethod_AttachOptions is unregistered or no longer valid.");
        return IME_ERR_PARAMCHECK;
    }

    AttachOptions attachOptions;
    attachOptions.isShowKeyboard = options->showKeyboard;
    attachOptions.requestKeyboardReason =
        static_cast<RequestKeyboardReason>(static_cast<int32_t>(options->requestKeyboardReason));
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return ErrorCodeConvert(instance->ShowTextInput(attachOptions));
}

InputMethod_ErrorCode OH_InputMethodProxy_HideKeyboard(InputMethod_InputMethodProxy *inputMethodProxy)
{
    NativeSessionGuard sessionGuard;
    if (!sessionGuard.IsAcquired()) {
        IMSA_HILOGE("Concurrent or reentrant C session operation rejected; wait for the current operation to finish.");
        return IME_ERR_IMCLIENT;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return ErrorCodeConvert(instance->HideCurrentInput());
}
InputMethod_ErrorCode OH_InputMethodProxy_NotifySelectionChange(
    InputMethod_InputMethodProxy *inputMethodProxy, char16_t text[], size_t length, int start, int end)
{
    NativeSessionGuard sessionGuard;
    if (!sessionGuard.IsAcquired()) {
        IMSA_HILOGE("Concurrent or reentrant C session operation rejected; wait for the current operation to finish.");
        return IME_ERR_IMCLIENT;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }
    if (text == nullptr) {
        IMSA_HILOGE("text is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (length > MAX_TEXT_LENGTH) {
        IMSA_HILOGE("text length is too long length=%{public}zu", length);
        return IME_ERR_PARAMCHECK;
    }
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return ErrorCodeConvert(instance->OnSelectionChange(std::u16string(text, length), start, end));
}
InputMethod_ErrorCode OH_InputMethodProxy_NotifyConfigurationChange(InputMethod_InputMethodProxy *inputMethodProxy,
    InputMethod_EnterKeyType enterKey, InputMethod_TextInputType textType)
{
    NativeSessionGuard sessionGuard;
    if (!sessionGuard.IsAcquired()) {
        IMSA_HILOGE("Concurrent or reentrant C session operation rejected; wait for the current operation to finish.");
        return IME_ERR_IMCLIENT;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }
    Configuration info;
    info.SetEnterKeyType(static_cast<EnterKeyType>(enterKey));
    info.SetTextInputType(static_cast<TextInputType>(textType));
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return ErrorCodeConvert(instance->OnConfigurationChange(info));
}

InputMethod_ErrorCode OH_InputMethodProxy_NotifyCursorUpdate(
    InputMethod_InputMethodProxy *inputMethodProxy, InputMethod_CursorInfo *cursorInfo)
{
    NativeSessionGuard sessionGuard;
    if (!sessionGuard.IsAcquired()) {
        IMSA_HILOGE("Concurrent or reentrant C session operation rejected; wait for the current operation to finish.");
        return IME_ERR_IMCLIENT;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }
    if (cursorInfo == nullptr) {
        IMSA_HILOGE("cursorInfo is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = NativeObjectRegistry<InputMethod_CursorInfo>::GetInstance().Get(cursorInfo);
    if (lease == nullptr) {
        IMSA_HILOGE("InputMethod_CursorInfo is unregistered or no longer valid.");
        return IME_ERR_PARAMCHECK;
    }
    CursorInfo info;
    info.left = cursorInfo->left;
    info.top = cursorInfo->top;
    info.width = cursorInfo->width;
    info.height = cursorInfo->height;
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return ErrorCodeConvert(instance->OnCursorUpdate(info));
}

InputMethod_ErrorCode OH_InputMethodProxy_SendPrivateCommand(
    InputMethod_InputMethodProxy *inputMethodProxy, InputMethod_PrivateCommand *privateCommand[], size_t size)
{
    NativeSessionGuard sessionGuard;
    if (!sessionGuard.IsAcquired()) {
        IMSA_HILOGE("Concurrent or reentrant C session operation rejected; wait for the current operation to finish.");
        return IME_ERR_IMCLIENT;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }
    if (privateCommand == nullptr) {
        IMSA_HILOGE("privateCommand is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (size > MAX_SYS_PRIVATE_COMMAND_COUNT) {
        IMSA_HILOGE("privateCommand size is too large: %{public}zu", size);
        return IME_ERR_PARAMCHECK;
    }

    std::unordered_map<std::string, PrivateDataValue> command;
    for (size_t i = 0; i < size; i++) {
        if (privateCommand[i] == nullptr) {
            IMSA_HILOGE("privateCommand[%zu] is nullptr", i);
            return IME_ERR_NULL_POINTER;
        }
        auto value = NativeObjectRegistry<InputMethod_PrivateCommand>::GetInstance().Get(privateCommand[i]);
        if (value == nullptr) {
            IMSA_HILOGE("Private command at index %{public}zu is unregistered or expired.", i);
            return IME_ERR_PARAMCHECK;
        }
        command.emplace(value->key, value->value);
    }
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return ErrorCodeConvert(instance->SendPrivateCommand(command));
}

InputMethod_ErrorCode OH_InputMethodProxy_SendMessage(InputMethod_InputMethodProxy *inputMethodProxy,
    const char16_t *msgId, size_t msgIdLength, const uint8_t *msgParam, size_t msgParamLength)
{
    NativeSessionGuard sessionGuard;
    if (!sessionGuard.IsAcquired()) {
        IMSA_HILOGE("Concurrent or reentrant C session operation rejected; wait for the current operation to finish.");
        return IME_ERR_IMCLIENT;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }
    if (msgId == nullptr || msgParam == nullptr) {
        IMSA_HILOGE("msgId or msgParam is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (msgIdLength > INVALID_MSG_ID_SIZE || msgParamLength > INVALID_MSG_PARAM_SIZE) {
        IMSA_HILOGE("ArrayBuffer size is invalid, msgIdLength: %{public}zu, msgParamLength: %{public}zu",
            msgIdLength, msgParamLength);
        return IME_ERR_PARAMCHECK;
    }
    ArrayBuffer arrayBuffer;
    std::u16string msgIdStr(msgId, msgIdLength);
    arrayBuffer.msgId = Str16ToStr8(msgIdStr);
    arrayBuffer.msgParam.assign(msgParam, msgParam + msgParamLength);
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return ErrorCodeConvert(instance->SendMessage(arrayBuffer));
}

InputMethod_ErrorCode OH_InputMethodProxy_RecvMessage(
    InputMethod_InputMethodProxy *inputMethodProxy, InputMethod_MessageHandlerProxy *messageHandler)
{
    NativeSessionGuard sessionGuard;
    if (!sessionGuard.IsAcquired()) {
        IMSA_HILOGE("Concurrent or reentrant C session operation rejected; wait for the current operation to finish.");
        return IME_ERR_IMCLIENT;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }
    auto handler = NativeObjectRegistry<InputMethod_MessageHandlerProxy>::GetInstance().Get(messageHandler);
    if (messageHandler != nullptr && handler == nullptr) {
        IMSA_HILOGE("Message handler is unregistered or destroyed.");
        return IME_ERR_PARAMCHECK;
    }
    if (IsValidMessageHandlerProxy(handler) != IME_ERR_OK) {
        IMSA_HILOGE("invalid messageHandler");
        return IME_ERR_NULL_POINTER;
    }
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (messageHandler == nullptr) {
        IMSA_HILOGI("UnRegister message handler.");
        return ErrorCodeConvert(instance->RegisterMsgHandler(nullptr));
    }
    IMSA_HILOGI("Register message handler.");
    std::shared_ptr<MsgHandlerCallbackInterface> msgHandler =
        std::make_shared<NativeMessageHandlerCallback>(messageHandler);
    return ErrorCodeConvert(instance->RegisterMsgHandler(msgHandler));
}

InputMethod_ErrorCode OH_InputMethod_InputMethodProxy_RequestSystemInputCapability(
    InputMethod_InputMethodProxy *inputMethodProxy, OH_InputMethod_InputCapabilityType type)
{
    if (type < OH_INPUTMETHOD_INPUT_CAPABILITY_TYPE_TRANSLATION ||
        type >= OH_INPUTMETHOD_INPUT_CAPABILITY_TYPE_END) {
        IMSA_HILOGE("invalid type=%{public}d", static_cast<int32_t>(type));
        return IME_ERR_PARAMCHECK;
    }
    auto errCode = IsValidInputMethodProxy(inputMethodProxy);
    if (errCode != IME_ERR_OK) {
        IMSA_HILOGE("invalid state, errCode=%{public}d", errCode);
        return errCode;
    }
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto ret = instance->RequestSystemInputCapability(static_cast<InputCapabilityType>(type));
    return ErrorCodeConvert(ret);
}
#ifdef __cplusplus
}
#endif /* __cplusplus */
