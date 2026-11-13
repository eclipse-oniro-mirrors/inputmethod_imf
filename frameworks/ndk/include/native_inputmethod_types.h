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
#ifndef NATIVE_INPUTMETHOD_TYPES_H
#define NATIVE_INPUTMETHOD_TYPES_H
#include <atomic>
#include <string>
#include <variant>

#include "inputmethod_controller_capi.h"
#include "inputmethod_preview_text_style_capi.h"
constexpr int32_t MAX_PLACEHOLDER_SIZE = 255;  // 255 utf-16 chars
constexpr int32_t MAX_ABILITY_NAME_SIZE = 127; // 127 utf-16 chars
// Maximum size of char16_t string, including the null terminator (0x0000).
// The range of one UTF16 encoded character is [1,2] char16_t.
constexpr size_t MAX_PLACEHOLDER_INPUT_SIZE = MAX_PLACEHOLDER_SIZE * 2 + 1;
// Maximum size of char16_t string, including the null terminator (0x0000).
constexpr size_t MAX_ABILITY_NAME_INPUT_SIZE = MAX_ABILITY_NAME_SIZE * 2 + 1;
constexpr char16_t UTF16_ENDING_SYMBOL = u'\0';
constexpr size_t ENDING_SYMBOL_SIZE = 1;

struct InputMethod_PrivateCommand {
    std::string key;
    std::variant<std::string, bool, int32_t> value;
};

struct InputMethod_CursorInfo {
    double left = -1.0;
    double top = -1.0;
    double width = -1.0;
    double height = -1.0;
};

struct InputMethod_TextAvoidInfo {
    double positionY;
    double height;
};

struct OH_InputMethod_PreviewTextStyle {
    OH_InputMethod_UnderlineStyle underlineStyle = OH_INPUTMETHOD_UNDERLINE_STYLE_NONE;
    uint32_t underlineColor = 0;
    bool hasUnderlineColor = false;
};
struct InputMethod_TextConfig {
    InputMethod_TextInputType inputType;
    InputMethod_EnterKeyType enterKeyType;
    bool previewTextSupported;
    InputMethod_CursorInfo cursorInfo;
    InputMethod_TextAvoidInfo avoidInfo;
    int32_t selectionStart;
    int32_t selectionEnd;
    int32_t windowId;
    char16_t placeholder[MAX_PLACEHOLDER_INPUT_SIZE];
    size_t placeholderLength = 1;
    char16_t abilityName[MAX_ABILITY_NAME_INPUT_SIZE];
    size_t abilityNameLength = 1;
    bool consumeKeyEvents = false;
};

struct InputMethod_MessageHandlerProxy {
    std::atomic<OH_MessageHandlerProxy_OnTerminatedFunc> onTerminatedFunc { nullptr };
    std::atomic<OH_MessageHandlerProxy_OnMessageFunc> onMessageFunc { nullptr };
};

struct InputMethod_TextEditorProxy {
    std::atomic<OH_TextEditorProxy_GetTextConfigFunc> getTextConfigFunc { nullptr };
    std::atomic<OH_TextEditorProxy_InsertTextFunc> insertTextFunc { nullptr };
    std::atomic<OH_TextEditorProxy_DeleteForwardFunc> deleteForwardFunc { nullptr };
    std::atomic<OH_TextEditorProxy_DeleteBackwardFunc> deleteBackwardFunc { nullptr };
    std::atomic<OH_TextEditorProxy_SendKeyboardStatusFunc> sendKeyboardStatusFunc { nullptr };
    std::atomic<OH_TextEditorProxy_SendEnterKeyFunc> sendEnterKeyFunc { nullptr };
    std::atomic<OH_TextEditorProxy_MoveCursorFunc> moveCursorFunc { nullptr };
    std::atomic<OH_TextEditorProxy_HandleSetSelectionFunc> handleSetSelectionFunc { nullptr };
    std::atomic<OH_TextEditorProxy_HandleExtendActionFunc> handleExtendActionFunc { nullptr };
    std::atomic<OH_TextEditorProxy_GetLeftTextOfCursorFunc> getLeftTextOfCursorFunc { nullptr };
    std::atomic<OH_TextEditorProxy_GetRightTextOfCursorFunc> getRightTextOfCursorFunc { nullptr };
    std::atomic<OH_TextEditorProxy_GetTextIndexAtCursorFunc> getTextIndexAtCursorFunc { nullptr };
    std::atomic<OH_TextEditorProxy_ReceivePrivateCommandFunc> receivePrivateCommandFunc { nullptr };
    std::atomic<OH_TextEditorProxy_SetPreviewTextFunc> setPreviewTextFunc { nullptr };
    OH_InputMethod_TextEditorProxy_SetPreviewTextWithStyleFunc setPreviewTextWithStyleFunc;
    std::atomic<OH_TextEditorProxy_FinishTextPreviewFunc> finishTextPreviewFunc { nullptr };
    std::atomic_bool isCallbackInMainThread = false;
};

struct InputMethod_AttachOptions {
    bool showKeyboard;
    InputMethod_RequestKeyboardReason requestKeyboardReason =
        InputMethod_RequestKeyboardReason::IME_REQUEST_REASON_NONE;
};
constexpr int32_t MAX_TEXT_LENGTH = 8 * 1024;
#endif // NATIVE_INPUTMETHOD_TYPES_H
