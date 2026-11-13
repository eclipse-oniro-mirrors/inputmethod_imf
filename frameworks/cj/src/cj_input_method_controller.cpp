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

#include <string>
#include <locale>
#include <codecvt>

#include "cj_input_method_controller.h"
#include "cj_input_method_textchanged_listener.h"
#include "cj_lambda.h"
#include "utils.h"
#include "string_ex.h"

namespace OHOS {
namespace MiscServices {
namespace {
template <typename Callback, typename Factory>
void ReplaceCallback(std::recursive_mutex &mutex, Callback &target, Factory makeCallback)
{
    // Release the replaced CJ callback only after the writer lock is released.
    Callback next;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex);
        next = makeCallback();
        target.swap(next);
    }
}
} // namespace
std::mutex CjInputMethodController::controllerMutex_;
std::shared_ptr<CjInputMethodController> CjInputMethodController::controller_{ nullptr };
const int8_t INSERT_TEXT = 0;
const int8_t DELETE_LEFT = 1;
const int8_t DELETE_RIGHT = 2;
const int8_t SEND_KEYBOARD_STATUS = 3;
const int8_t SEND_FUNCTION_KEY = 4;
const int8_t MOVE_CURSOR = 5;
const int8_t HANDLE_EXTEND_ACTION = 6;
const int8_t GET_LEFT_TEXT = 7;
const int8_t GET_RIGHT_TEXT = 8;
const int8_t GET_TEXT_INDEX = 9;
const int8_t SELECT_BY_MOVEMENT = 10;
const int8_t SELECT_BY_RANGE = 11;

std::shared_ptr<CjInputMethodController> CjInputMethodController::GetInstance()
{
    if (controller_ == nullptr) {
        std::lock_guard<std::mutex> lock(controllerMutex_);
        if (controller_ == nullptr) {
            auto controller = std::make_shared<CjInputMethodController>();
            controller_ = controller;
            auto inputMethodController = InputMethodController::GetInstance();
            if (inputMethodController != nullptr) {
                inputMethodController->SetControllerListener(controller_);
            }
        }
    }
    return controller_;
}

int32_t CjInputMethodController::Attach(const CTextConfig &txtCfg, const AttachOptions &attachOptions)
{
    auto textListener = CjInputMethodTextChangedListener::GetInstance();
    if (textListener == nullptr) {
        IMSA_HILOGE("failed to create CjInputMethodTextChangedListener!");
        return ERR_NO_MEMORY;
    }
    TextConfig textCfg;
    textCfg.inputAttribute.inputPattern = txtCfg.inputAttrbute.textInputType;
    textCfg.inputAttribute.enterKeyType = txtCfg.inputAttrbute.enterKeyType;
    textCfg.cursorInfo.left = txtCfg.cursor.left;
    textCfg.cursorInfo.top = txtCfg.cursor.top;
    textCfg.cursorInfo.width = txtCfg.cursor.width;
    textCfg.cursorInfo.height = txtCfg.cursor.height;
    textCfg.range.start = txtCfg.range.start;
    textCfg.range.end = txtCfg.range.end;
    textCfg.windowId = txtCfg.windowId;

    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    return controller->Attach(textListener, attachOptions, textCfg, ClientType::CJ);
}

int32_t CjInputMethodController::Detach()
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    return controller->Close();
}

int32_t CjInputMethodController::ShowTextInput(const AttachOptions &attachOptions)
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    return controller->ShowTextInput(attachOptions, ClientType::CJ);
}

int32_t CjInputMethodController::HideTextInput()
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    return controller->HideTextInput();
}

int32_t CjInputMethodController::SetCallingWindow(uint32_t windowId)
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    return controller->SetCallingWindow(windowId);
}

int32_t CjInputMethodController::UpdateCursor(const CCursorInfo &cursor)
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    CursorInfo cursorInfo;
    cursorInfo.left = cursor.left;
    cursorInfo.top = cursor.top;
    cursorInfo.width = cursor.width;
    cursorInfo.height = cursor.height;
    return controller->OnCursorUpdate(cursorInfo);
}

int32_t CjInputMethodController::ChangeSelection(const std::string &text, int32_t start, int32_t end)
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    std::u16string txt = converter.from_bytes(text);
    return controller->OnSelectionChange(txt, start, end);
}

int32_t CjInputMethodController::UpdateAttribute(const CInputAttribute &inputAttribute)
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    Configuration config = Configuration();
    config.SetTextInputType(static_cast<TextInputType>(inputAttribute.textInputType));
    config.SetEnterKeyType(static_cast<EnterKeyType>(inputAttribute.enterKeyType));
    return controller->OnConfigurationChange(config);
}

int32_t CjInputMethodController::ShowSoftKeyboard()
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    return controller->ShowSoftKeyboard(ClientType::CJ);
}

int32_t CjInputMethodController::HideSoftKeyboard()
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    return controller->HideSoftKeyboard();
}

int32_t CjInputMethodController::StopInputSession()
{
    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    return controller->StopInputSession();
}

void CjInputMethodController::RegisterListener(int8_t type, int64_t id)
{
    switch (type) {
        case INSERT_TEXT:
            InitInsertText(id);
            break;
        case DELETE_LEFT:
            InitDeleteRight(id);
            break;
        case DELETE_RIGHT:
            InitDeleteLeft(id);
            break;
        case SEND_KEYBOARD_STATUS:
            InitSendKeyboardStatus(id);
            break;
        case SEND_FUNCTION_KEY:
            InitSendFunctionKey(id);
            break;
        case MOVE_CURSOR:
            InitMoveCursor(id);
            break;
        case HANDLE_EXTEND_ACTION:
            InitHandleExtendAction(id);
            break;
        case GET_LEFT_TEXT:
            InitGetLeftText(id);
            break;
        case GET_RIGHT_TEXT:
            InitGetRightText(id);
            break;
        case GET_TEXT_INDEX:
            InitGetTextIndexAtCursor(id);
            break;
        case SELECT_BY_MOVEMENT:
            InitSelectByMovement(id);
            break;
        case SELECT_BY_RANGE:
            InitSelectByRange(id);
            break;
        default:
            return;
    }
}

void CjInputMethodController::UnRegisterListener(int8_t type)
{
    auto emptyCallback = []() {
        return nullptr;
    };
    switch (type) {
        case INSERT_TEXT:
            ReplaceCallback(mutex_, insertText, emptyCallback);
            break;
        case DELETE_LEFT:
            ReplaceCallback(mutex_, deleteLeft, emptyCallback);
            break;
        case DELETE_RIGHT:
            ReplaceCallback(mutex_, deleteRight, emptyCallback);
            break;
        case SEND_KEYBOARD_STATUS:
            ReplaceCallback(mutex_, sendKeyboardStatus, emptyCallback);
            break;
        case SEND_FUNCTION_KEY:
            ReplaceCallback(mutex_, sendFunctionKey, emptyCallback);
            break;
        case MOVE_CURSOR:
            ReplaceCallback(mutex_, moveCursor, emptyCallback);
            break;
        case HANDLE_EXTEND_ACTION:
            ReplaceCallback(mutex_, handleExtendAction, emptyCallback);
            break;
        case GET_LEFT_TEXT:
            ReplaceCallback(mutex_, getLeftText, emptyCallback);
            break;
        case GET_RIGHT_TEXT:
            ReplaceCallback(mutex_, getRightText, emptyCallback);
            break;
        case GET_TEXT_INDEX:
            ReplaceCallback(mutex_, getTextIndexAtCursor, emptyCallback);
            break;
        case SELECT_BY_MOVEMENT:
            ReplaceCallback(mutex_, onSelectByMovement, emptyCallback);
            break;
        case SELECT_BY_RANGE:
            ReplaceCallback(mutex_, onSelectByRange, emptyCallback);
            break;
        default:
            return;
    }
}

int32_t CjInputMethodController::Subscribe(int8_t type, int64_t id)
{
    auto controller = CjInputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    controller->RegisterListener(type, id);
    return SUCCESS_CODE;
}

int32_t CjInputMethodController::Unsubscribe(int8_t type)
{
    auto controller = CjInputMethodController::GetInstance();
    if (controller == nullptr) {
        return ERR_NO_MEMORY;
    }
    controller->UnRegisterListener(type);
    return SUCCESS_CODE;
}

void CjInputMethodController::OnSelectByRange(int32_t start, int32_t end)
{
    decltype(onSelectByRange) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = onSelectByRange;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("onSelectByRange null.");
        return;
    }
    IMSA_HILOGD("onSelelctByRange runs.");
    Range range;
    range.start = start;
    range.end = end;
    return callback(range);
}

void CjInputMethodController::OnSelectByMovement(int32_t direction)
{
    decltype(onSelectByMovement) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = onSelectByMovement;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("onSelectByMovement null.");
        return;
    }
    IMSA_HILOGD("onSelectByMovement runs.");
    return callback(direction);
}

void CjInputMethodController::InsertText(const std::u16string &text)
{
    char *insertTxt = Utils::MallocCString(Str16ToStr8(text));
    if (insertTxt == nullptr) {
        IMSA_HILOGE("Failed to excute InsertText callback: out of memory.");
        return;
    }
    decltype(insertText) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = insertText;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("insertText null.");
        free(insertTxt);
        return;
    }
    IMSA_HILOGD("insertText runs.");
    callback(insertTxt);
    free(insertTxt);
    return;
}

void CjInputMethodController::DeleteRight(int32_t length)
{
    decltype(deleteRight) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = deleteRight;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("deleteRight null.");
        return;
    }
    IMSA_HILOGD("deleteRight runs.");
    callback(length);
    return;
}

void CjInputMethodController::DeleteLeft(int32_t length)
{
    decltype(deleteLeft) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = deleteLeft;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("deleteLeft null.");
        return;
    }
    IMSA_HILOGD("deleteLeft runs.");
    callback(length);
    return;
}

void CjInputMethodController::SendKeyboardStatus(const KeyboardStatus &status)
{
    decltype(sendKeyboardStatus) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = sendKeyboardStatus;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("sendKeyboardStatus null.");
        return;
    }
    IMSA_HILOGD("sendKeyboardStatus runs.");
    auto statusNum = static_cast<int32_t>(status);
    callback(statusNum);
    return;
}

void CjInputMethodController::SendFunctionKey(const FunctionKey &functionKey)
{
    decltype(sendFunctionKey) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = sendFunctionKey;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("sendFunctionKey null.");
        return;
    }
    IMSA_HILOGD("sendFunctionKey runs.");
    auto type = static_cast<int32_t>(functionKey.GetEnterKeyType());
    callback(type);
    return;
}

void CjInputMethodController::MoveCursor(const Direction direction)
{
    decltype(moveCursor) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = moveCursor;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("moveCursor null.");
        return;
    }
    IMSA_HILOGD("moveCursor runs.");
    auto dir = static_cast<int32_t>(direction);
    callback(dir);
    return;
}

void CjInputMethodController::HandleExtendAction(int32_t action)
{
    decltype(handleExtendAction) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = handleExtendAction;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("handleExtendAction null.");
        return;
    }
    IMSA_HILOGD("handleExtendAction runs.");
    callback(action);
    return;
}

std::u16string CjInputMethodController::GetLeftText(int32_t number)
{
    decltype(getLeftText) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = getLeftText;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("getLeftText null.");
        return u"";
    }
    IMSA_HILOGD("getLeftText runs.");
    char *text = callback(number);
    if (text == nullptr) {
        IMSA_HILOGE("text is nullptr.");
        return u"";
    }
    auto ret = Str8ToStr16(std::string(text));
    free(text);
    return ret;
}

std::u16string CjInputMethodController::GetRightText(int32_t number)
{
    decltype(getRightText) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = getRightText;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("getRightText null.");
        return u"";
    }
    IMSA_HILOGD("getRightText runs.");
    char *text = callback(number);
    if (text == nullptr) {
        IMSA_HILOGE("text is nullptr.");
        return u"";
    }
    auto ret = Str8ToStr16(std::string(text));
    free(text);
    return ret;
}

int32_t CjInputMethodController::GetTextIndexAtCursor()
{
    decltype(getTextIndexAtCursor) callback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        callback = getTextIndexAtCursor;
    }
    if (callback == nullptr) {
        IMSA_HILOGE("getTextIndexAtCursor null.");
        return -1;
    }
    IMSA_HILOGD("getTextIndexAtCursor runs.");
    return callback();
}

void CjInputMethodController::InitInsertText(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(const char*)>(id);
    ReplaceCallback(mutex_, insertText, [callback]() {
        return [lambda = CJLambda::Create(callback)](const char *text) -> void {
            lambda(text);
        };
    });
}

void CjInputMethodController::InitDeleteRight(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(int32_t)>(id);
    ReplaceCallback(mutex_, deleteLeft, [callback]() {
        return [lambda = CJLambda::Create(callback)](int32_t length) -> void {
            lambda(length);
        };
    });
}

void CjInputMethodController::InitDeleteLeft(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(int32_t)>(id);
    ReplaceCallback(mutex_, deleteRight, [callback]() {
        return [lambda = CJLambda::Create(callback)](int32_t length) -> void {
            lambda(length);
        };
    });
}

void CjInputMethodController::InitSendKeyboardStatus(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(int32_t)>(id);
    ReplaceCallback(mutex_, sendKeyboardStatus, [callback]() {
        return [lambda = CJLambda::Create(callback)](int32_t status) -> void {
            lambda(status);
        };
    });
}

void CjInputMethodController::InitSendFunctionKey(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(int32_t)>(id);
    ReplaceCallback(mutex_, sendFunctionKey, [callback]() {
        return [lambda = CJLambda::Create(callback)](int32_t functionKey) -> void {
            lambda(functionKey);
        };
    });
}

void CjInputMethodController::InitMoveCursor(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(int32_t)>(id);
    ReplaceCallback(mutex_, moveCursor, [callback]() {
        return [lambda = CJLambda::Create(callback)](int32_t direction) -> void {
            lambda(direction);
        };
    });
}

void CjInputMethodController::InitHandleExtendAction(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(int32_t)>(id);
    ReplaceCallback(mutex_, handleExtendAction, [callback]() {
        return [lambda = CJLambda::Create(callback)](int32_t action) -> void {
            lambda(action);
        };
    });
}

void CjInputMethodController::InitGetLeftText(int64_t id)
{
    auto callback = reinterpret_cast<char*(*)(int32_t)>(id);
    ReplaceCallback(mutex_, getLeftText, [callback]() {
        return [lambda = CJLambda::Create(callback)](int32_t number) {
            return lambda(number);
        };
    });
}

void CjInputMethodController::InitGetRightText(int64_t id)
{
    auto callback = reinterpret_cast<char*(*)(int32_t)>(id);
    ReplaceCallback(mutex_, getRightText, [callback]() {
        return [lambda = CJLambda::Create(callback)](int32_t number) {
            return lambda(number);
        };
    });
}

void CjInputMethodController::InitGetTextIndexAtCursor(int64_t id)
{
    auto callback = reinterpret_cast<int32_t(*)()>(id);
    ReplaceCallback(mutex_, getTextIndexAtCursor, [callback]() {
        return [lambda = CJLambda::Create(callback)](void) -> int32_t {
            return lambda();
        };
    });
}

void CjInputMethodController::InitSelectByMovement(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(int32_t)>(id);
    ReplaceCallback(mutex_, onSelectByMovement, [callback]() {
        return [lambda = CJLambda::Create(callback)](int32_t direction) -> void {
            lambda(direction);
        };
    });
}

void CjInputMethodController::InitSelectByRange(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(Range)>(id);
    ReplaceCallback(mutex_, onSelectByRange, [callback]() {
        return [lambda = CJLambda::Create(callback)](Range range) -> void {
            lambda(range);
        };
    });
}

} // namespace MiscServices
} // namespace OHOS
