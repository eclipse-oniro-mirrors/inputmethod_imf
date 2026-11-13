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
#include "native_text_changed_listener.h"
#include "input_method_utils.h"
#include "native_inputmethod_utils.h"
#include "native_object_registry.h"
#include "text_editor_proxy_manager.h"

namespace OHOS {
namespace MiscServices {
NativeTextChangedListener::NativeTextChangedListener(InputMethod_TextEditorProxy *textEditor)
    : textEditor_(TextEditorProxyManager::GetInstance().GetWeak(textEditor))
{
}
void NativeTextChangedListener::InsertText(const std::u16string &text)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return;
    }

    auto callback = proxy->insertTextFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("insertTextFunc is nullptr");
        return;
    }

    callback(proxy.get(), text.c_str(), text.length());
}

void NativeTextChangedListener::DeleteForward(int32_t length)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return;
    }

    auto callback = proxy->deleteForwardFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("deleteForwardFunc is nullptr");
        return;
    }

    callback(proxy.get(), length);
}

void NativeTextChangedListener::DeleteBackward(int32_t length)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return;
    }

    auto callback = proxy->deleteBackwardFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("deleteBackwardFunc is nullptr");
        return;
    }

    callback(proxy.get(), length);
}

void NativeTextChangedListener::SendKeyboardStatus(const OHOS::MiscServices::KeyboardStatus &status)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return;
    }

    auto callback = proxy->sendKeyboardStatusFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("sendKeyboardStatusFunc is nullptr");
        return;
    }

    callback(proxy.get(), ConvertToCKeyboardStatus(status));
}

void NativeTextChangedListener::SendFunctionKey(const OHOS::MiscServices::FunctionKey &functionKey)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return;
    }

    auto callback = proxy->sendEnterKeyFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("sendEnterKeyFunc is nullptr");
        return;
    }

    auto enterKeyType = ConvertToCEnterKeyType(functionKey.GetEnterKeyType());

    callback(proxy.get(), enterKeyType);
}

void NativeTextChangedListener::MoveCursor(const OHOS::MiscServices::Direction direction)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return;
    }

    auto callback = proxy->moveCursorFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("moveCursorFunc is nullptr");
        return;
    }

    callback(proxy.get(), ConvertToCDirection(direction));
}

void NativeTextChangedListener::HandleSetSelection(int32_t start, int32_t end)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return;
    }

    auto callback = proxy->handleSetSelectionFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("handleSetSelectionFunc is nullptr");
        return;
    }

    callback(proxy.get(), start, end);
}

void NativeTextChangedListener::HandleExtendAction(int32_t action)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return;
    }

    auto callback = proxy->handleExtendActionFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("handleExtendActionFunc is nullptr");
        return;
    }

    callback(proxy.get(), ConvertToCExtendAction(action));
}

std::u16string NativeTextChangedListener::GetLeftTextOfCursor(int32_t number)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return u"";
    }

    auto callback = proxy->getLeftTextOfCursorFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("getLeftTextOfCursorFunc is nullptr");
        return u"";
    }

    if (number <= 0 || number > MAX_TEXT_LENGTH) {
        IMSA_HILOGE("number is invalid");
        return u"";
    }

    size_t bufferSize = static_cast<size_t>(number + 1);
    std::vector<char16_t> text(bufferSize);
    size_t realLength = static_cast<size_t>(number);

    callback(proxy.get(), number, text.data(), &realLength);
    if (realLength > static_cast<size_t>(number)) {
        IMSA_HILOGE("realLength > number");
        return u"";
    }

    std::u16string textStr(text.data(), realLength);
    return textStr;
}

std::u16string NativeTextChangedListener::GetRightTextOfCursor(int32_t number)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return u"";
    }

    auto callback = proxy->getRightTextOfCursorFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("getRightTextOfCursorFunc is nullptr");
        return u"";
    }

    if (number <= 0 || number > MAX_TEXT_LENGTH) {
        IMSA_HILOGE("number is invalid");
        return u"";
    }

    size_t bufferSize = static_cast<size_t>(number + 1);
    std::vector<char16_t> text(bufferSize);
    size_t realLength = static_cast<size_t>(number);

    callback(proxy.get(), number, text.data(), &realLength);
    if (realLength > static_cast<size_t>(number)) {
        IMSA_HILOGE("realLength > number");
        return u"";
    }
    std::u16string textStr(text.data(), realLength);
    return textStr;
}

int32_t NativeTextChangedListener::GetTextIndexAtCursor()
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return 0;
    }

    auto callback = proxy->getTextIndexAtCursorFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("getTextIndexAtCursorFunc is nullptr");
        return 0;
    }

    return callback(proxy.get());
}

int32_t NativeTextChangedListener::ReceivePrivateCommand(
    const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    auto callback = proxy->receivePrivateCommandFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("receivePrivateCommandFunc is nullptr");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    std::vector<NativeObjectScope<InputMethod_PrivateCommand>> borrowed;
    std::vector<InputMethod_PrivateCommand *> command;
    borrowed.reserve(privateCommand.size());
    command.reserve(privateCommand.size());
    for (const auto &item : privateCommand) {
        borrowed.emplace_back();
        auto value = borrowed.back().Get();
        if (value == nullptr) {
            IMSA_HILOGE("Failed to allocate callback private command.");
            return ErrorCode::ERROR_NULL_POINTER;
        }
        value->key = item.first;
        value->value = item.second;
        command.push_back(value);
    }
    return callback(proxy.get(), command.data(), command.size());
}

int32_t NativeTextChangedListener::SetPreviewText(const std::u16string &text, const OHOS::MiscServices::Range &range)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    auto callback = proxy->setPreviewTextFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("setPreviewTextFunc is nullptr");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    return callback(proxy.get(), text.c_str(), text.length(), range.start, range.end);
}

int32_t NativeTextChangedListener::SetPreviewTextWithStyle(
    const std::u16string &text, const OHOS::MiscServices::Range &range, const PreviewTextStyleInner &style)
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    if (proxy->setPreviewTextWithStyleFunc == nullptr) {
        IMSA_HILOGE("setPreviewTextWithStyleFunc is nullptr");
        return ErrorCode::NO_ERROR;
    }
    OH_InputMethod_PreviewTextStyle cStyle {};
    cStyle.underlineStyle = static_cast<OH_InputMethod_UnderlineStyle>(style.underlineStyle);
    cStyle.underlineColor = style.underlineColor;
    cStyle.hasUnderlineColor = style.hasUnderlineColor;
    return proxy->setPreviewTextWithStyleFunc(
        proxy.get(), text.c_str(), static_cast<uint32_t>(text.length()), range.start, range.end, &cStyle);
}

void NativeTextChangedListener::FinishTextPreview()
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return;
    }

    auto callback = proxy->finishTextPreviewFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("finishTextPreviewFunc is nullptr");
        return;
    }

    callback(proxy.get());
}

void NativeTextChangedListener::OnDetach()
{
    ClearInputMethodProxy();
}

std::shared_ptr<AppExecFwk::EventHandler> NativeTextChangedListener::GetEventHandler()
{
    auto proxy = textEditor_.lock();
    if (proxy == nullptr) {
        IMSA_HILOGE("textEditor_ is nullptr");
        return nullptr;
    }

    if (!proxy->isCallbackInMainThread) {
        return nullptr;
    }

    return GetMainHandler();
}

InputMethod_KeyboardStatus NativeTextChangedListener::ConvertToCKeyboardStatus(KeyboardStatus status)
{
    switch (status) {
        case OHOS::MiscServices::KeyboardStatus::HIDE:
            return IME_KEYBOARD_STATUS_HIDE;
        case OHOS::MiscServices::KeyboardStatus::SHOW:
            return IME_KEYBOARD_STATUS_SHOW;
        default:
            return IME_KEYBOARD_STATUS_NONE;
    }
}

InputMethod_EnterKeyType NativeTextChangedListener::ConvertToCEnterKeyType(
    OHOS::MiscServices::EnterKeyType enterKeyType)
{
    switch (enterKeyType) {
        case OHOS::MiscServices::EnterKeyType::NONE:
            return IME_ENTER_KEY_NONE;
        case OHOS::MiscServices::EnterKeyType::GO:
            return IME_ENTER_KEY_GO;
        case OHOS::MiscServices::EnterKeyType::SEARCH:
            return IME_ENTER_KEY_SEARCH;
        case OHOS::MiscServices::EnterKeyType::SEND:
            return IME_ENTER_KEY_SEND;
        case OHOS::MiscServices::EnterKeyType::NEXT:
            return IME_ENTER_KEY_NEXT;
        case OHOS::MiscServices::EnterKeyType::DONE:
            return IME_ENTER_KEY_DONE;
        case OHOS::MiscServices::EnterKeyType::PREVIOUS:
            return IME_ENTER_KEY_PREVIOUS;
        case OHOS::MiscServices::EnterKeyType::NEW_LINE:
            return IME_ENTER_KEY_NEWLINE;
        default:
            return IME_ENTER_KEY_UNSPECIFIED;
    }
}

InputMethod_Direction NativeTextChangedListener::ConvertToCDirection(OHOS::MiscServices::Direction direction)
{
    switch (direction) {
        case OHOS::MiscServices::Direction::NONE:
            return IME_DIRECTION_NONE;
        case OHOS::MiscServices::Direction::UP:
            return IME_DIRECTION_UP;
        case OHOS::MiscServices::Direction::DOWN:
            return IME_DIRECTION_DOWN;
        case OHOS::MiscServices::Direction::LEFT:
            return IME_DIRECTION_LEFT;
        case OHOS::MiscServices::Direction::RIGHT:
            return IME_DIRECTION_RIGHT;
        default:
            return IME_DIRECTION_NONE;
    }
}

InputMethod_ExtendAction NativeTextChangedListener::ConvertToCExtendAction(int32_t action)
{
    switch (action) {
        case static_cast<int32_t>(OHOS::MiscServices::ExtendAction::SELECT_ALL):
            return IME_EXTEND_ACTION_SELECT_ALL;
        case static_cast<int32_t>(OHOS::MiscServices::ExtendAction::CUT):
            return IME_EXTEND_ACTION_CUT;
        case static_cast<int32_t>(OHOS::MiscServices::ExtendAction::COPY):
            return IME_EXTEND_ACTION_COPY;
        case static_cast<int32_t>(OHOS::MiscServices::ExtendAction::PASTE):
            return IME_EXTEND_ACTION_PASTE;
        default:
            IMSA_HILOGE("invalid action:%{public}d", action);
            return IME_EXTEND_ACTION_SELECT_ALL;
    }
}

std::shared_ptr<AppExecFwk::EventHandler> NativeTextChangedListener::GetMainHandler()
{
    std::lock_guard<std::mutex> lock(mainHandlerMtx_);
    if (mainHandler_ != nullptr) {
        return mainHandler_;
    }
    auto mainRunner = AppExecFwk::EventRunner::GetMainEventRunner();
    if (mainRunner == nullptr) {
        IMSA_HILOGE("GetMainEventRunner failed");
        return nullptr;
    }

    mainHandler_ = std::make_shared<AppExecFwk::EventHandler>(mainRunner);
    IMSA_HILOGI("success");
    return mainHandler_;
}
} // namespace MiscServices
} // namespace OHOS
