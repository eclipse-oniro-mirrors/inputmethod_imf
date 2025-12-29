/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ani_message_handler.h"
#include "input_method_controller_impl.h"
#include <cstdint>
#include "ani_common.h"
#include "input_method_ability.h"
#include "input_method_controller.h"
#include "input_method_text_changed_listener.h"
#include "input_method_utils.h"
#include "js_utils.h"
#include "stdexcept"
#include "string_ex.h"
#include "taihe/runtime.hpp"
#include <iostream>
#include <string>
#include <unicode/unistr.h>
#include <unicode/ucnv.h>

namespace OHOS {
namespace MiscServices {
using namespace taihe;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
std::mutex InputMethodControllerImpl::controllerMutex_;
std::shared_ptr<InputMethodControllerImpl> InputMethodControllerImpl::controller_{ nullptr };
const std::set<std::string> InputMethodControllerImpl::TEXT_EVENT_TYPE{
    "insertText",
    "deleteLeft",
    "deleteRight",
    "sendKeyboardStatus",
    "sendFunctionKey",
    "moveCursor",
    "handleExtendAction",
    "getLeftTextOfCursor",
    "getRightTextOfCursor",
    "getTextIndexAtCursor",
};

std::shared_ptr<InputMethodControllerImpl> InputMethodControllerImpl::GetInstance()
{
    if (controller_ == nullptr) {
        std::lock_guard<std::mutex> lock(controllerMutex_);
        if (controller_ == nullptr) {
            auto controller = std::make_shared<InputMethodControllerImpl>();
            controller_ = controller;
            InputMethodController::GetInstance()->SetControllerListener(controller_);
        }
    }
    return controller_;
}

void InputMethodControllerImpl::HideSoftKeyboardSync()
{
    int32_t errCode = InputMethodController::GetInstance()->HideSoftKeyboard();
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::HideSoftKeyboard failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::HideSoftKeyboard success");
}

void InputMethodControllerImpl::HideSoftKeyboardIdSync(int64_t displayId)
{
    uint64_t id = 0;
    if (displayId >= 0) {
        id = static_cast<uint64_t>(displayId);
    }
    IMSA_HILOGD("target displayId: %{public}" PRIu64 "", id);
    int32_t errCode = InputMethodController::GetInstance()->HideSoftKeyboard(id);
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::HideSoftKeyboard failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::HideSoftKeyboard success");
}

void InputMethodControllerImpl::ShowTextInputHasParam(RequestKeyboardReason_t requestKeyboardReason)
{
    AttachOptions attachOptions;
    attachOptions.requestKeyboardReason = static_cast<RequestKeyboardReason>(requestKeyboardReason.get_value());
    int32_t errCode = InputMethodController::GetInstance()->ShowTextInput(attachOptions, ClientType::JS);
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::ShowTextInput failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::ShowTextInput success");
}

void InputMethodControllerImpl::ShowTextInputSync()
{
    ShowTextInputHasParam(RequestKeyboardReason_t::key_t::NONE);
}

void InputMethodControllerImpl::HideTextInputSync()
{
    int32_t errCode = InputMethodController::GetInstance()->HideTextInput();
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::HideTextInput failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::HideTextInput success");
}

void InputMethodControllerImpl::AttachSync(bool showKeyboard, TextConfig_t const &textConfig)
{
    IMSA_HILOGI("start");
    AttachWithReason(showKeyboard, textConfig, RequestKeyboardReason_t::key_t::NONE);
}

void InputMethodControllerImpl::AttachWithReason(bool showKeyboard, TextConfig_t const &textConfig,
    RequestKeyboardReason_t requestKeyboardReason)
{
    AttachOptions attachOptions;
    attachOptions.isShowKeyboard = showKeyboard;
    attachOptions.requestKeyboardReason = static_cast<RequestKeyboardReason>(requestKeyboardReason.get_value());
    TextConfig config;
    EnumConvert::AniTextConfigToNative(textConfig, config);
    if (IsTextPreviewSupported()) {
        config.inputAttribute.isTextPreviewSupported = true;
    }

    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        IMSA_HILOGI("InputMethodController instance is not nullptr!");
        errCode =
            instance->Attach(InputMethodTextChangedListener::GetInstance(), attachOptions, config, ClientType::JS);
    }
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::Attach failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::Attach success");
}

void InputMethodControllerImpl::AttachWithUIContextSync(uintptr_t uiContext, TextConfig_t const& textConfig,
    taihe::optional_view<AttachOptions_t> attachOptions)
{
    auto context = reinterpret_cast<ani_object>(uiContext);
    if (context == nullptr) {
        IMSA_HILOGE("uiContext is invalid");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, "uiContext is invalid");
        return;
    }
    ani_env* env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr");
        return;
    }
    uint32_t windowId = 0;
    if (!EnumConvert::ParseUiContextGetWindowId(env, context, windowId)) {
        IMSA_HILOGE("uiContext convert failed");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, "uiContext convert failed");
        return;
    }
    TextConfig config;
    EnumConvert::AniTextConfigToNative(textConfig, config);
    config.windowId = windowId;
    if (IsTextPreviewSupported()) {
        config.inputAttribute.isTextPreviewSupported = true;
    }
    AttachOptions opts {};
    if (attachOptions.has_value()) {
        opts = EnumConvert::AniAttachOptionsToNative(attachOptions.value());
    }
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        IMSA_HILOGI("InputMethodController instance is not nullptr!");
        errCode =
            instance->Attach(InputMethodTextChangedListener::GetInstance(), opts, config, ClientType::JS);
    }
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::AttachWithUIContext failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::AttachWithUIContext success");
}

void InputMethodControllerImpl::DetachSync()
{
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("GetInstance return nullptr!");
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        return;
    }
    errCode = instance->Close();
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::Close failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::Close success");
}

void InputMethodControllerImpl::RegisterListener(std::string const &type, callbackType &&cb, uintptr_t opq)
{
    if (TEXT_EVENT_TYPE.find(type) != TEXT_EVENT_TYPE.end()) {
        if (!InputMethodController::GetInstance()->WasAttached()) {
            std::string message = JsUtils::ToMessage(IMFErrorCode::EXCEPTION_DETACHED) + "need to be attached first";
            set_business_error(IMFErrorCode::EXCEPTION_DETACHED, message);
            IMSA_HILOGE("RegisterListener failed, need to be attached first type: %{public}s!", type.c_str());
            return;
        }
    }

    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        IMSA_HILOGE("ani_env is nullptr or GlobalReference_Create failed, type: %{public}s!", type.c_str());
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    bool isDuplicate =
        std::any_of(cbVec.begin(), cbVec.end(), [env, callbackRef](std::unique_ptr<CallbackObject> &obj) {
            ani_boolean isEqual = false;
            return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
        });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        IMSA_HILOGI("callback already registered, type: %{public}s!", type.c_str());
        return;
    }
    cbVec.emplace_back(std::make_unique<CallbackObject>(cb, callbackRef));
    IMSA_HILOGI("register callback success, type: %{public}s!", type.c_str());
}

void InputMethodControllerImpl::UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq)
{
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("ani_env is nullptr!");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const auto iter = jsCbMap_.find(type);
    if (iter == jsCbMap_.end()) {
        IMSA_HILOGE("methodName: %{public}s already unRegistered!", type.c_str());
        return;
    }

    if (!opq.has_value()) {
        for (auto &uniquePtr : iter->second) {
            uniquePtr->Release();
        }
        jsCbMap_.erase(iter);
        UpdateTextPreviewState(type);
        IMSA_HILOGE("callback is nullptr!");
        return;
    }

    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        IMSA_HILOGE("GlobalRefGuard is false!");
        return;
    }

    const auto pred = [env, targetRef = guard.get()](std::unique_ptr<CallbackObject> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        it->get()->Release();
        callbacks.erase(it);
        IMSA_HILOGI("UnRegisterListener one type:%{public}s", type.c_str());
    }
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
        UpdateTextPreviewState(type);
        IMSA_HILOGI("UnRegisterListener callbacks is empty type:%{public}s", type.c_str());
    }
}

void InputMethodControllerImpl::InsertTextCallback(const std::u16string &text)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["insertText"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(taihe::string_view)>>(cb->callback);
        taihe::string textStr = Str16ToStr8(text);
        func(textStr);
    }
}
void InputMethodControllerImpl::DeleteLeftCallback(int32_t length)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["deleteLeft"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(int32_t)>>(cb->callback);
        func(length);
    }
}
void InputMethodControllerImpl::DeleteRightCallback(int32_t length)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["deleteRight"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(int32_t)>>(cb->callback);
        func(length);
    }
}
void InputMethodControllerImpl::SendKeyboardStatusCallback(const KeyboardStatus &status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["sendKeyboardStatus"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(KeyboardStatus_t)>>(cb->callback);
        KeyboardStatus_t state = EnumConvert::ConvertKeyboardStatus(status);
        func(state);
    }
}
void InputMethodControllerImpl::SendFunctionKeyCallback(const FunctionKey &key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["sendFunctionKey"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(FunctionKey_t const &)>>(cb->callback);
        FunctionKey_t funcKey{ .enterKeyType = EnumConvert::ConvertEnterKeyType(key.GetEnterKeyType()) };
        func(funcKey);
    }
}
void InputMethodControllerImpl::MoveCursorCallback(const Direction &direction)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["moveCursor"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(Direction_t)>>(cb->callback);
        Direction_t directionType = EnumConvert::ConvertDirection(direction);
        func(directionType);
    }
}
void InputMethodControllerImpl::HandleExtendActionCallback(int32_t action)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["handleExtendAction"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(ExtendAction_t)>>(cb->callback);
        ExtendAction_t actionType = EnumConvert::ConvertExtendAction(action);
        func(actionType);
    }
}
std::u16string InputMethodControllerImpl::GetLeftTextOfCursorCallback(int32_t number)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["getLeftTextOfCursor"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<taihe::string(int32_t)>>(cb->callback);
        taihe::string s = func(number);
        return Str8ToStr16(std::string(s));
    }
    return Str8ToStr16(std::string());
}
std::u16string InputMethodControllerImpl::GetRightTextOfCursorCallback(int32_t number)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["getRightTextOfCursor"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<taihe::string(int32_t)>>(cb->callback);
        taihe::string s = func(number);
        return Str8ToStr16(std::string(s));
    }
    return Str8ToStr16(std::string());
}
int32_t InputMethodControllerImpl::GetTextIndexAtCursorCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["getTextIndexAtCursor"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<int32_t()>>(cb->callback);
        return func();
    }
    return 0;
}

int32_t InputMethodControllerImpl::SetPreviewTextCallback(const std::u16string &text, const Range &range)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["setPreviewText"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(taihe::string_view, Range_t const &)>>(cb->callback);
        taihe::string textStr = Str16ToStr8(text);
        Range_t tmpRange { .start = range.start, .end = range.end };
        func(textStr, tmpRange);
    }
    return ErrorCode::NO_ERROR;
}

void InputMethodControllerImpl::FinishTextPreviewCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["finishTextPreview"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(UndefinedType_t const&)>>(cb->callback);
        UndefinedType_t type = UndefinedType_t::make_undefined();
        func(type);
    }
}

void InputMethodControllerImpl::OnSelectByRange(int32_t start, int32_t end)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["selectByRange"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(Range_t const &)>>(cb->callback);
        Range_t range{ .start = start, .end = end };
        func(range);
    }
}
void InputMethodControllerImpl::OnSelectByMovement(int32_t direction)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["selectByMovement"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(Movement_t const &)>>(cb->callback);
        Movement_t movement{ .direction = EnumConvert::ConvertDirection(static_cast<Direction>(direction)) };
        func(movement);
    }
}

void InputMethodControllerImpl::DiscardTypingTextSync()
{
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("GetInstance return nullptr!");
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        return;
    }
    errCode = instance->DiscardTypingText();
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::DiscardTypingText failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::DiscardTypingText success!");
}

void InputMethodControllerImpl::SetCallingWindowSync(int32_t windowId)
{
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        IMSA_HILOGI("InputMethodController instance is not nullptr!");
        errCode = instance->SetCallingWindow(windowId);
    }
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::SetCallingWindow failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::SetCallingWindow success!");
}

void InputMethodControllerImpl::ChangeSelectionSync(::taihe::string_view text, int32_t start, int32_t end)
{
    icu::UnicodeString unicode_str = icu::UnicodeString::fromUTF8(std::string(text));
    int32_t length = unicode_str.length();
    const UChar* utf16_data = unicode_str.getBuffer();
    if (utf16_data == nullptr) {
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, "text is invalid");
        IMSA_HILOGE("InputMethodControllerImpl::ChangeSelection failed, text is invalid!");
        return;
    }
    std::u16string u16_string(reinterpret_cast<const char16_t*>(utf16_data), length);
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        IMSA_HILOGI("InputMethodController instance is not nullptr!");
        errCode = instance->OnSelectionChange(u16_string, start, end);
    }
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::ChangeSelection failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::OnSelectionChange success!");
}

void InputMethodControllerImpl::UpdateAttributeSync(InputAttribute_t const& attribute)
{
    Configuration cfg;
    cfg.SetEnterKeyType(static_cast<OHOS::MiscServices::EnterKeyType>(attribute.enterKeyType.get_value()));
    cfg.SetTextInputType(static_cast<OHOS::MiscServices::TextInputType>(attribute.textInputType.get_value()));
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        IMSA_HILOGI("InputMethodController instance is not nullptr!");
        errCode = instance->OnConfigurationChange(cfg);
    }
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::OnConfigurationChange failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::OnConfigurationChange success!");
}

bool InputMethodControllerImpl::StopInputSessionSync()
{
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodControllerImpl::GetInstance return nullptr!");
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        return false;
    }
    errCode = instance->StopInputSession();
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::StopInputSession failed, errCode: %{public}d!", errCode);
        return false;
    }
    IMSA_HILOGI("InputMethodControllerImpl::StopInputSession success!");
    return true;
}

void InputMethodControllerImpl::ShowSoftKeyboardSync()
{
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodControllerImpl::GetInstance return nullptr!");
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        return;
    }
    errCode = instance->ShowSoftKeyboard(ClientType::JS);
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::ShowSoftKeyboard failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::ShowSoftKeyboard success!");
}

void InputMethodControllerImpl::ShowSoftKeyboardIdSync(int64_t displayId)
{
    uint64_t id = 0;
    if (displayId >= 0) {
        id = static_cast<uint64_t>(displayId);
    }
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodControllerImpl::GetInstance return nullptr!");
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        return;
    }
    IMSA_HILOGD("target displayId: %{public}" PRIu64 "", id);
    errCode = instance->ShowSoftKeyboard(ClientType::JS, id);
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodControllerImpl::ShowSoftKeyboard failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::ShowSoftKeyboard success!");
}

void InputMethodControllerImpl::SendMessageSync(::taihe::string_view msgId,
    ::taihe::optional_view<::taihe::array<uint8_t>> msgParam)
{
    ArrayBuffer arrayBuffer {};
    arrayBuffer.msgId = std::string(msgId);
    arrayBuffer.jsArgc = ARGC_ONE;
    if (msgParam.has_value()) {
        arrayBuffer.jsArgc = ARGC_TWO;
        arrayBuffer.msgParam.resize(msgParam.value().size());
        auto const &value = msgParam.value();
        for (size_t i = 0; i < value.size(); ++i) {
            arrayBuffer.msgParam[i] = value[i];
        }
    }
    if (!ArrayBuffer::IsSizeValid(arrayBuffer)) {
        IMSA_HILOGE("msgId limit 256B and msgParam limit 128KB.");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, "msgId limit 256B and msgParam limit 128KB.");
        return;
    }
    int32_t code = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        IMSA_HILOGI("InputMethodController instance is not nullptr!");
        code = instance->SendMessage(arrayBuffer);
    }
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("InputMethodControllerImpl::SendMessage failed, errCode: %{public}d!", code);
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::SendMessage success!");
}

void InputMethodControllerImpl::recvMessage(::taihe::optional_view<MessageHandler_t> msgHandler)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("InputMethodController instance is not nullptr!");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        return;
    }
    if (msgHandler.has_value()) {
        IMSA_HILOGI("RecvMessage on.");
        std::shared_ptr<MsgHandlerCallbackInterface> callback = std::make_shared<AniMessageHandler>(msgHandler.value());
        instance->RegisterMsgHandler(callback);
    } else {
        IMSA_HILOGI("RecvMessage off.");
        instance->RegisterMsgHandler();
    }
}

void InputMethodControllerImpl::UpdateCursorSync(::ohos::inputMethod::CursorInfo const& cursorInfo)
{
    OHOS::MiscServices::CursorInfo info;
    info.height = cursorInfo.height;
    info.left = cursorInfo.left;
    info.top = cursorInfo.top;
    info.width = cursorInfo.width;
    int32_t errCode = ErrorCode::ERROR_CLIENT_NULL_POINTER;
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        IMSA_HILOGI("InputMethodController instance is not nullptr!");
        errCode = instance->OnCursorUpdate(info);
    }
    if (errCode != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        IMSA_HILOGE("InputMethodController::OnCursorUpdate failed, errCode: %{public}d!", errCode);
        return;
    }
    IMSA_HILOGI("InputMethodControllerImpl::OnCursorUpdate success!");
}

void InputMethodControllerImpl::UpdateTextPreviewState(const std::string &type)
{
    if (type == "setPreviewText" || type == "finishTextPreview") {
        auto instance = InputMethodController::GetInstance();
        if (instance == nullptr) {
            IMSA_HILOGE("GetInstance() is nullptr!");
            return;
        }
        instance->UpdateTextPreviewState(false);
    }
}

bool InputMethodControllerImpl::IsRegister(const std::string &type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (jsCbMap_.empty() || jsCbMap_.find(type) == jsCbMap_.end()) {
        IMSA_HILOGD("methodName: %{public}s is not registered!", type.c_str());
        return false;
    }
    if (jsCbMap_[type].empty()) {
        IMSA_HILOGD("methodName: %{public}s cb-vector is empty!", type.c_str());
        return false;
    }
    return true;
}

bool InputMethodControllerImpl::IsTextPreviewSupported()
{
    return IsRegister("setPreviewText") && IsRegister("finishTextPreview");
}
} // namespace MiscServices
} // namespace OHOS