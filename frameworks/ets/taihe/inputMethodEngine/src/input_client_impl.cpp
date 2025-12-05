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
#include "input_client_impl.h"

#include "js_utils.h"
#include "input_method_ability.h"
#include "input_method_client_impl.h"
namespace OHOS {
namespace MiscServices {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
bool InputClientImpl::SendKeyFunctionAsync(int32_t action)
{
    bool isSendKeyFunction = false;
    int32_t code = InputMethodAbility::GetInstance().SendFunctionKey(action);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("send function key failed!");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return false;
    }
    IMSA_HILOGI("send function key success");
    return true;
}

bool InputClientImpl::DeleteForwardAsync(int32_t length)
{
    if (length < 0) {
        IMSA_HILOGE("length should no less than 0, length: %{public}d", length);
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED)));
        return false;
    }
    int32_t code = InputMethodAbility::GetInstance().DeleteForward(length);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("delete forward failed");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return false;
    }
    IMSA_HILOGI("delete forward success");
    return true;
}

bool InputClientImpl::DeleteBackwardAsync(int32_t length)
{
    int32_t code = InputMethodAbility::GetInstance().DeleteBackward(length);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("delete backward failed!");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return false;
    }
    IMSA_HILOGI("delete backward success");
    return true;
}

bool InputClientImpl::InsertTextAsync(taihe::string_view text)
{
    std::string insertText = std::string(text);
    int32_t code = InputMethodAbility::GetInstance().InsertText(insertText);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("insert text failed!");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return false;
    }
    IMSA_HILOGI("insert text success");
    return true;
}

taihe::string InputClientImpl::GetForwardAsync(int32_t length)
{
    std::u16string temp;
    int32_t code = InputMethodAbility::GetInstance().GetTextBeforeCursor(length, temp);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("get text before cursor failed");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return "";
    }
    IMSA_HILOGI("get text before cursor success");
    taihe::string text = OHOS::Str16ToStr8(temp);
    return text;
}

taihe::string InputClientImpl::GetBackwardAsync(int32_t length)
{
    std::u16string temp;
    int32_t code = InputMethodAbility::GetInstance().GetTextAfterCursor(length, temp);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("get backward failed");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return "";
    }
    IMSA_HILOGI("get backward success");
    taihe::string text = OHOS::Str16ToStr8(temp);
    return text;
}

ohos::inputMethodEngine::EditorAttributeCallback InputClientImpl::GetEditorAttributeAsync()
{
    EditorAttribute_t result {};
    TextTotalConfig config;
    int32_t ret = InputMethodAbility::GetInstance().GetTextConfig(config);
    if (ret == ErrorCode::NO_ERROR) {
        IMSA_HILOGD("inputPattern: %{public}d, enterKeyType: %{public}d, isTextPreviewSupported: %{public}d",
            config.inputAttribute.inputPattern, config.inputAttribute.enterKeyType,
            config.inputAttribute.isTextPreviewSupported);
    } else {
        IMSA_HILOGE("failed to get text config: %{public}d!", ret);
        taihe::set_business_error(IMFErrorCode::EXCEPTION_IMCLIENT,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_IMCLIENT));
        return ohos::inputMethodEngine::EditorAttributeCallback::make_type_null();
    }
    result = CommonConvert::NativeAttributeToAni(config.inputAttribute);
    return ohos::inputMethodEngine::EditorAttributeCallback::make_type_EditorAttribute(result);
}

void InputClientImpl::MoveCursorAsync(int32_t direction)
{
    if (direction < 0) {
        IMSA_HILOGE("direction should be not less than 0, direction: %{public}d", direction);
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED),
            "direction should be not less than 0!");
        return;
    }
    int32_t code = InputMethodAbility::GetInstance().MoveCursor(direction);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("delete backward failed!");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("delete backward success!");
}

void InputClientImpl::SelectByRangeAsync(Range_t const& range)
{
    Range tmpRange {};
    tmpRange.start = range.start;
    tmpRange.end = range.end;
    int32_t code = InputMethodAbility::GetInstance().SelectByRange(tmpRange.start, tmpRange.end);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("select by range failed");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("select by range success");
}

void InputClientImpl::SelectByMovementAsync(Movement_t const& movement)
{
    int32_t direction = static_cast<int32_t>(movement.direction.get_value());
    IMSA_HILOGD("direction: %{public}d.", direction);
    int32_t code = InputMethodAbility::GetInstance().SelectByMovement(direction);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("select by movement failed");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("select by movement success");
}

int32_t InputClientImpl::GetTextIndexAtCursorAsync()
{
    int32_t index = 0;
    int32_t code = InputMethodAbility::GetInstance().GetTextIndexAtCursor(index);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("get text index at cursor failed");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return index;
    }
    IMSA_HILOGI("get text index at cursor success");
    return index;
}

void InputClientImpl::SendExtendActionAsync(ohos::inputMethodEngine::ExtendAction action)
{
    int32_t tmpAction = static_cast<int32_t>(action.get_value());
    int32_t code = InputMethodAbility::GetInstance().SendExtendAction(tmpAction);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("send extend action failed");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("send extend action success");
}

void InputClientImpl::SendPrivateCommandAsync(taihe::map_view<taihe::string, CommandDataType_t> commandData)
{
    ValueMap privateCommand = CommonConvert::AniConvertPCommandToNative(commandData);
    if (!TextConfig::IsPrivateCommandValid(privateCommand)) {
        IMSA_HILOGE("privateCommand invalid.");
        taihe::set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            "commandData size limit 32KB, count limit 5.");
        return;
    }
    int32_t ret = InputMethodAbility::GetInstance().SendPrivateCommand(privateCommand);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SendPrivateCommand failed.");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("SendPrivateCommand success.");
}

ohos::inputMethodEngine::WindowInfoCallback InputClientImpl::GetCallingWindowInfoAsync()
{
    WindowInfo_t result {};
    CallingWindowInfo windowInfo {};
    int32_t ret = InputMethodAbility::GetInstance().GetCallingWindowInfo(windowInfo);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGI("GetCallingWindowInfo failed.");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return ohos::inputMethodEngine::WindowInfoCallback::make_type_null();
    }
    return ohos::inputMethodEngine::WindowInfoCallback::make_type_WindowInfo(result);
}

void InputClientImpl::SetPreviewTextAsync(taihe::string_view text, Range_t const& range)
{
    std::string previewString = std::string(text);
    Range tmpRange {};
    tmpRange.start = range.start;
    tmpRange.end = range.end;
    int32_t code = InputMethodAbility::GetInstance().SetPreviewText(previewString, tmpRange);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("set preview text failed");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("set preview text success");
}

void InputClientImpl::FinishTextPreviewAsync()
{
    IMSA_HILOGD("start.");
    int32_t code = InputMethodAbility::GetInstance().FinishTextPreview();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("finish text preview failed");
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("finish text preview success.");
}

void InputClientImpl::SendMessageAsync(taihe::string_view msgId, taihe::optional_view<taihe::array<uint8_t>> msgParam)
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
        taihe::set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, "msgId limit 256B and msgParam limit 128KB.");
        return;
    }
    int32_t ret = InputMethodAbility::GetInstance().SendMessage(arrayBuffer);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SendMessage failed ret: %{public}d!", ret);
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGE("SendMessage success!");
}

void InputClientImpl::RecvMessage(taihe::optional_view<::ohos::inputMethodEngine::MessageHandler> msgHandler)
{
    if (msgHandler.has_value()) {
        IMSA_HILOGI("RecvMessage on.");
        ani_object onTerminatedCB = reinterpret_cast<ani_object>(msgHandler.value().onTerminated);
        ani_object onMessageCB = reinterpret_cast<ani_object>(msgHandler.value().onMessage);
        ani_env *env = taihe::get_env();
        if (env == nullptr) {
            IMSA_HILOGE("env is nullptr, RecvMessage failed!");
            taihe::set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
                "env is nullptr, RecvMessage failed!");
            return;
        }
        ani_vm* vm = nullptr;
        if (env->GetVM(&vm) != ANI_OK) {
            IMSA_HILOGE("GetVM failed");
            return;
        }
        std::shared_ptr<MsgHandlerCallbackInterface> callback =
            std::make_shared<AniMessageHandler>(vm, onTerminatedCB, onMessageCB);
        InputMethodAbility::GetInstance().RegisterMsgHandler(callback);
    } else {
        IMSA_HILOGI("RecvMessage off.");
        InputMethodAbility::GetInstance().RegisterMsgHandler();
    }
}

void InputClientImpl::FinishTextPreviewSync()
{
    IMSA_HILOGD("Taihe TextInputClientEngine in");
    int32_t ret = InputMethodAbility::GetInstance().FinishTextPreview();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to finish text preview!");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("finish text preview success!");
}

void InputClientImpl::SetPreviewTextSync(taihe::string_view text, Range_t const& range)
{
    IMSA_HILOGD("start.");
    std::string previewString = std::string(text);
    Range tmpRange {};
    tmpRange.start = range.start;
    tmpRange.end = range.end;
    int32_t ret = InputMethodAbility::GetInstance().SetPreviewText(previewString, tmpRange);
    if (ret == ErrorCode::ERROR_INVALID_RANGE) {
        IMSA_HILOGE("range is invalid!");
        taihe::set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            "range should be included in preview text range, otherwise should be included in total text range");
        return;
    } else if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("range is invalid!");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("SetPreviewTextSync success");
}

void InputClientImpl::SelectByMovementSync(Movement_t const& movement)
{
    IMSA_HILOGD("run in");
    int32_t direction = movement.direction.get_value();
    IMSA_HILOGD("direction: %{public}d.", direction);
    int32_t ret = InputMethodAbility::GetInstance().SelectByMovement(direction);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to select by movement!");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("select by movement success!");
}

void InputClientImpl::SelectByRangeSync(Range_t const& range)
{
    IMSA_HILOGD("SelectByRangeSync");
    Range tmpRange {};
    tmpRange.start = range.start;
    tmpRange.end = range.end;
    int32_t ret = InputMethodAbility::GetInstance().SelectByRange(tmpRange.start, tmpRange.end);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to select by range!");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("select by range success!");
}

void InputClientImpl::MoveCursorSync(int32_t direction)
{
    if (direction < 0) {
        IMSA_HILOGE("direction should be no less than 0!");
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED),
            "direction should be no less than 0!");
        return;
    }
    IMSA_HILOGD("moveCursor, direction: %{public}d", direction);
    int32_t ret = InputMethodAbility::GetInstance().MoveCursor(direction);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGI("failed to move cursor!");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("move cursor success!");
}

taihe::string InputClientImpl::GetBackwardSync(int32_t length)
{
    taihe::string result = "";
    if (length < 0) {
        IMSA_HILOGE("length should be no less than 0!");
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED),
            "length should be no less than 0!");
        return result;
    }
    IMSA_HILOGD("get backward, length: %{public}d.", length);
    std::u16string text;
    int32_t ret = InputMethodAbility::GetInstance().GetTextAfterCursor(length, text);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get backward!");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return result;
    }
    IMSA_HILOGI("get backward success!");
    result = std::string(OHOS::Str16ToStr8(text));
    return result;
}

taihe::string InputClientImpl::GetForwardSync(int32_t length)
{
    taihe::string result = "";
    if (length < 0) {
        IMSA_HILOGE("length should be no less than 0!");
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED),
            "length should be no less than 0!");
        return result;
    }
    IMSA_HILOGD("get forward, length: %{public}d.", length);
    std::u16string text;
    int32_t ret = InputMethodAbility::GetInstance().GetTextBeforeCursor(length, text);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get forward!");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return result;
    }
    IMSA_HILOGI("get forward success!");
    result = std::string(OHOS::Str16ToStr8(text));
    return result;
}

void InputClientImpl::InsertTextSync(taihe::string_view text)
{
    std::string tmpText = std::string(text);
    int32_t ret = InputMethodAbility::GetInstance().InsertText(tmpText);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to insert text!");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("insert text success!");
}

void InputClientImpl::DeleteBackwardSync(int32_t length)
{
    if (length < 0) {
        IMSA_HILOGE("length should be no less than 0!");
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED),
            "length should be no less than 0!");
        return;
    }
    IMSA_HILOGD("delete backward, length: %{public}d.", length);
    int32_t ret = InputMethodAbility::GetInstance().DeleteBackward(length);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to delete backward");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("delete backward success!");
}

void InputClientImpl::DeleteForwardSync(int32_t length)
{
    if (length < 0) {
        IMSA_HILOGE("length should be no less than 0!");
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED),
            "length should be no less than 0!");
        return;
    }
    IMSA_HILOGD("delete forward, length: %{public}d.", length);
    int32_t ret = InputMethodAbility::GetInstance().DeleteForward(length);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to delete forward");
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("delete forward success!");
}

ohos::inputMethodEngine::EditorAttributeCallback InputClientImpl::GetEditorAttributeSync()
{
    TextTotalConfig config;
    EditorAttribute_t result;
    int32_t ret = InputMethodAbility::GetInstance().GetTextConfig(config);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get text config: %{public}d!", ret);
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return ohos::inputMethodEngine::EditorAttributeCallback::make_type_null();
    }
    IMSA_HILOGD("inputPattern: %{public}d, enterKeyType: %{public}d, isTextPreviewSupported: %{public}d.",
        config.inputAttribute.inputPattern, config.inputAttribute.enterKeyType,
        config.inputAttribute.isTextPreviewSupported);
    IMSA_HILOGI("get editor attribute success!");
    result = CommonConvert::NativeAttributeToAni(config.inputAttribute);
    return ohos::inputMethodEngine::EditorAttributeCallback::make_type_EditorAttribute(result);
}

int32_t InputClientImpl::GetTextIndexAtCursorSync()
{
    IMSA_HILOGD("start.");
    int32_t index = 0;
    int32_t ret = InputMethodAbility::GetInstance().GetTextIndexAtCursor(index);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get text index at cursor: %{public}d!", ret);
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return index;
    }
    IMSA_HILOGI("get text index at cursor success");
    return index;
}

ohos::inputMethodEngine::AttachOptionsCallback InputClientImpl::GetAttachOptions()
{
    AttachOptions_t result {};
    auto attachOptions = InputMethodAbility::GetInstance().GetAttachOptions();
    IMSA_HILOGD("GetAttachOptions:%{public}d/%{public}d.", attachOptions.requestKeyboardReason,
        attachOptions.isSimpleKeyboardEnabled);
    result = CommonConvert::NativeAttachOptionsToAni(attachOptions);
    return ohos::inputMethodEngine::AttachOptionsCallback::make_type_AttachOptions(result);
}

void InputClientImpl::OnAttachOptionsDidChange(
    taihe::callback_view<void(AttachOptions_t const&)> callback, uintptr_t opq)
{
    InputMethodClientImpl::GetInstance()->RegisterListener("attachOptionsDidChange", callback, opq);
}

void InputClientImpl::OffAttachOptionsDidChange(taihe::optional_view<uintptr_t> opq)
{
    InputMethodClientImpl::GetInstance()->UnRegisterListener("attachOptionsDidChange", opq);
}
}
}