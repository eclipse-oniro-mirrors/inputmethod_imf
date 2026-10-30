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
#include "proxy_text_input_client_impl.h"

#include "global.h"
#include "input_method_ability.h"
#include "js_utils.h"

namespace OHOS {
namespace MiscServices {

void IMFProxyTextInputClientImpl::SendKeyFunctionAsync(int32_t action)
{
    if (!OHOS::MiscServices::IsValidEnterKeyType(action)) {
        IMSA_HILOGE("error action: %{public}d.", action);
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "action is out of valid "
                                                                                             "range!");
        return;
    }
    int32_t code = InputMethodAbility::GetInstance().SendFunctionKey(action);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("send function key failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGD("send function key success");
}

void IMFProxyTextInputClientImpl::DeleteForwardAsync(int32_t length)
{
    if (length < 0) {
        IMSA_HILOGE("length should be no less than 0!");
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "length cannot be less "
                                                                                             "than 0!");
        return;
    }
    int32_t code = InputMethodAbility::GetInstance().DeleteForward(length);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("delete forward failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGD("delete forward success");
}

void IMFProxyTextInputClientImpl::DeleteBackwardAsync(int32_t length)
{
    if (length < 0) {
        IMSA_HILOGE("length should be no less than 0!");
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "length cannot be less "
                                                                                             "than 0!");
        return;
    }
    int32_t code = InputMethodAbility::GetInstance().DeleteBackward(length);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("delete backward failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGD("delete backward success");
}

void IMFProxyTextInputClientImpl::InsertTextAsync(taihe::string_view text)
{
    std::string insertText = std::string(text);
    int32_t code = InputMethodAbility::GetInstance().InsertText(insertText);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("insert text failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGD("insert text success");
}

taihe::string IMFProxyTextInputClientImpl::GetForwardAsync(int32_t length)
{
    if (length < 0) {
        IMSA_HILOGE("length should be no less than 0!");
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "length cannot be less "
                                                                                             "than 0!");
        return "";
    }
    std::u16string temp;
    int32_t code = InputMethodAbility::GetInstance().GetTextBeforeCursor(length, temp);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("get text before cursor failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return "";
    }
    IMSA_HILOGD("get text before cursor success");
    return OHOS::Str16ToStr8(temp);
}

taihe::string IMFProxyTextInputClientImpl::GetBackwardAsync(int32_t length)
{
    if (length < 0) {
        IMSA_HILOGE("length should be no less than 0!");
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "length cannot be less "
                                                                                             "than 0!");
        return "";
    }
    std::u16string temp;
    int32_t code = InputMethodAbility::GetInstance().GetTextAfterCursor(length, temp);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("get text after cursor failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return "";
    }
    IMSA_HILOGD("get text after cursor success");
    return OHOS::Str16ToStr8(temp);
}

ohos::inputMethodEngine::EditorAttributeCallback IMFProxyTextInputClientImpl::GetEditorAttributeAsync()
{
    TextTotalConfig config;
    int32_t ret = InputMethodAbility::GetInstance().GetTextConfig(config);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get text config: %{public}d!", ret);
        taihe::set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return ohos::inputMethodEngine::EditorAttributeCallback::make_type_null();
    }
    IMSA_HILOGD("inputPattern: %{public}d, enterKeyType: %{public}d, isTextPreviewSupported: %{public}d",
        config.inputAttribute.inputPattern, config.inputAttribute.enterKeyType,
        config.inputAttribute.isTextPreviewSupported);
    EditorAttribute_t result = CommonConvert::NativeAttributeToAni(config.inputAttribute);
    return ohos::inputMethodEngine::EditorAttributeCallback::make_type_EditorAttribute(result);
}

void IMFProxyTextInputClientImpl::MoveCursorAsync(ohos::inputMethodEngine::Direction direction)
{
    int32_t directionVal = direction.get_value();
    if (!OHOS::MiscServices::IsValidCursorDirection(directionVal)) {
        IMSA_HILOGE("error direction: %{public}d.", directionVal);
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "direction is out of "
                                                                                             "valid range!");
        return;
    }
    int32_t code = InputMethodAbility::GetInstance().MoveCursor(directionVal);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("move cursor failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGD("move cursor success");
}

void IMFProxyTextInputClientImpl::SelectByRangeAsync(Range_t const &range)
{
    int32_t start = range.start;
    int32_t end = range.end;
    if (start < 0 || end < 0) {
        IMSA_HILOGE("error param, start: %{public}d, end: %{public}d.", start, end);
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "start and end cannot be "
                                                                                             "less than 0!");
        return;
    }
    if (end < start) {
        IMSA_HILOGE("error param end, start: %{public}d, end: %{public}d.", start, end);
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "end cannot be less than "
                                                                                             "start!");
        return;
    }
    int32_t code = InputMethodAbility::GetInstance().SelectByRange(start, end);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("select by range failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGD("select by range success");
}

void IMFProxyTextInputClientImpl::SelectByMovementAsync(Movement_t const &movement)
{
    int32_t directionVal = movement.direction.get_value();
    if (!OHOS::MiscServices::IsValidCursorDirection(directionVal)) {
        IMSA_HILOGE("error direction: %{public}d.", directionVal);
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "direction is out of "
                                                                                             "valid range!");
        return;
    }
    int32_t code = InputMethodAbility::GetInstance().SelectByMovement(directionVal);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("select by movement failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGD("select by movement success");
}

int32_t IMFProxyTextInputClientImpl::GetTextIndexAtCursorAsync()
{
    int32_t index = 0;
    int32_t code = InputMethodAbility::GetInstance().GetTextIndexAtCursor(index);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("get text index at cursor failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return index;
    }
    IMSA_HILOGD("get text index at cursor success");
    return index;
}

void IMFProxyTextInputClientImpl::SendExtendActionAsync(ohos::inputMethodEngine::ExtendAction action)
{
    int32_t actionVal = action.get_value();
    if (!OHOS::MiscServices::IsValidExtendAction(actionVal)) {
        IMSA_HILOGE("error action: %{public}d.", actionVal);
        taihe::set_business_error(JsUtils::Convert(ErrorCode::ERROR_PARAMETER_CHECK_FAILED), "action is out of valid "
                                                                                             "range!");
        return;
    }
    int32_t code = InputMethodAbility::GetInstance().SendExtendAction(actionVal);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("send extend action failed, code: %{public}d!", code);
        taihe::set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGD("send extend action success");
}

} // namespace MiscServices
} // namespace OHOS
