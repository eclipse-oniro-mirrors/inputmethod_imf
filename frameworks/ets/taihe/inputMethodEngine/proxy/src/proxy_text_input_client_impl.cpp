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
#include "proxy_text_input_client_impl.h"

namespace OHOS {
namespace MiscServices {

void IMFProxyTextInputClientImpl::SendKeyFunctionAsync(int32_t action)
{
    delegate_.SendKeyFunctionAsync(action);
}

void IMFProxyTextInputClientImpl::DeleteForwardAsync(int32_t length)
{
    delegate_.DeleteForwardAsync(length);
}

void IMFProxyTextInputClientImpl::DeleteBackwardAsync(int32_t length)
{
    delegate_.DeleteBackwardAsync(length);
}

void IMFProxyTextInputClientImpl::InsertTextAsync(taihe::string_view text)
{
    delegate_.InsertTextAsync(text);
}

taihe::string IMFProxyTextInputClientImpl::GetForwardAsync(int32_t length)
{
    return delegate_.GetForwardAsync(length);
}

taihe::string IMFProxyTextInputClientImpl::GetBackwardAsync(int32_t length)
{
    return delegate_.GetBackwardAsync(length);
}

ohos::inputMethodEngine::EditorAttributeCallback IMFProxyTextInputClientImpl::GetEditorAttributeAsync()
{
    return delegate_.GetEditorAttributeAsync();
}

void IMFProxyTextInputClientImpl::MoveCursorAsync(int32_t direction)
{
    delegate_.MoveCursorAsync(direction);
}

void IMFProxyTextInputClientImpl::SelectByRangeAsync(Range_t const& range)
{
    delegate_.SelectByRangeAsync(range);
}

void IMFProxyTextInputClientImpl::SelectByMovementAsync(Movement_t const& movement)
{
    delegate_.SelectByMovementAsync(movement);
}

int32_t IMFProxyTextInputClientImpl::GetTextIndexAtCursorAsync()
{
    return delegate_.GetTextIndexAtCursorAsync();
}

void IMFProxyTextInputClientImpl::SendExtendActionAsync(ohos::inputMethodEngine::ExtendAction action)
{
    delegate_.SendExtendActionAsync(action);
}

} // namespace MiscServices
} // namespace OHOS
