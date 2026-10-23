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
#ifndef TAIHE_PROXY_TEXT_INPUT_CLIENT_IMPL_H
#define TAIHE_PROXY_TEXT_INPUT_CLIENT_IMPL_H

#include "input_client_impl.h"

namespace OHOS {
namespace MiscServices {
class IMFProxyTextInputClientImpl {
public:
    IMFProxyTextInputClientImpl() = default;
    ~IMFProxyTextInputClientImpl() = default;

    void SendKeyFunctionAsync(int32_t action);
    void DeleteForwardAsync(int32_t length);
    void DeleteBackwardAsync(int32_t length);
    void InsertTextAsync(taihe::string_view text);
    taihe::string GetForwardAsync(int32_t length);
    taihe::string GetBackwardAsync(int32_t length);
    ohos::inputMethodEngine::EditorAttributeCallback GetEditorAttributeAsync();
    void MoveCursorAsync(int32_t direction);
    void SelectByRangeAsync(Range_t const& range);
    void SelectByMovementAsync(Movement_t const& movement);
    int32_t GetTextIndexAtCursorAsync();
    void SendExtendActionAsync(ohos::inputMethodEngine::ExtendAction action);

private:
    InputClientImpl delegate_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_PROXY_TEXT_INPUT_CLIENT_IMPL_H
