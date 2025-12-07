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
#ifndef INPUT_CLIENT_IMPL_H
#define INPUT_CLIENT_IMPL_H
#include "ani_common_engine.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "ohos.inputMethodEngine.InputMethodAbility.ani.1.hpp"
#include "ani_message_handler.h"
namespace OHOS {
namespace MiscServices {
class InputClientImpl {
public:
    InputClientImpl()
    {
        // Don't forget to implement the constructor.
    }

    bool SendKeyFunctionAsync(int32_t action);

    bool DeleteForwardAsync(int32_t length);

    bool DeleteBackwardAsync(int32_t length);

    bool InsertTextAsync(taihe::string_view text);

    taihe::string GetForwardAsync(int32_t length);

    taihe::string GetBackwardAsync(int32_t length);

    ohos::inputMethodEngine::EditorAttributeCallback GetEditorAttributeAsync();

    void MoveCursorAsync(int32_t direction);

    void SelectByRangeAsync(Range_t const& range);

    void SelectByMovementAsync(Movement_t const& movement);

    int32_t GetTextIndexAtCursorAsync();

    void SendExtendActionAsync(ohos::inputMethodEngine::ExtendAction action);

    void SendPrivateCommandAsync(taihe::map_view<taihe::string, CommandDataType_t> commandData);

    ohos::inputMethodEngine::WindowInfoCallback GetCallingWindowInfoAsync();

    void SetPreviewTextAsync(taihe::string_view text, Range_t const& range);

    void FinishTextPreviewAsync();

    void SendMessageAsync(taihe::string_view msgId, taihe::optional_view<taihe::array<uint8_t>> msgParam);

    void RecvMessage(taihe::optional_view<::ohos::inputMethodEngine::MessageHandler> msgHandler);

    void FinishTextPreviewSync();

    void SetPreviewTextSync(taihe::string_view text, Range_t const& range);

    void SelectByMovementSync(Movement_t const& movement);

    void SelectByRangeSync(Range_t const& range);

    void MoveCursorSync(int32_t direction);

    taihe::string GetBackwardSync(int32_t length);

    taihe::string GetForwardSync(int32_t length);

    void InsertTextSync(taihe::string_view text);

    void DeleteBackwardSync(int32_t length);

    void DeleteForwardSync(int32_t length);

    ohos::inputMethodEngine::EditorAttributeCallback GetEditorAttributeSync();

    int32_t GetTextIndexAtCursorSync();

    ohos::inputMethodEngine::AttachOptionsCallback GetAttachOptions();

    void OnAttachOptionsDidChange(taihe::callback_view<void(AttachOptions_t const&)> callback, uintptr_t opq);

    void OffAttachOptionsDidChange(taihe::optional_view<uintptr_t> opq);
};
}
}
#endif // INPUT_CLIENT_IMPL_H