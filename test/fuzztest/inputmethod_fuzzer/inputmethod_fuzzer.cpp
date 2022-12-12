/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "inputmethod_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "global.h"
#include "input_client_stub.h"
#include "input_method_controller.h"
#include "keyboard_event.h"
#include "message_handler.h"
#include "message_parcel.h"
#include "para_handle.h"
#include "utils.h"

using namespace OHOS::MiscServices;
namespace OHOS {
class TextListener : public OnTextChangedListener {
public:
    TextListener() {}
    ~TextListener() {}
    void InsertText(const std::u16string &text) {}
    void DeleteBackward(int32_t length) {}
    void SetKeyboardStatus(bool status) {}
    void DeleteForward(int32_t length) {}
    void SendKeyEventFromInputMethod(const KeyEvent &event) {}
    void SendKeyboardInfo(const KeyboardInfo &status) {}
    void MoveCursor(const Direction direction) {}
};

bool FuzzParaHandle(const uint8_t *rawData, size_t size)
{
    int32_t userId = static_cast<int32_t>(*rawData);
    std::string imeName = std::string(rawData, rawData + size);
    ParaHandle::SetDefaultIme(userId, imeName);
    return true;
}
} // namespace OHOS
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzParaHandle(data, size);
    return 0;
}