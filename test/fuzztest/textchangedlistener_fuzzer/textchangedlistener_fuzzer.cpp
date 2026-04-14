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

#include "textchangedlistener_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "input_method_controller.h"
#include "input_method_utils.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace MiscServices {

namespace {
constexpr size_t MIN_INPUT_SIZE = 10;
constexpr size_t MAX_INPUT_SIZE = 1000;
constexpr size_t MAX_TEXT_LENGTH = 100;
constexpr size_t MAX_FUZZ_TEXT_LENGTH = 200;
} // namespace

class FuzzTextChangedListener : public OnTextChangedListener {
public:
    FuzzTextChangedListener() = default;
    ~FuzzTextChangedListener() override = default;

    void InsertText(const std::u16string &text) override
    {
        insertedText_ = text;
    }

    void DeleteForward(int32_t length) override
    {
        deleteForwardLength_ = length;
    }

    void DeleteBackward(int32_t length) override
    {
        deleteBackwardLength_ = length;
    }

    void SendKeyEventFromInputMethod(const KeyEvent &event) override
    {
        lastKeyEvent_ = event;
    }

    void SendKeyboardStatus(const KeyboardStatus &keyboardStatus) override
    {
        keyboardStatus_ = keyboardStatus;
    }

    void SendFunctionKey(const FunctionKey &functionKey) override
    {
        lastFunctionKey_ = functionKey;
    }

    void SetKeyboardStatus(bool status) override
    {
        keyboardVisible_ = status;
    }

    void MoveCursor(const Direction direction) override
    {
        cursorDirection_ = direction;
    }

    void HandleSetSelection(int32_t start, int32_t end) override
    {
        selectionStart_ = start;
        selectionEnd_ = end;
    }

    void HandleExtendAction(int32_t action) override
    {
        extendAction_ = action;
    }

    void HandleSelect(int32_t keyCode, int32_t cursorMoveSkip) override
    {
        selectKeyCode_ = keyCode;
        selectCursorMoveSkip_ = cursorMoveSkip;
    }

    std::u16string GetLeftTextOfCursor(int32_t number) override
    {
        return leftText_;
    }

    std::u16string GetRightTextOfCursor(int32_t number) override
    {
        return rightText_;
    }

    int32_t GetTextIndexAtCursor() override
    {
        return textIndex_;
    }

    void FinishTextPreview() override
    {
        finishTextPreviewCalled_ = true;
    }

    void OnDetach() override
    {
        onDetachCalled_ = true;
    }

    void SetLeftText(const std::u16string &text)
    {
        leftText_ = text;
    }

    void SetRightText(const std::u16string &text)
    {
        rightText_ = text;
    }

    void SetTextIndex(int32_t index)
    {
        textIndex_ = index;
    }

    bool GetFinishTextPreviewCalled() const
    {
        return finishTextPreviewCalled_;
    }

    bool GetOnDetachCalled() const
    {
        return onDetachCalled_;
    }

    std::u16string GetInsertedText() const
    {
        return insertedText_;
    }

private:
    std::u16string insertedText_;
    int32_t deleteForwardLength_ = 0;
    int32_t deleteBackwardLength_ = 0;
    KeyEvent lastKeyEvent_;
    KeyboardStatus keyboardStatus_ = KeyboardStatus::NONE;
    FunctionKey lastFunctionKey_;
    bool keyboardVisible_ = false;
    Direction cursorDirection_ = Direction::NONE;
    int32_t selectionStart_ = 0;
    int32_t selectionEnd_ = 0;
    int32_t extendAction_ = 0;
    int32_t selectKeyCode_ = 0;
    int32_t selectCursorMoveSkip_ = 0;
    std::u16string leftText_;
    std::u16string rightText_;
    int32_t textIndex_ = 0;
    bool finishTextPreviewCalled_ = false;
    bool onDetachCalled_ = false;
};

void FuzzFinishTextPreview(FuzzedDataProvider &provider)
{
    sptr<FuzzTextChangedListener> listener = new FuzzTextChangedListener();

    std::string fuzzedLeftText = provider.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    std::string fuzzedRightText = provider.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    int32_t fuzzedTextIndex = provider.ConsumeIntegral<int32_t>();

    listener->SetLeftText(std::u16string(fuzzedLeftText.begin(), fuzzedLeftText.end()));
    listener->SetRightText(std::u16string(fuzzedRightText.begin(), fuzzedRightText.end()));
    listener->SetTextIndex(fuzzedTextIndex);

    listener->FinishTextPreview();
}

void FuzzOnDetach(FuzzedDataProvider &provider)
{
    sptr<FuzzTextChangedListener> listener = new FuzzTextChangedListener();
    std::string fuzzedText = provider.ConsumeRandomLengthString(MAX_FUZZ_TEXT_LENGTH);
    listener->SetLeftText(std::u16string(fuzzedText.begin(), fuzzedText.end()));
    listener->OnDetach();
}

void FuzzInsertText(FuzzedDataProvider &provider)
{
    sptr<FuzzTextChangedListener> listener = new FuzzTextChangedListener();
    std::string fuzzedText = provider.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    listener->InsertText(std::u16string(fuzzedText.begin(), fuzzedText.end()));
}

void FuzzDeleteForward(FuzzedDataProvider &provider)
{
    sptr<FuzzTextChangedListener> listener = new FuzzTextChangedListener();
    int32_t fuzzedLength = provider.ConsumeIntegral<int32_t>();
    listener->DeleteForward(fuzzedLength);
}

void FuzzDeleteBackward(FuzzedDataProvider &provider)
{
    sptr<FuzzTextChangedListener> listener = new FuzzTextChangedListener();
    int32_t fuzzedLength = provider.ConsumeIntegral<int32_t>();
    listener->DeleteBackward(fuzzedLength);
}

void FuzzHandleSetSelection(FuzzedDataProvider &provider)
{
    sptr<FuzzTextChangedListener> listener = new FuzzTextChangedListener();
    int32_t start = provider.ConsumeIntegral<int32_t>();
    int32_t end = provider.ConsumeIntegral<int32_t>();
    listener->HandleSetSelection(start, end);
}

void FuzzHandleExtendAction(FuzzedDataProvider &provider)
{
    sptr<FuzzTextChangedListener> listener = new FuzzTextChangedListener();
    int32_t action = provider.ConsumeIntegral<int32_t>();
    listener->HandleExtendAction(action);
}

void FuzzHandleSelect(FuzzedDataProvider &provider)
{
    sptr<FuzzTextChangedListener> listener = new FuzzTextChangedListener();
    int32_t keyCode = provider.ConsumeIntegral<int32_t>();
    int32_t cursorMoveSkip = provider.ConsumeIntegral<int32_t>();
    listener->HandleSelect(keyCode, cursorMoveSkip);
}

} // namespace MiscServices
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::MiscServices::MIN_INPUT_SIZE) {
        return 0;
    }

    if (size > OHOS::MiscServices::MAX_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);

    OHOS::MiscServices::FuzzFinishTextPreview(provider);
    OHOS::MiscServices::FuzzOnDetach(provider);
    OHOS::MiscServices::FuzzInsertText(provider);
    OHOS::MiscServices::FuzzDeleteForward(provider);
    OHOS::MiscServices::FuzzDeleteBackward(provider);
    OHOS::MiscServices::FuzzHandleSetSelection(provider);
    OHOS::MiscServices::FuzzHandleExtendAction(provider);
    OHOS::MiscServices::FuzzHandleSelect(provider);

    return 0;
}
