/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "input_method_controller.h"
#undef private

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include "tdd_util.h"
#include "text_listener.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
constexpr int CURSOR_DIRECTION_BASE_VALUE = 2011;
class TextListenerInnerApiTest : public testing::Test {
public:
    static sptr<InputMethodController> imc_;
    static sptr<OnTextChangedListener> textListener_;
    static void SetUpTestCase(void)
    {
        IMSA_HILOGI("TextListenerInnerApiTest::SetUpTestCase");
        TddUtil::InitWindow(true);
        TextListener::ResetParam();

        textListener_ = new TextListener();
        imc_ = InputMethodController::GetInstance();
    }
    static void TearDownTestCase(void)
    {
        IMSA_HILOGI("TextListenerInnerApiTest::TearDownTestCase");
        imc_->Close();
        TextListener::ResetParam();
        TddUtil::DestroyWindow();
    }
    void SetUp()
    {
        IMSA_HILOGI("TextListenerInnerApiTest::SetUp");
        TextListener::ResetParam();
    }
    void TearDown()
    {
        IMSA_HILOGI("TextListenerInnerApiTest::TearDown");
        TextListener::ResetParam();
    }
    static void GetIMCAttached()
    {
        imc_->SetTextListener(textListener_);
        imc_->clientInfo_.state = ClientState::ACTIVE;
        imc_->isBound_.store(true);
        imc_->isEditable_.store(true);
    }
    static void GetIMCDetached()
    {
        imc_->SetTextListener(nullptr);
        imc_->isBound_.store(false);
        imc_->isEditable_.store(false);
    }
};
sptr<InputMethodController> TextListenerInnerApiTest::imc_;
sptr<OnTextChangedListener> TextListenerInnerApiTest::textListener_;

/**
 * @tc.name: testInsertText01
 * @tc.desc: insert text.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testInsertText01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testInsertText01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    std::string text = "text";
    std::u16string u16Text = Str8ToStr16(text);
    int32_t ret = imc_->InsertText(u16Text);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::insertText_, u16Text);
}

/**
 * @tc.name: testInsertText02
 * @tc.desc: insert text without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testInsertText02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testInsertText02 START");
    TextListener::ResetParam();
    std::string text = "text";
    std::u16string u16Text = Str8ToStr16(text);

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = imc_->InsertText(u16Text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::insertText_, u16Text);

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    ret = imc_->InsertText(u16Text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::insertText_, u16Text);
}

/**
 * @tc.name: testDeleteForward01
 * @tc.desc: delete forward.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testDeleteForward01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testDeleteForward01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t length = 5;
    int32_t ret = TextListenerInnerApiTest::imc_->DeleteForward(length);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::deleteBackwardLength_, length);
}

/**
 * @tc.name: testDeleteForward02
 * @tc.desc: delete forward without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testDeleteForward02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testDeleteForward02 START");
    TextListener::ResetParam();
    int32_t length = 5;

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = TextListenerInnerApiTest::imc_->DeleteForward(length);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::deleteForwardLength_, length);

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    ret = TextListenerInnerApiTest::imc_->DeleteForward(length);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::deleteBackwardLength_, length);
}

/**
 * @tc.name: testDeleteBackward01
 * @tc.desc: delete backward.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testDeleteBackward01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testDeleteBackward01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t length = 5;
    int32_t ret = TextListenerInnerApiTest::imc_->DeleteBackward(length);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::deleteForwardLength_, length);
}

/**
 * @tc.name: testDeleteBackward02
 * @tc.desc: delete backward without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testDeleteBackward02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testDeleteBackward02 START");
    TextListener::ResetParam();
    int32_t length = 5;

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = TextListenerInnerApiTest::imc_->DeleteBackward(length);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::deleteBackwardLength_, length);

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    ret = TextListenerInnerApiTest::imc_->DeleteBackward(length);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::deleteForwardLength_, length);
}

/**
 * @tc.name: testGetLeft01
 * @tc.desc: get left.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testGetLeft01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testGetLeft01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t number = 5;
    std::u16string text;
    int32_t ret = TextListenerInnerApiTest::imc_->GetLeft(number, text);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(text, Str8ToStr16(TextListener::TEXT_BEFORE_CURSOR));
}

/**
 * @tc.name: testGetLeft02
 * @tc.desc: get left without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testGetLeft02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testGetLeft02 START");
    TextListener::ResetParam();
    int32_t number = 5;
    std::u16string text = u"";

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = TextListenerInnerApiTest::imc_->GetLeft(number, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(text, Str8ToStr16(TextListener::TEXT_BEFORE_CURSOR));

    text = u"";
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    ret = TextListenerInnerApiTest::imc_->GetLeft(number, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(text, Str8ToStr16(TextListener::TEXT_BEFORE_CURSOR));
}

/**
 * @tc.name: testGetRight01
 * @tc.desc: get left.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testGetRight01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testGetRight01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t number = 5;
    std::u16string text;
    int32_t ret = TextListenerInnerApiTest::imc_->GetRight(number, text);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(text, Str8ToStr16(TextListener::TEXT_AFTER_CURSOR));
}

/**
 * @tc.name: testGetRight02
 * @tc.desc: get right without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testGetRight02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testGetRight02 START");
    TextListener::ResetParam();
    int32_t number = 5;
    std::u16string text = u"";

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = TextListenerInnerApiTest::imc_->GetRight(number, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(text, Str8ToStr16(TextListener::TEXT_AFTER_CURSOR));

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    ret = TextListenerInnerApiTest::imc_->GetRight(number, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(text, Str8ToStr16(TextListener::TEXT_AFTER_CURSOR));
}

/**
 * @tc.name: testSendKeyboardStatus01
 * @tc.desc: send keyboard status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSendKeyboardStatus01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSendKeyboardStatus01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->SendKeyboardStatus(KeyboardStatus::HIDE);
    EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::HIDE));
}

/**
 * @tc.name: testSendKeyboardStatus02
 * @tc.desc: get right without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSendKeyboardStatus02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSendKeyboardStatus02 START");
    TextListenerInnerApiTest::GetIMCAttached();
    TextListener::ResetParam();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    TextListenerInnerApiTest::imc_->SendKeyboardStatus(KeyboardStatus::HIDE);
    EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::NONE));

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    TextListenerInnerApiTest::imc_->SendKeyboardStatus(KeyboardStatus::HIDE);
    EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::NONE));
}

/**
 * @tc.name: testSendFunctionKey01
 * @tc.desc: send keyboard status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSendFunctionKey01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSendFunctionKey01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t key = 1;
    TextListenerInnerApiTest::imc_->SendFunctionKey(key);
    EXPECT_EQ(TextListener::key_, key);
}

/**
 * @tc.name: testSendFunctionKey02
 * @tc.desc: get right without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSendFunctionKey02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSendFunctionKey02 START");
    TextListener::ResetParam();
    int32_t key = 1;

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    TextListenerInnerApiTest::imc_->SendFunctionKey(key);
    EXPECT_NE(TextListener::key_, key);

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    TextListenerInnerApiTest::imc_->SendFunctionKey(key);
    EXPECT_NE(TextListener::key_, key);
}

/**
 * @tc.name: testMoveCursor01
 * @tc.desc: move cursor.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testMoveCursor01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testMoveCursor01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t direction = 2;
    int32_t ret = TextListenerInnerApiTest::imc_->MoveCursor(static_cast<Direction>(direction));
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::direction_, direction);
}

/**
 * @tc.name: testMoveCursor02
 * @tc.desc: move cursor without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testMoveCursor02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testMoveCursor02 START");
    TextListener::ResetParam();
    int32_t direction = 2;

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = TextListenerInnerApiTest::imc_->MoveCursor(static_cast<Direction>(direction));
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::direction_, direction);

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    ret = TextListenerInnerApiTest::imc_->MoveCursor(static_cast<Direction>(direction));
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::direction_, direction);
}

/**
 * @tc.name: testSelectByRange01
 * @tc.desc: select by range.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSelectByRange01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSelectByRange01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t start = 1;
    int32_t end = 1;
    TextListenerInnerApiTest::imc_->SelectByRange(start, end);
    EXPECT_EQ(TextListener::selectionStart_, start);
    EXPECT_EQ(TextListener::selectionEnd_, end);
}

/**
 * @tc.name: testSelectByRange02
 * @tc.desc: select by range without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSelectByRange02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSelectByRange02 START");
    TextListener::ResetParam();
    int32_t start = 1;
    int32_t end = 1;

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    TextListenerInnerApiTest::imc_->SelectByRange(start, end);
    EXPECT_NE(TextListener::selectionStart_, start);
    EXPECT_NE(TextListener::selectionEnd_, end);

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    TextListenerInnerApiTest::imc_->SelectByRange(start, end);
    EXPECT_NE(TextListener::selectionStart_, start);
    EXPECT_NE(TextListener::selectionEnd_, end);
}

/**
 * @tc.name: testSelectByMovement01
 * @tc.desc: select by movement.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSelectByMovement01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSelectByMovement01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t direction = 1;
    int32_t cursorSkip = 2;
    TextListenerInnerApiTest::imc_->SelectByMovement(direction, cursorSkip);
    EXPECT_EQ(TextListener::selectionDirection_, direction + CURSOR_DIRECTION_BASE_VALUE);
    EXPECT_EQ(TextListener::selectionSkip_, cursorSkip);
}

/**
 * @tc.name: testSelectByMovement02
 * @tc.desc: select by movement without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSelectByMovement02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSelectByMovement02 START");
    TextListener::ResetParam();
    int32_t direction = 1;
    int32_t skip = 2;

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    TextListenerInnerApiTest::imc_->SelectByMovement(direction, skip);
    EXPECT_NE(TextListener::direction_, direction);
    EXPECT_NE(TextListener::selectionSkip_, skip);

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    TextListenerInnerApiTest::imc_->SelectByMovement(direction, skip);
    EXPECT_NE(TextListener::selectionDirection_, direction + CURSOR_DIRECTION_BASE_VALUE);
    EXPECT_NE(TextListener::selectionSkip_, skip);
}

/**
 * @tc.name: testHandleExtendAction01
 * @tc.desc: move cursor.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testHandleExtendAction01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testHandleExtendAction01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t action = 2;
    int32_t ret = TextListenerInnerApiTest::imc_->HandleExtendAction(action);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::action_, action);
}

/**
 * @tc.name: testHandleExtendAction02
 * @tc.desc: move cursor without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testHandleExtendAction02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testHandleExtendAction02 START");
    TextListener::ResetParam();
    int32_t action = 2;

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = TextListenerInnerApiTest::imc_->HandleExtendAction(action);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::action_, action);

    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    ret = TextListenerInnerApiTest::imc_->HandleExtendAction(action);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::action_, action);
}

/**
 * @tc.name: testGetTextIndexAtCursor01
 * @tc.desc: get text index at cursor.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testGetTextIndexAtCursor01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testGetTextIndexAtCursor01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t index = -1;
    int32_t ret = TextListenerInnerApiTest::imc_->GetTextIndexAtCursor(index);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(index, TextListener::TEXT_INDEX);
}

/**
 * @tc.name: testGetTextIndexAtCursor02
 * @tc.desc: get text index at cursor without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testGetTextIndexAtCursor02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testGetTextIndexAtCursor02 START");
    TextListener::ResetParam();
    int32_t index = -1;

    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = TextListenerInnerApiTest::imc_->GetTextIndexAtCursor(index);
    EXPECT_NE(ret, ErrorCode::NO_ERROR);
    EXPECT_NE(index, TextListener::TEXT_INDEX);

    index = -1;
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCDetached();
    ret = TextListenerInnerApiTest::imc_->GetTextIndexAtCursor(index);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(index, TextListener::TEXT_INDEX);
}

/**
 * @tc.name: testSetPreviewText01
 * @tc.desc: insert text.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSetPreviewText01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSetPreviewText01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    std::string text = "text";
    std::u16string u16Text = Str8ToStr16(text);
    Range range = { 1, 2 };
    TextListenerInnerApiTest::imc_->textConfig_.inputAttribute.isTextPreviewSupported = true;
    int32_t ret = TextListenerInnerApiTest::imc_->SetPreviewText(text, range);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::previewText_, text);
    EXPECT_EQ(TextListener::previewRange_, range);
    TextListenerInnerApiTest::GetIMCDetached();
}

/**
 * @tc.name: testSetPreviewText02
 * @tc.desc: insert text without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testSetPreviewText02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testSetPreviewText02 START");
    TextListener::ResetParam();
    std::string text = "text";
    Range range = { 1, 2 };
    TextListenerInnerApiTest::imc_->textConfig_.inputAttribute.isTextPreviewSupported = true;
    // textListener is nullptr
    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = TextListenerInnerApiTest::imc_->SetPreviewText(text, range);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::previewText_, text);
    EXPECT_FALSE(TextListener::previewRange_ == range);
    // isEditable: false
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->isEditable_.store(false);
    ret = TextListenerInnerApiTest::imc_->SetPreviewText(text, range);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::previewText_, text);
    EXPECT_FALSE(TextListener::previewRange_ == range);
    TextListenerInnerApiTest::GetIMCDetached();
    // ClientState: INACTIVE
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->clientInfo_.state = ClientState::INACTIVE;
    ret = TextListenerInnerApiTest::imc_->SetPreviewText(text, range);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_NE(TextListener::previewText_, text);
    EXPECT_FALSE(TextListener::previewRange_ == range);
}

/**
 * @tc.name: testFinishTextPreview01
 * @tc.desc: insert text.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testFinishTextPreview01, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testFinishTextPreview01 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::imc_->textConfig_.inputAttribute.isTextPreviewSupported = true;
    TextListenerInnerApiTest::GetIMCAttached();
    int32_t ret = TextListenerInnerApiTest::imc_->FinishTextPreview();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(TextListener::isFinishTextPreviewCalled_);
    TextListenerInnerApiTest::GetIMCDetached();
}

/**
 * @tc.name: testFinishTextPreview02
 * @tc.desc: insert text without Attach.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TextListenerInnerApiTest, testFinishTextPreview02, TestSize.Level0)
{
    IMSA_HILOGI("TextListenerInnerApiTest testFinishTextPreview02 START");
    TextListener::ResetParam();
    TextListenerInnerApiTest::imc_->textConfig_.inputAttribute.isTextPreviewSupported = true;

    // textListener is nullptr
    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->textListener_ = nullptr;
    int32_t ret = TextListenerInnerApiTest::imc_->FinishTextPreview();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_FALSE(TextListener::isFinishTextPreviewCalled_);
    // isEditable: false
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->isEditable_.store(false);
    ret = TextListenerInnerApiTest::imc_->FinishTextPreview();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_FALSE(TextListener::isFinishTextPreviewCalled_);
    // ClientState: INACTIVE
    TextListener::ResetParam();
    TextListenerInnerApiTest::GetIMCAttached();
    TextListenerInnerApiTest::imc_->clientInfo_.state = ClientState::INACTIVE;
    ret = TextListenerInnerApiTest::imc_->FinishTextPreview();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_FALSE(TextListener::isFinishTextPreviewCalled_);
}
} // namespace MiscServices
} // namespace OHOS