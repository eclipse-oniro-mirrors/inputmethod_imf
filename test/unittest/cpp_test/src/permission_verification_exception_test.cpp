/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include "input_method_ability.h"
#undef private

#include <cstdint>
#include <gtest/gtest.h>
#include <regex>
#include <sstream>
#include <string>
#include <sys/time.h>
#include <unistd.h>

#include "global.h"
#include "input_method_ability.h"
#include "input_method_controller.h"
#include "tdd_util.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
class TextListener : public OnTextChangedListener {
public:
    TextListener() = default;
    ~TextListener() override = default;
    void InsertText(const std::u16string &text) override;
    void DeleteBackward(int32_t length) override;
    void SetKeyboardStatus(bool status) override;
    void DeleteForward(int32_t length) override;
    void SendKeyEventFromInputMethod(const KeyEvent &event) override;
    void SendKeyboardStatus(const KeyboardStatus &keyboardStatus) override;
    void SendFunctionKey(const FunctionKey &functionKey) override;
    void MoveCursor(const Direction direction) override;
    void HandleSetSelection(int32_t start, int32_t end) override;
    void HandleExtendAction(int32_t action) override;
    void HandleSelect(int32_t keyCode, int32_t cursorMoveSkip) override;
};

void TextListener::InsertText(const std::u16string &text)
{
}
void TextListener::DeleteBackward(int32_t length)
{
}
void TextListener::SetKeyboardStatus(bool status)
{
}
void TextListener::DeleteForward(int32_t length)
{
}
void TextListener::SendKeyEventFromInputMethod(const KeyEvent &event)
{
}
void TextListener::SendKeyboardStatus(const KeyboardStatus &keyboardStatus)
{
}
void TextListener::SendFunctionKey(const FunctionKey &functionKey)
{
}
void TextListener::MoveCursor(const Direction direction)
{
}
void TextListener::HandleSetSelection(int32_t start, int32_t end)
{
}
void TextListener::HandleExtendAction(int32_t action)
{
}

void TextListener::HandleSelect(int32_t keyCode, int32_t cursorMoveSkip)
{
}

class PermissionVerificationExceptionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static sptr<InputMethodController> imc_;
    static sptr<OnTextChangedListener> textListener_;
    static sptr<InputMethodAbility> ima_;
    static uint64_t tokenId_;
};
sptr<InputMethodController> PermissionVerificationExceptionTest::imc_;
sptr<OnTextChangedListener> PermissionVerificationExceptionTest::textListener_;
sptr<InputMethodAbility> PermissionVerificationExceptionTest::ima_;
uint64_t PermissionVerificationExceptionTest::tokenId_ = 0;

void PermissionVerificationExceptionTest::SetUpTestCase(void)
{
    IMSA_HILOGI("PermissionVerificationExceptionTest::SetUpTestCase");
    TddUtil::StorageSelfTokenID();
    ima_ = InputMethodAbility::GetInstance();
    ima_->OnImeReady();
    PermissionVerificationExceptionTest::textListener_ = new TextListener();
    imc_ = InputMethodController::GetInstance();
    auto property = InputMethodController::GetInstance()->GetCurrentInputMethod();
    EXPECT_NE(property, nullptr);
    tokenId_ = TddUtil::GetTestTokenID(property->name);
    TddUtil::StorageSelfUid();
}

void PermissionVerificationExceptionTest::TearDownTestCase(void)
{
    IMSA_HILOGI("PermissionVerificationExceptionTest::TearDownTestCase");
    TddUtil::KillImsaProcess();
}

void PermissionVerificationExceptionTest::SetUp(void)
{
    IMSA_HILOGI("PermissionVerificationExceptionTest::SetUp");
}

void PermissionVerificationExceptionTest::TearDown(void)
{
    IMSA_HILOGI("PermissionVerificationExceptionTest::TearDown");
}

/**
* @tc.name: ShowAndHideSoftKeyboard
* @tc.desc: PermissionVerificationExceptionTest ShowAndHideSoftKeyboard.
* @tc.type: FUNC
* @tc.require: issuesI640YZ
*/
HWTEST_F(PermissionVerificationExceptionTest, ShowAndHideSoftKeyboard, TestSize.Level0)
{
    IMSA_HILOGI("PermissionTest ShowAndHideSoftKeyboard TEST START");
    TddUtil::SetTestTokenID(tokenId_);
    PermissionVerificationExceptionTest::ima_->SetCoreAndAgent();
    TddUtil::RestoreSelfTokenID();

    TddUtil::SetTestUid();
    PermissionVerificationExceptionTest::imc_->Attach(PermissionVerificationExceptionTest::textListener_);
    int32_t ret = PermissionVerificationExceptionTest::imc_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    ret = PermissionVerificationExceptionTest::imc_->HideSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    TddUtil::RestoreSelfUid();
}

/**
* @tc.name: SwitchInputMethod
* @tc.desc: PermissionVerificationExceptionTest SwitchInputMethod.
* @tc.type: FUNC
* @tc.require: issuesI640YZ
*/
HWTEST_F(PermissionVerificationExceptionTest, SwitchInputMethod, TestSize.Level0)
{
    IMSA_HILOGI("PermissionTest SwitchInputMethod TEST START");
    auto property = PermissionVerificationExceptionTest::imc_->GetCurrentInputMethod();
    ASSERT_TRUE(property != nullptr);
    auto subProperty = PermissionVerificationExceptionTest::imc_->GetCurrentInputMethodSubtype();
    ASSERT_TRUE(subProperty != nullptr);

    int32_t ret = PermissionVerificationExceptionTest::imc_->SwitchInputMethod(property->name, subProperty->id);
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetCoreAndAgent
 * @tc.desc: PermissionVerificationExceptionTest SetCoreAndAgent.
 * @tc.type: FUNC
 * @tc.author: Zhaolinglan
 */
HWTEST_F(PermissionVerificationExceptionTest, SetCoreAndAgent, TestSize.Level0)
{
    IMSA_HILOGI("PermissionTest SetCoreAndAgent TEST START");
    InputMethodAbility::GetInstance()->isBound_.store(false);
    int32_t ret = InputMethodAbility::GetInstance()->SetCoreAndAgent();
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_CURRENT_IME);
}

/**
 * @tc.name: SetCoreAndAgentPassCheck
 * @tc.desc: PermissionVerificationExceptionTest SetCoreAndAgentPassCheck.
 * @tc.type: FUNC
 * @tc.author: Zhaolinglan
 */
HWTEST_F(PermissionVerificationExceptionTest, SetCoreAndAgentPassCheck, TestSize.Level0)
{
    IMSA_HILOGI("PermissionTest SetCoreAndAgentPassCheck TEST START");
    TddUtil::SetTestTokenID(tokenId_);
    InputMethodAbility::GetInstance()->isBound_.store(false);
    int32_t ret = InputMethodAbility::GetInstance()->SetCoreAndAgent();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    TddUtil::RestoreSelfTokenID();
}
} // namespace MiscServices
} // namespace OHOS