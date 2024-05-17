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
#include <event_handler.h>
#include <gtest/gtest.h>
#include <string_ex.h>
#include <sys/time.h>

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "global.h"
#include "i_input_method_agent.h"
#include "i_input_method_system_ability.h"
#include "input_client_stub.h"
#include "input_data_channel_stub.h"
#include "input_method_ability.h"
#include "input_method_controller.h"
#include "input_method_engine_listener_impl.h"
#include "input_method_system_ability_proxy.h"
#include "input_method_utils.h"
#include "keyboard_listener.h"
#include "message_parcel.h"
#include "tdd_util.h"
#include "text_listener.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
class KeyboardListenerImpl : public KeyboardListener {
public:
    KeyboardListenerImpl(){};
    ~KeyboardListenerImpl(){};
    static int32_t keyCode_;
    static int32_t keyStatus_;
    static CursorInfo cursorInfo_;
    bool OnDealKeyEvent(
        const std::shared_ptr<MMI::KeyEvent> &keyEvent, sptr<KeyEventConsumerProxy> &consumer) override;
    bool OnKeyEvent(int32_t keyCode, int32_t keyStatus, sptr<KeyEventConsumerProxy> &consumer) override;
    bool OnKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, sptr<KeyEventConsumerProxy> &consumer) override;
    void OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height) override;
    void OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd) override;
    void OnTextChange(const std::string &text) override;
    void OnEditorAttributeChange(const InputAttribute &inputAttribute) override;
};
int32_t KeyboardListenerImpl::keyCode_ = 0;
int32_t KeyboardListenerImpl::keyStatus_ = 0;
CursorInfo KeyboardListenerImpl::cursorInfo_ = {};
bool KeyboardListenerImpl::OnKeyEvent(int32_t keyCode, int32_t keyStatus, sptr<KeyEventConsumerProxy> &consumer)
{
    IMSA_HILOGD("KeyboardListenerImpl::OnKeyEvent %{public}d %{public}d", keyCode, keyStatus);
    keyCode_ = keyCode;
    keyStatus_ = keyStatus;
    return true;
}
bool KeyboardListenerImpl::OnKeyEvent(
    const std::shared_ptr<MMI::KeyEvent> &keyEvent, sptr<KeyEventConsumerProxy> &consumer)
{
    return true;
}
bool KeyboardListenerImpl::OnDealKeyEvent(
    const std::shared_ptr<MMI::KeyEvent> &keyEvent, sptr<KeyEventConsumerProxy> &consumer)
{
    bool isKeyCodeConsume = OnKeyEvent(keyEvent->GetKeyCode(), keyEvent->GetKeyAction(), consumer);
    bool isKeyEventConsume = OnKeyEvent(keyEvent, consumer);
    if (consumer != nullptr) {
        consumer->OnKeyEventResult(isKeyEventConsume | isKeyCodeConsume);
    }
    return true;
}
void KeyboardListenerImpl::OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height)
{
    IMSA_HILOGD("KeyboardListenerImpl::OnCursorUpdate %{public}d %{public}d %{public}d", positionX, positionY, height);
    cursorInfo_ = { static_cast<double>(positionX), static_cast<double>(positionY), 0, static_cast<double>(height) };
}
void KeyboardListenerImpl::OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd)
{
}
void KeyboardListenerImpl::OnTextChange(const std::string &text)
{
}
void KeyboardListenerImpl::OnEditorAttributeChange(const InputAttribute &inputAttribute)
{
}

class InputMethodEditorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static sptr<InputMethodController> inputMethodController_;
    static sptr<InputMethodAbility> inputMethodAbility_;
    static std::shared_ptr<MMI::KeyEvent> keyEvent_;
    static std::shared_ptr<KeyboardListenerImpl> kbListener_;
    static std::shared_ptr<InputMethodEngineListenerImpl> imeListener_;
    static sptr<OnTextChangedListener> textListener_;
};
sptr<InputMethodController> InputMethodEditorTest::inputMethodController_;
sptr<InputMethodAbility> InputMethodEditorTest::inputMethodAbility_;
std::shared_ptr<MMI::KeyEvent> InputMethodEditorTest::keyEvent_;
std::shared_ptr<KeyboardListenerImpl> InputMethodEditorTest::kbListener_;
std::shared_ptr<InputMethodEngineListenerImpl> InputMethodEditorTest::imeListener_;
sptr<OnTextChangedListener> InputMethodEditorTest::textListener_;

void InputMethodEditorTest::SetUpTestCase(void)
{
    IMSA_HILOGI("InputMethodEditorTest::SetUpTestCase");
    TddUtil::StorageSelfTokenID();
    std::shared_ptr<Property> property = InputMethodController::GetInstance()->GetCurrentInputMethod();
    std::string bundleName = property != nullptr ? property->name : "default.inputmethod.unittest";
    TddUtil::SetTestTokenID(TddUtil::GetTestTokenID(bundleName));
    inputMethodAbility_ = InputMethodAbility::GetInstance();
    inputMethodAbility_->SetCoreAndAgent();
    kbListener_ = std::make_shared<KeyboardListenerImpl>();
    imeListener_ = std::make_shared<InputMethodEngineListenerImpl>();
    inputMethodAbility_->SetKdListener(kbListener_);
    inputMethodAbility_->SetImeListener(imeListener_);

    textListener_ = new TextListener();
    inputMethodController_ = InputMethodController::GetInstance();

    keyEvent_ = MMI::KeyEvent::Create();
    constexpr int32_t keyAction = 2;
    constexpr int32_t keyCode = 2001;
    keyEvent_->SetKeyAction(keyAction);
    keyEvent_->SetKeyCode(keyCode);
    TextListener::ResetParam();
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "undefine"));
    TddUtil::InitWindow(true);
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, false);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = InputMethodEditorTest::inputMethodController_->Close();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    TddUtil::GetUnfocused();
}

void InputMethodEditorTest::TearDownTestCase(void)
{
    IMSA_HILOGI("InputMethodEditorTest::TearDownTestCase");
    TddUtil::RestoreSelfTokenID();
    TextListener::ResetParam();
    TddUtil::DestroyWindow();
}

void InputMethodEditorTest::SetUp(void)
{
    IMSA_HILOGI("InputMethodEditorTest::SetUp");
}

void InputMethodEditorTest::TearDown(void)
{
    IMSA_HILOGI("InputMethodEditorTest::TearDown");
}

/**
 * @tc.name: testIMCAttachUnfocused
 * @tc.desc: InputMethodEditorTest Attach.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testIMCAttachUnfocused, TestSize.Level0)
{
    IMSA_HILOGD("InputMethodEditorTest Attach Unfocused Test START");
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(textListener_, false);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
    ret = InputMethodEditorTest::inputMethodController_->Attach(textListener_);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
    ret = InputMethodEditorTest::inputMethodController_->Attach(textListener_, true);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: test Unfocused
 * @tc.desc: InputMethodEditorTest Unfocused
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testUnfocused, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest Unfocused Test START");
    int32_t ret = InputMethodEditorTest::inputMethodController_->ShowTextInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->DispatchKeyEvent(
        InputMethodEditorTest::keyEvent_, [](std::shared_ptr<MMI::KeyEvent> &keyEvent, bool isConsumed) {});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    ret = InputMethodEditorTest::inputMethodController_->HideSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    ret = InputMethodEditorTest::inputMethodController_->StopInputSession();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
    ret = InputMethodEditorTest::inputMethodController_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->OnCursorUpdate({});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->OnSelectionChange(Str8ToStr16(""), 0, 0);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->SetCallingWindow(1);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->OnConfigurationChange({});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
}

/**
 * @tc.name: testRequestInput001.
 * @tc.desc: InputMethodEditorTest RequestShowInput/RequestHideInput neither permitted nor focused.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testRequestInput001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest testRequestInput001 Test START");
    int32_t ret = InputMethodEditorTest::inputMethodController_->RequestShowInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    ret = InputMethodEditorTest::inputMethodController_->RequestHideInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
}

/**
 * @tc.name: testRequestInput002.
 * @tc.desc: InputMethodEditorTest RequestShowInput/RequestHideInput with permitted and not focused.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testRequestInput002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest testRequestInput002 Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "undefine", { "ohos.permission.CONNECT_IME_ABILITY" }));
    int32_t ret = InputMethodEditorTest::inputMethodController_->RequestShowInput();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = InputMethodEditorTest::inputMethodController_->RequestHideInput();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    TddUtil::RestoreSelfTokenID();
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "undefine"));
}

/**
 * @tc.name: test AttachFocused
 * @tc.desc: InputMethodEditorTest Attach Focused
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testAttachFocused, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest Attach Focused Test START");
    TddUtil::GetFocused();
    InputMethodEditorTest::imeListener_->isInputStart_ = false;
    InputMethodEditorTest::imeListener_->keyboardState_ = false;
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, false);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    InputMethodEditorTest::imeListener_->isInputStart_ = false;
    InputMethodEditorTest::imeListener_->keyboardState_ = false;
    ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_);
    EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::SHOW));
    EXPECT_TRUE(imeListener_->keyboardState_);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    InputMethodEditorTest::imeListener_->isInputStart_ = false;
    InputMethodEditorTest::imeListener_->keyboardState_ = false;
    ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::SHOW));
    EXPECT_TRUE(imeListener_->keyboardState_);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    InputMethodEditorTest::inputMethodController_->Close();
    TddUtil::GetUnfocused();
}

/**
 * @tc.name: testShowSoftKeyboard
 * @tc.desc: InputMethodEditorTest ShowSoftKeyboard
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testShowSoftKeyboard, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest ShowSoftKeyboard Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "undefined", { "ohos.permission.CONNECT_IME_ABILITY" }));
    TddUtil::GetFocused();
    InputMethodEditorTest::imeListener_->keyboardState_ = false;
    TextListener::ResetParam();
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, false);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(imeListener_->keyboardState_ && TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::SHOW));
    InputMethodEditorTest::inputMethodController_->Close();
    TddUtil::GetUnfocused();
}

/**
 * @tc.name: testIMCHideTextInput.
 * @tc.desc: InputMethodEditorTest testHideTextInput.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testIMCHideTextInput, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest HideTextInputAndShowTextInput Test START");
    TddUtil::GetFocused();
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    imeListener_->keyboardState_ = true;
    InputMethodEditorTest::inputMethodController_->HideTextInput();
    ret = InputMethodEditorTest::inputMethodController_->DispatchKeyEvent(
        InputMethodEditorTest::keyEvent_, [](std::shared_ptr<MMI::KeyEvent> &keyEvent, bool isConsumed) {});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = InputMethodEditorTest::inputMethodController_->HideSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = InputMethodEditorTest::inputMethodController_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->OnCursorUpdate({});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->OnSelectionChange(Str8ToStr16(""), 0, 0);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->SetCallingWindow(1);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->OnConfigurationChange({});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    InputMethodEditorTest::inputMethodController_->Close();
    TddUtil::GetUnfocused();
}

/**
 * @tc.name: testIMCDeactivateClient.
 * @tc.desc: InputMethodEditorTest testIMCDeactivateClient.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testIMCDeactivateClient, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest testIMCDeactivateClient Test START");
    TddUtil::GetFocused();
    int32_t ret = inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    inputMethodController_->DeactivateClient();
    ret = inputMethodController_->DispatchKeyEvent(
        InputMethodEditorTest::keyEvent_, [](std::shared_ptr<MMI::KeyEvent> &keyEvent, bool isConsumed) {});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = inputMethodController_->ShowTextInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = inputMethodController_->HideTextInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = inputMethodController_->HideSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = inputMethodController_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = inputMethodController_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = inputMethodController_->OnCursorUpdate({});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = inputMethodController_->OnSelectionChange(Str8ToStr16(""), 0, 0);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = inputMethodController_->SetCallingWindow(1);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = inputMethodController_->OnConfigurationChange({});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);

    ret = inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    ret = inputMethodController_->ShowTextInput();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    InputMethodEditorTest::inputMethodController_->Close();
    TddUtil::GetUnfocused();
}

/**
 * @tc.name: testShowTextInput
 * @tc.desc: InputMethodEditorTest ShowTextInput
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testShowTextInput, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest ShowTextInput Test START");
    TddUtil::GetFocused();
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    InputMethodEditorTest::inputMethodController_->HideTextInput();

    ret = InputMethodEditorTest::inputMethodController_->ShowTextInput();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    bool consumeResult = false;
    ret = InputMethodEditorTest::inputMethodController_->DispatchKeyEvent(InputMethodEditorTest::keyEvent_,
        [&consumeResult](std::shared_ptr<MMI::KeyEvent> &keyEvent, bool isConsumed) { consumeResult = isConsumed; });
    usleep(1000);
    ret = ret && kbListener_->keyCode_ == keyEvent_->GetKeyCode()
          && kbListener_->keyStatus_ == keyEvent_->GetKeyAction();
    EXPECT_TRUE(consumeResult);
    InputMethodEditorTest::inputMethodController_->Close();
    TddUtil::GetUnfocused();
}

/**
 * @tc.name: testIMCClose.
 * @tc.desc: InputMethodEditorTest Close.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testIMCClose, TestSize.Level0)
{
    IMSA_HILOGI("IMC Close Test START");
    TddUtil::GetFocused();
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    InputMethodEditorTest::inputMethodController_->Close();

    ret = InputMethodEditorTest::inputMethodController_->ShowTextInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->DispatchKeyEvent(
        InputMethodEditorTest::keyEvent_, [](std::shared_ptr<MMI::KeyEvent> &keyEvent, bool isConsumed) {});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
    ret = InputMethodEditorTest::inputMethodController_->HideSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
    ret = InputMethodEditorTest::inputMethodController_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->OnCursorUpdate({});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->OnSelectionChange(Str8ToStr16(""), 0, 0);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->SetCallingWindow(1);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->OnConfigurationChange({});
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    TddUtil::GetUnfocused();
}

/**
 * @tc.name: testRequestShowInput.
 * @tc.desc: InputMethodEditorTest testRequestShowInput with focused.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testRequestShowInput, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest testRequestShowInput Test START");
    TddUtil::GetFocused();
    imeListener_->keyboardState_ = false;
    int32_t ret = InputMethodEditorTest::inputMethodController_->RequestShowInput();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(imeListener_->keyboardState_);
    TddUtil::GetUnfocused();
}

/**
 * @tc.name: testRequestHideInput_001.
 * @tc.desc: InputMethodEditorTest testRequestHideInput with focused.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testRequestHideInput_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest testRequestHideInput_001 Test START");
    TddUtil::GetFocused();
    imeListener_->keyboardState_ = true;
    int32_t ret = InputMethodEditorTest::inputMethodController_->RequestHideInput();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    TddUtil::GetUnfocused();
}

/**
 * @tc.name: testRequestHideInput_002.
 * @tc.desc: InputMethodEditorTest testRequestHideInput with focused.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testRequestHideInput_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest testRequestHideInput_002 Test START");
    TddUtil::GetFocused();
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, false);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    imeListener_->keyboardState_ = true;
    ret = InputMethodEditorTest::inputMethodController_->RequestHideInput();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_FALSE(imeListener_->keyboardState_);
    InputMethodEditorTest::inputMethodController_->Close();
    TddUtil::GetUnfocused();
}
} // namespace MiscServices
} // namespace OHOS
