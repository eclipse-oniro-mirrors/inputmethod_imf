/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include "string_ex.h"

#include "global.h"
#include "input_method_controller.h"
#include "mock_input_method_system_ability_proxy.h"
#include "mock_iremote_object.h"
#include "native_inputmethod_types.h"
#include "native_text_changed_listener.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace testing;

namespace OHOS {
namespace MiscServices {
class NativeTextChangedListenerTest : public testing::Test {
public:
    static void SetUpTestSuite()
    {
        // 100000 means the uid of app
        setuid(100000);
        textEditorProxy_ = OH_TextEditorProxy_Create();
        ASSERT_NE(textEditorProxy_, nullptr) << "Failed to create InputMethod_TextEditorProxy";
        ConstructTextEditorProxy(textEditorProxy_);

        attachOptions_ = OH_AttachOptions_Create(true);
        ASSERT_NE(nullptr, attachOptions_);

        imc_ = InputMethodController::GetInstance();
        ASSERT_NE(imc_, nullptr);
        systemAbilityProxyMock_ = new (std::nothrow) NiceMock<MockInputMethodSystemAbilityProxy>();
        ASSERT_NE(systemAbilityProxyMock_, nullptr);
        MockInputMethodSystemAbilityProxy::SetImsaProxyForTest(imc_, systemAbilityProxyMock_);

        ON_CALL(*systemAbilityProxyMock_, StartInput(_, _, _))
            .WillByDefault(Invoke([](const InputClientInfoInner &info, vector<sptr<IRemoteObject>> &agents,
                                      vector<BindImeInfo> &imeInfos) {
                sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) NiceMock<MockIRemoteObject>();
                EXPECT_NE(iremoteObject, nullptr);
                agents.emplace_back(iremoteObject);
                BindImeInfo imeinfo;
                imeInfos.push_back(imeinfo);
                return ErrorCode::NO_ERROR;
            }));
    }

    static void TearDownTestSuite()
    {
        setuid(0);
        MockInputMethodSystemAbilityProxy::SetImsaProxyForTest(imc_, nullptr);
        systemAbilityProxyMock_ = nullptr;
        if (textEditorProxy_ != nullptr) {
            OH_TextEditorProxy_Destroy(textEditorProxy_);
            textEditorProxy_ = nullptr;
        }

        if (attachOptions_ != nullptr) {
            OH_AttachOptions_Destroy(attachOptions_);
            attachOptions_ = nullptr;
        }
    }

    void SetUp() override
    {
        ConstructTextEditorProxy(textEditorProxy_);
        ASSERT_NE(imc_, nullptr);
    }

    static InputMethod_TextEditorProxy *textEditorProxy_;
    static InputMethod_AttachOptions *attachOptions_;
    static sptr<MockInputMethodSystemAbilityProxy> systemAbilityProxyMock_;
    static sptr<InputMethodController> imc_;

    static void ConstructTextEditorProxy(InputMethod_TextEditorProxy *textEditorProxy);
};

InputMethod_TextEditorProxy *NativeTextChangedListenerTest::textEditorProxy_ = nullptr;
InputMethod_AttachOptions *NativeTextChangedListenerTest::attachOptions_ = nullptr;
sptr<MockInputMethodSystemAbilityProxy> NativeTextChangedListenerTest::systemAbilityProxyMock_ = nullptr;
sptr<InputMethodController> NativeTextChangedListenerTest::imc_ = nullptr;
static void TestNativeTextChangedListener(sptr<NativeTextChangedListener> listener)
{
    listener->InsertText(u"");
    listener->DeleteForward(0);
    listener->DeleteBackward(0);
    listener->SendKeyboardStatus(KeyboardStatus::HIDE);
    FunctionKey functionKey;
    listener->SendFunctionKey(functionKey);
    listener->MoveCursor(OHOS::MiscServices::Direction::LEFT);
    listener->HandleSetSelection(0, 0);
    listener->HandleExtendAction(0);
    EXPECT_EQ(u"", listener->GetLeftTextOfCursor(0));
    EXPECT_EQ(u"", listener->GetLeftTextOfCursor(1));
    EXPECT_EQ(u"", listener->GetRightTextOfCursor(0));
    EXPECT_EQ(u"", listener->GetRightTextOfCursor(1));
    EXPECT_EQ(0, listener->GetTextIndexAtCursor());
    listener->FinishTextPreview();
}

/**
 * @tc.name: NativeTextChangedListener_001
 * @tc.desc: Test textEditorProxy_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, NativeTextChangedListener_001, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::NativeTextChangedListener_001 start");
    sptr<NativeTextChangedListener> listener = new (std::nothrow) NativeTextChangedListener(nullptr);
    ASSERT_NE(nullptr, listener);
    TestNativeTextChangedListener(listener);
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, listener->ReceivePrivateCommand(privateCommand));
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, listener->SetPreviewText(u"", Range({ 0, 0 })));
}

/**
 * @tc.name: CallbackIsNullTest_001
 * @tc.desc: Test callback is null.
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, CallbackIsNullTest_001, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::CallbackIsNullTest_001 start");
    auto textEditor = OH_TextEditorProxy_Create();
    EXPECT_NE(nullptr, textEditor);
    sptr<NativeTextChangedListener> listener = new (std::nothrow) NativeTextChangedListener(textEditor);
    ASSERT_NE(nullptr, listener);
    TestNativeTextChangedListener(listener);
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, listener->ReceivePrivateCommand(privateCommand));
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, listener->SetPreviewText(u"", Range({ 0, 0 })));
    OH_TextEditorProxy_Destroy(textEditor);
}

void GetTextConfig(InputMethod_TextEditorProxy *proxy, InputMethod_TextConfig *config) { }
void InsertText(InputMethod_TextEditorProxy *proxy, const char16_t *text, size_t length) { }
void DeleteForward(InputMethod_TextEditorProxy *proxy, int32_t length) { }
void DeleteBackward(InputMethod_TextEditorProxy *proxy, int32_t length) { }
void SendKeyboardStatus(InputMethod_TextEditorProxy *proxy, InputMethod_KeyboardStatus status) { }
void SendEnterKey(InputMethod_TextEditorProxy *proxy, InputMethod_EnterKeyType type) { }
void MoveCursor(InputMethod_TextEditorProxy *proxy, InputMethod_Direction direction) { }
void HandleSetSelection(InputMethod_TextEditorProxy *proxy, int32_t start, int32_t end) { }
void HandleExtendAction(InputMethod_TextEditorProxy *proxy, InputMethod_ExtendAction action) { }
void GetleftTextOfCursor(InputMethod_TextEditorProxy *proxy, int32_t number, char16_t text[], size_t *length)
{
    *length = 0;
}
void GetRightTextOfCursor(InputMethod_TextEditorProxy *proxy, int32_t number, char16_t text[], size_t *length)
{
    *length = 0;
}
int32_t GetTextIndexAtCursor(InputMethod_TextEditorProxy *proxy)
{
    return 0;
}
int32_t ReceivePrivateCommand(
    InputMethod_TextEditorProxy *proxy, InputMethod_PrivateCommand *privateCommand[], size_t size)
{
    return 0;
}
int32_t SetPreviewText(
    InputMethod_TextEditorProxy *proxy, const char16_t *text, size_t length, int32_t start, int32_t end)
{
    return 0;
}
void FinishTextPreview(InputMethod_TextEditorProxy *proxy) { }
void NativeTextChangedListenerTest::ConstructTextEditorProxy(InputMethod_TextEditorProxy *textEditorProxy)
{
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetTextConfigFunc(textEditorProxy, GetTextConfig));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetInsertTextFunc(textEditorProxy, InsertText));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetDeleteForwardFunc(textEditorProxy, DeleteForward));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetDeleteBackwardFunc(textEditorProxy, DeleteBackward));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetSendKeyboardStatusFunc(textEditorProxy, SendKeyboardStatus));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetSendEnterKeyFunc(textEditorProxy, SendEnterKey));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetMoveCursorFunc(textEditorProxy, MoveCursor));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetHandleSetSelectionFunc(textEditorProxy, HandleSetSelection));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetHandleExtendActionFunc(textEditorProxy, HandleExtendAction));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetLeftTextOfCursorFunc(textEditorProxy, GetleftTextOfCursor));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetRightTextOfCursorFunc(textEditorProxy, GetRightTextOfCursor));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetTextIndexAtCursorFunc(textEditorProxy, GetTextIndexAtCursor));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetReceivePrivateCommandFunc(textEditorProxy, ReceivePrivateCommand));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetSetPreviewTextFunc(textEditorProxy, SetPreviewText));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetFinishTextPreviewFunc(textEditorProxy, FinishTextPreview));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetCallbackInMainThread(textEditorProxy, false));
    InputMethod_ErrorCode ret = OH_TextEditorProxy_SetCallbackInMainThread(nullptr, true);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: CallbackFinishTest_001
 * @tc.desc: Test callback finish.
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, CallbackFinishTest_001, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::CallbackFinishTest_001 start");
    sptr<NativeTextChangedListener> listener = new (std::nothrow) NativeTextChangedListener(textEditorProxy_);
    ASSERT_NE(nullptr, listener);
    TestNativeTextChangedListener(listener);
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    privateCommand.insert({ "key", "value" });
    EXPECT_EQ(0, listener->ReceivePrivateCommand(privateCommand));
    EXPECT_EQ(0, listener->SetPreviewText(u"", Range({ 0, 0 })));
}

/**
 * @tc.name: ConvertKeyBoardStarusTest_001
 * @tc.desc: Test ConvertKeyBoardStarus.
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, ConvertKeyBoardStarusTest_001, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::ConvertKeyBoardStarusTest_001 start");
    sptr<NativeTextChangedListener> listener = new (std::nothrow) NativeTextChangedListener(textEditorProxy_);
    ASSERT_NE(nullptr, listener);
    listener->SendKeyboardStatus(KeyboardStatus::NONE);
    listener->SendKeyboardStatus(KeyboardStatus::HIDE);
    listener->SendKeyboardStatus(KeyboardStatus::SHOW);
}
/**
 * @tc.name: ConvertToCEnterKeyTypeTest_001
 * @tc.desc: Test ConvertToCEnterKeyType.
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, ConvertToCEnterKeyTypeTest_001, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::ConvertToCEnterKeyTypeTest_001 start");
    sptr<NativeTextChangedListener> listener = new (std::nothrow) NativeTextChangedListener(textEditorProxy_);
    ASSERT_NE(nullptr, listener);
    FunctionKey key;
    key.SetEnterKeyType(EnterKeyType::UNSPECIFIED);
    listener->SendFunctionKey(key);
    key.SetEnterKeyType(EnterKeyType::NONE);
    listener->SendFunctionKey(key);
    key.SetEnterKeyType(EnterKeyType::GO);
    listener->SendFunctionKey(key);
    key.SetEnterKeyType(EnterKeyType::SEARCH);
    listener->SendFunctionKey(key);
    key.SetEnterKeyType(EnterKeyType::SEND);
    listener->SendFunctionKey(key);
    key.SetEnterKeyType(EnterKeyType::NEXT);
    listener->SendFunctionKey(key);
    key.SetEnterKeyType(EnterKeyType::DONE);
    listener->SendFunctionKey(key);
    key.SetEnterKeyType(EnterKeyType::PREVIOUS);
    listener->SendFunctionKey(key);
    key.SetEnterKeyType(EnterKeyType::NEW_LINE);
    listener->SendFunctionKey(key);
}

/**
 * @tc.name: ConvertToCDirectionTest_001
 * @tc.desc: Test ConvertToCDirection.
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, ConvertToCDirectionTest_001, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::ConvertToCDirectionTest_001 start");
    sptr<NativeTextChangedListener> listener = new (std::nothrow) NativeTextChangedListener(textEditorProxy_);
    ASSERT_NE(nullptr, listener);
    listener->MoveCursor(OHOS::MiscServices::Direction::NONE);
    listener->MoveCursor(OHOS::MiscServices::Direction::UP);
    listener->MoveCursor(OHOS::MiscServices::Direction::DOWN);
    listener->MoveCursor(OHOS::MiscServices::Direction::RIGHT);
    listener->MoveCursor(OHOS::MiscServices::Direction::LEFT);
}

/**
 * @tc.name: ConvertToCExtendActionTest_001
 * @tc.desc: Test ConvertToCExtendAction.
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, ConvertToCExtendActionTest_001, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::ConvertToCExtendActionTest_001 start");
    sptr<NativeTextChangedListener> listener = new (std::nothrow) NativeTextChangedListener(textEditorProxy_);
    ASSERT_NE(nullptr, listener);
    listener->HandleExtendAction(static_cast<int32_t>(OHOS::MiscServices::ExtendAction::SELECT_ALL));
    listener->HandleExtendAction(static_cast<int32_t>(OHOS::MiscServices::ExtendAction::COPY));
    listener->HandleExtendAction(static_cast<int32_t>(OHOS::MiscServices::ExtendAction::CUT));
    listener->HandleExtendAction(static_cast<int32_t>(OHOS::MiscServices::ExtendAction::PASTE));
}

/**
 * @tc.name: GetTextWithInvalidLength_FAIL
 * @tc.desc: Test GetTextWithInvalidLength_FAIL.
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, GetTextWithInvalidLength_FAIL, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::GetTextWithInvalidLength_FAIL start");
    sptr<NativeTextChangedListener> listener = new (std::nothrow) NativeTextChangedListener(textEditorProxy_);
    ASSERT_NE(nullptr, listener);
    auto getTextOfCursor = [](InputMethod_TextEditorProxy *proxy, int32_t number, char16_t text[], size_t *length) {
        *length = number + 1;
    };
    OH_TextEditorProxy_SetGetRightTextOfCursorFunc(textEditorProxy_, getTextOfCursor);
    OH_TextEditorProxy_SetGetLeftTextOfCursorFunc(textEditorProxy_, getTextOfCursor);

    auto str = listener->GetRightTextOfCursor(10);
    EXPECT_EQ(str, u"");
    str = listener->GetLeftTextOfCursor(10);
    EXPECT_EQ(str, u"");
}

/**
 * @tc.name: CallInNonMainThreadAndNoPostTest_SUCCESS
 * @tc.desc: test call in non main thread and not post to main thread
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, CallInNonMainThreadAndNoPostTest_SUCCESS, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::CallInNonMainThreadAndNoPostTest_SUCCESS start");
    OH_TextEditorProxy_GetRightTextOfCursorFunc cbFunc = [](InputMethod_TextEditorProxy *, int32_t number,
                                                             char16_t text[], size_t *length) {
        for (size_t i = 0; i < number; i++) {
            text[i] = 'a';
        }
        *length = number;
    };

    OH_TextEditorProxy_SetGetRightTextOfCursorFunc(textEditorProxy_, cbFunc);
    OH_TextEditorProxy_SetGetLeftTextOfCursorFunc(textEditorProxy_, cbFunc);
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));
    auto func = []() {
        std::u16string realStr;
        auto ret = imc_->GetRight(5, realStr);
        EXPECT_EQ(ret, ErrorCode::NO_ERROR);
        std::u16string expectStr(u"aaaaa");
        EXPECT_EQ(realStr, expectStr);

        ret = imc_->GetLeft(6, realStr);
        EXPECT_EQ(ret, ErrorCode::NO_ERROR);
        expectStr = std::u16string(u"aaaaaa");
        EXPECT_EQ(realStr, expectStr);
    };

    std::thread noMainThread(func);
    noMainThread.join();
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: CallInNonMainThreadAndPostTest_FAIL
 * @tc.desc: test call in non main thread and post to main thread
 * @tc.type: FUNC
 */
HWTEST_F(NativeTextChangedListenerTest, CallInNonMainThreadAndPostTest_FAIL, TestSize.Level1)
{
    IMSA_HILOGI("NativeTextChangedListenerTest::CallInNonMainThreadAndPostTest_FAIL start");
    OH_TextEditorProxy_GetRightTextOfCursorFunc cbFunc = [](InputMethod_TextEditorProxy *, int32_t number,
                                                             char16_t text[], size_t *length) {
        for (size_t i = 0; i < number; i++) {
            text[i] = 'a';
        }
        *length = number;
    };

    OH_TextEditorProxy_SetGetRightTextOfCursorFunc(textEditorProxy_, cbFunc);
    OH_TextEditorProxy_SetCallbackInMainThread(textEditorProxy_, true);
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));
    auto func = []() {
        std::u16string realStr;
        auto ret = imc_->GetRight(5, realStr);
        EXPECT_EQ(ret, ErrorCode::NO_ERROR);
        std::u16string expectStr(u"");
        // eventHandler throwing tasks to the main thread does not work properly in tdd
        EXPECT_EQ(realStr, expectStr);
    };

    std::thread noMainThread(func);
    noMainThread.join();
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}
} // namespace MiscServices
} // namespace OHOS