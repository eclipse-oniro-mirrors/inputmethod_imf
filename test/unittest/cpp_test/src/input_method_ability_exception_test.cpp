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

#include <gtest/gtest.h>
#include "input_method_ability.h"
#include "iinput_method_agent.h"
#include "input_data_channel_proxy.h"
#include "input_data_channel_proxy_wrap.h"
#include "input_data_channel_service_impl.h"
#include "input_method_agent_service_impl.h"
#include "input_method_engine_listener_impl.h"
#include "input_data_channel_stub.h"
#include "input_method_agent_stub.h"
#include "input_method_engine_listener_impl.h"
#include "key_event_util.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
const std::u16string AGENTSTUB_INTERFACE_TOKEN = u"ohos.miscservices.inputmethod.IInputMethodAgent";
class InputMethodAbilityExceptionTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        IMSA_HILOGI("InputMethodAbilityExceptionTest::SetUpTestCase");
    }
    static void TearDownTestCase(void)
    {
        IMSA_HILOGI("InputMethodAbilityExceptionTest::TearDownTestCase");
    }
    void SetUp() { }
    void TearDown()
    {
        ResetMemberVar();
    }
    static void ResetMemberVar()
    {
        inputMethodAbility_.dataChannelProxyWrap_ = nullptr;
        inputMethodAbility_.dataChannelObject_ = nullptr;
        inputMethodAbility_.imeListener_ = nullptr;
        inputMethodAbility_.panels_.Clear();
    }
    static InputMethodAbility &inputMethodAbility_;
};
InputMethodAbility &InputMethodAbilityExceptionTest::inputMethodAbility_ = InputMethodAbility::GetInstance();

/**
 * @tc.name: testMoveCursorException
 * @tc.desc: InputMethodAbility MoveCursor
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Hollokin
 */
HWTEST_F(InputMethodAbilityExceptionTest, testMoveCursorException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest MoveCursor Test START");
    auto ret = inputMethodAbility_.MoveCursor(4); // move cursor right
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testInsertTextException
 * @tc.desc: InputMethodAbility InsertText
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Hollokin
 */
HWTEST_F(InputMethodAbilityExceptionTest, testInsertTextException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest InsertText Test START");
    auto ret = inputMethodAbility_.InsertText("text");
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_CHANNEL_NULLPTR);
}

/**
 * @tc.name: testSendFunctionKeyException
 * @tc.desc: InputMethodAbility SendFunctionKey
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Hollokin
 */
HWTEST_F(InputMethodAbilityExceptionTest, testSendFunctionKeyException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest SendFunctionKey Test START");
    auto ret = inputMethodAbility_.SendFunctionKey(0);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testSendExtendActionException
 * @tc.desc: InputMethodAbility SendExtendAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenyu
 */
HWTEST_F(InputMethodAbilityExceptionTest, testSendExtendActionException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest SendExtendAction Test START");
    constexpr int32_t action = 1;
    auto ret = inputMethodAbility_.SendExtendAction(action);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testSelectByRangeException
 * @tc.desc: InputMethodAbility SelectByRange
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenyu
 */
HWTEST_F(InputMethodAbilityExceptionTest, testSelectByRangeException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testSelectByRange START");
    // start < 0, end < 0
    int32_t start = -1;
    int32_t end = -2;
    auto ret = inputMethodAbility_.SelectByRange(start, end);
    EXPECT_EQ(ret, ErrorCode::ERROR_PARAMETER_CHECK_FAILED);
    // start < 0, end >0
    start = -1;
    end = 2;
    ret = inputMethodAbility_.SelectByRange(start, end);
    EXPECT_EQ(ret, ErrorCode::ERROR_PARAMETER_CHECK_FAILED);
    // end < 0, start > 0
    start = 1;
    end = -2;
    ret = inputMethodAbility_.SelectByRange(start, end);
    EXPECT_EQ(ret, ErrorCode::ERROR_PARAMETER_CHECK_FAILED);
    // dataChannel == nullptr
    start = 1;
    end = 2;
    ret = inputMethodAbility_.SelectByRange(start, end);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testSelectByMovementException
 * @tc.desc: InputMethodAbility SelectByMovement
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenyu
 */
HWTEST_F(InputMethodAbilityExceptionTest, testSelectByMovementException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testSelectByMovement START");
    constexpr int32_t direction = 1;
    auto ret = inputMethodAbility_.SelectByMovement(direction);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testDeleteExceptionText
 * @tc.desc: InputMethodAbility DeleteForward & DeleteBackward
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Hollokin
 */
HWTEST_F(InputMethodAbilityExceptionTest, testDeleteExceptionText, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testDelete Test START");
    int32_t deleteForwardLenth = 1;
    auto ret = inputMethodAbility_.DeleteForward(deleteForwardLenth);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_CHANNEL_NULLPTR);
    int32_t deleteBackwardLenth = 2;
    ret = inputMethodAbility_.DeleteBackward(deleteBackwardLenth);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_CHANNEL_NULLPTR);
}

/**
 * @tc.name: testGetTextException001
 * @tc.desc: InputMethodAbility GetTextBeforeCursor & GetTextAfterCursor & GetTextIndexAtCursor
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Hollokin
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetTextException001, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetText001 START");
    std::u16string text;
    auto ret = inputMethodAbility_.GetTextAfterCursor(8, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
    ret = inputMethodAbility_.GetTextBeforeCursor(3, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
    int32_t index;
    ret = inputMethodAbility_.GetTextIndexAtCursor(index);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testGetEnterKeyTypeException
 * @tc.desc: InputMethodAbility GetEnterKeyType & GetInputPattern
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Hollokin
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetEnterKeyTypeException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetEnterKeyType START");
    int32_t keyType2;
    auto ret = inputMethodAbility_.GetEnterKeyType(keyType2);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
    int32_t inputPattern;
    ret = inputMethodAbility_.GetInputPattern(inputPattern);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testDispatchKeyEventException
 * @tc.desc: DispatchKeyEvent Exception
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenyu
 */
HWTEST_F(InputMethodAbilityExceptionTest, testDispatchKeyEventException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest DispatchKeyEvent START");
    // keyEvent == nullptr;
    std::shared_ptr<MMI::KeyEvent> keyEvent = nullptr;
    uint64_t cbId = 12;
    auto ret = inputMethodAbility_.DispatchKeyEvent(keyEvent, cbId, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);

    // kdListener_ == nullptr
    keyEvent = KeyEventUtil::CreateKeyEvent(MMI::KeyEvent::KEYCODE_A, MMI::KeyEvent::KEY_ACTION_DOWN);
    ret = inputMethodAbility_.DispatchKeyEvent(keyEvent, cbId, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testShowKeyboard_001
 * @tc.desc: ShowKeyboard Exception
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenyu
 */
HWTEST_F(InputMethodAbilityExceptionTest, testShowKeyboard_001, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testShowKeyboard_001 START");
    // channelObject == nullptr
    auto ret = inputMethodAbility_.ShowKeyboard(static_cast<int32_t>(RequestKeyboardReason::NONE));
    EXPECT_EQ(ret, ErrorCode::ERROR_IME);

    ResetMemberVar();
}

/**
 * @tc.name: testShowKeyboard_002
 * @tc.desc: ShowKeyBoard Exception
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenyu
 */
HWTEST_F(InputMethodAbilityExceptionTest, testShowKeyboard_002, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testShowKeyboard_002 START");
    // imeListener_ == nullptr
    auto ret = inputMethodAbility_.ShowKeyboard(static_cast<int32_t>(RequestKeyboardReason::NONE));
    EXPECT_EQ(ret, ErrorCode::ERROR_IME);

    auto imeListener = std::make_shared<InputMethodEngineListenerImpl>();
    inputMethodAbility_.SetImeListener(imeListener);
    sptr<InputDataChannelStub> channelObject = new InputDataChannelServiceImpl();
    inputMethodAbility_.SetInputDataChannel(channelObject->AsObject());
    // panel exist, PanelFlag == FLG_CANDIDATE_COLUMN
    auto panel = std::make_shared<InputMethodPanel>();
    panel->panelFlag_ = FLG_CANDIDATE_COLUMN;
    panel->windowId_ = 2;
    inputMethodAbility_.panels_.Insert(SOFT_KEYBOARD, panel);
    ret = inputMethodAbility_.ShowKeyboard(static_cast<int32_t>(RequestKeyboardReason::NONE));
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    // panel not exist
    inputMethodAbility_.panels_.Clear();
    ret = inputMethodAbility_.ShowKeyboard(static_cast<int32_t>(RequestKeyboardReason::NONE));
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ResetMemberVar();
}

/**
 * @tc.name: testHideKeyboard_001
 * @tc.desc: HideKeyboard Exception
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: chenyu
 */
HWTEST_F(InputMethodAbilityExceptionTest, testHideKeyboard_001, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testHideKeyboard_001 START");
    // imeListener_ == nullptr
    auto ret = inputMethodAbility_.HideKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_IME);

    // panel exist, PanelFlag == FLG_CANDIDATE_COLUMN
    auto imeListener = std::make_shared<InputMethodEngineListenerImpl>();
    inputMethodAbility_.SetImeListener(imeListener);
    sptr<InputDataChannelStub> channelObject = new InputDataChannelServiceImpl();
    inputMethodAbility_.SetInputDataChannel(channelObject->AsObject());
    auto panel = std::make_shared<InputMethodPanel>();
    panel->panelFlag_ = FLG_CANDIDATE_COLUMN;
    panel->windowId_ = 2;
    inputMethodAbility_.panels_.Insert(SOFT_KEYBOARD, panel);
    ret = inputMethodAbility_.HideKeyboard();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    // ShowPanel failed
    inputMethodAbility_.panels_.Clear();
    panel->panelFlag_ = FLG_FIXED;
    inputMethodAbility_.panels_.Insert(SOFT_KEYBOARD, panel);
    ret = inputMethodAbility_.HideKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);

    ResetMemberVar();
}

/**
 * @tc.name: testDispatchKeyEvent_001
 * @tc.desc: DispatchKeyEvent Exception
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: mashaoyin
 */
HWTEST_F(InputMethodAbilityExceptionTest, testDispatchKeyEvent_001, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testDispatchKeyEvent_001 START");
    sptr<InputMethodAgentStub> agentStub = new InputMethodAgentServiceImpl();
    MessageParcel data;
    data.WriteInterfaceToken(AGENTSTUB_INTERFACE_TOKEN);
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    keyEvent->WriteToParcel(data);
    data.WriteRemoteObject(nullptr);
    auto ret =
        agentStub->OnRemoteRequest(static_cast<uint32_t>(IInputMethodAgentIpcCode::COMMAND_DISPATCH_KEY_EVENT),
        data, reply, option);
    EXPECT_EQ(ret, ERR_TRANSACTION_FAILED);
}

/**
 * @tc.name: OnResponse_001
 * @tc.desc: OnResponse Exception
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(InputMethodAbilityExceptionTest, OnResponse_001, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest OnResponse_001 START");
    ResponseData data = std::monostate{};
    auto ret = inputMethodAbility_.OnResponse(0, 0, data);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: OnClientInactive_001
 * @tc.desc: OnClientInactive Exception
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(InputMethodAbilityExceptionTest, OnClientInactive_001, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest OnClientInactive_001 START");
    auto panel = std::make_shared<InputMethodPanel>();
    panel->panelFlag_ = FLG_FIXED;
    auto panel1 = std::make_shared<InputMethodPanel>();
    panel1->panelFlag_ = FLG_FLOATING;
    auto panel2 = std::make_shared<InputMethodPanel>();
    panel2->panelFlag_ = FLG_CANDIDATE_COLUMN;
    auto panel3 = std::make_shared<InputMethodPanel>();
    inputMethodAbility_.panels_.Insert(SOFT_KEYBOARD, panel);
    inputMethodAbility_.panels_.Insert(SOFT_KEYBOARD, panel1);
    inputMethodAbility_.panels_.Insert(SOFT_KEYBOARD, panel2);
    inputMethodAbility_.panels_.Insert(STATUS_BAR, panel3);
    sptr<InputDataChannelServiceImpl> stub = new InputDataChannelServiceImpl();
    ASSERT_NE(stub, nullptr);
    inputMethodAbility_.dataChannelObject_ = stub->AsObject();
    inputMethodAbility_.OnClientInactive(inputMethodAbility_.dataChannelObject_);
    EXPECT_EQ(inputMethodAbility_.dataChannelObject_, nullptr);
}

/**
 * @tc.name: HandleKeyEventResult_001
 * @tc.desc: HandleKeyEventResult Exception
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(InputMethodAbilityExceptionTest, HandleKeyEventResult_001, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest HandleKeyEventResult_001 START");
    uint64_t cbId = 9;
    bool consumeResult = true;
    auto ret = inputMethodAbility_.HandleKeyEventResult(cbId, consumeResult, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_CHANNEL_NULLPTR);
}

/**
 * @tc.name: testGetRichBeforeCursorException
 * @tc.desc: InputMethodAbility GetRichBeforeCursor with nullptr data channel proxy wrap.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetRichBeforeCursorException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetRichBeforeCursorException START");
    // Ensure dataChannelProxyWrap_ is nullptr to cover channel == nullptr branch.
    inputMethodAbility_.dataChannelProxyWrap_ = nullptr;
    RichTextData richText;
    int32_t number = 5;
    // sync branch: callback is nullptr
    auto ret = inputMethodAbility_.GetRichBeforeCursor(number, richText);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
    EXPECT_TRUE(richText.spans.empty());

    // async branch: callback is non-null, still fails at channel == nullptr check before Request.
    AsyncIpcCallBack callback = [](int32_t code, const ResponseData &data) {};
    RichTextData asyncRichText;
    ret = inputMethodAbility_.GetRichBeforeCursor(number, asyncRichText, callback);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
    EXPECT_TRUE(asyncRichText.spans.empty());
}

/**
 * @tc.name: testGetRichAfterCursorException
 * @tc.desc: InputMethodAbility GetRichAfterCursor with nullptr data channel proxy wrap.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetRichAfterCursorException, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetRichAfterCursorException START");
    // Ensure dataChannelProxyWrap_ is nullptr to cover channel == nullptr branch.
    inputMethodAbility_.dataChannelProxyWrap_ = nullptr;
    RichTextData richText;
    int32_t number = 5;
    // sync branch: callback is nullptr
    auto ret = inputMethodAbility_.GetRichAfterCursor(number, richText);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
    EXPECT_TRUE(richText.spans.empty());

    // async branch: callback is non-null, still fails at channel == nullptr check before Request.
    AsyncIpcCallBack callback = [](int32_t code, const ResponseData &data) {};
    RichTextData asyncRichText;
    ret = inputMethodAbility_.GetRichAfterCursor(number, asyncRichText, callback);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
    EXPECT_TRUE(asyncRichText.spans.empty());
}

/**
 * @tc.name: testGetRichBeforeCursorNormalBranch
 * @tc.desc: InputMethodAbility GetRichBeforeCursor with non-null data channel proxy wrap.
 *           Directly set dataChannelProxyWrap_ to a wrap constructed with a local
 *           InputDataChannelServiceImpl stub so GetInputDataChannelProxyWrap() returns
 *           non-null and the normal branch (channel->GetRichBeforeCursor) is executed.
 *           IPC fails on local stub, expecting ERROR_IMA_DATA_CHANNEL_ABNORMAL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetRichBeforeCursorNormalBranch, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetRichBeforeCursorNormalBranch START");
    // Construct a non-null channel wrap with a local stub. GetDataChannel() will return
    // a non-null InputDataChannelProxy, so Request() proceeds to call work() which does
    // channel->GetRichBeforeCursor. The IPC transaction fails on the local stub, so
    // Request() returns ERROR_IMA_DATA_CHANNEL_ABNORMAL.
    sptr<InputDataChannelStub> channelObject = new InputDataChannelServiceImpl();
    auto channelProxy = std::make_shared<InputDataChannelProxy>(channelObject->AsObject());
    inputMethodAbility_.dataChannelProxyWrap_ =
        std::make_shared<InputDataChannelProxyWrap>(channelProxy, nullptr);
    ASSERT_NE(inputMethodAbility_.dataChannelProxyWrap_, nullptr);

    // sync branch: callback == nullptr, covers InputMethodAbility line 973 + ProxyWrap sync path.
    RichTextData syncRichText;
    int32_t number = 5;
    auto ret = inputMethodAbility_.GetRichBeforeCursor(number, syncRichText);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(syncRichText.spans.empty());

    // async branch: callback != nullptr, covers InputMethodAbility line 973 + ProxyWrap async path.
    AsyncIpcCallBack callback = [](int32_t code, const ResponseData &data) {};
    RichTextData asyncRichText;
    ret = inputMethodAbility_.GetRichBeforeCursor(number, asyncRichText, callback);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(asyncRichText.spans.empty());
}

/**
 * @tc.name: testGetRichAfterCursorNormalBranch
 * @tc.desc: InputMethodAbility GetRichAfterCursor with non-null data channel proxy wrap.
 *           Same approach as testGetRichBeforeCursorNormalBranch but for GetRichAfterCursor.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetRichAfterCursorNormalBranch, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetRichAfterCursorNormalBranch START");
    sptr<InputDataChannelStub> channelObject = new InputDataChannelServiceImpl();
    auto channelProxy = std::make_shared<InputDataChannelProxy>(channelObject->AsObject());
    inputMethodAbility_.dataChannelProxyWrap_ =
        std::make_shared<InputDataChannelProxyWrap>(channelProxy, nullptr);
    ASSERT_NE(inputMethodAbility_.dataChannelProxyWrap_, nullptr);

    // sync branch: callback == nullptr, covers InputMethodAbility line 987 + ProxyWrap sync path.
    RichTextData syncRichText;
    int32_t number = 5;
    auto ret = inputMethodAbility_.GetRichAfterCursor(number, syncRichText);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(syncRichText.spans.empty());

    // async branch: callback != nullptr, covers InputMethodAbility line 987 + ProxyWrap async path.
    AsyncIpcCallBack callback = [](int32_t code, const ResponseData &data) {};
    RichTextData asyncRichText;
    ret = inputMethodAbility_.GetRichAfterCursor(number, asyncRichText, callback);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(asyncRichText.spans.empty());
}

/**
 * @tc.name: testGetRichBeforeCursorZeroLength
 * @tc.desc: InputMethodAbility GetRichBeforeCursor with number=0 returns empty RichTextData
 *           immediately without IPC, regardless of channel state (nullptr here).
 *           Covers the MIN_RICH_TEXT_LENGTH short-circuit for the sync path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetRichBeforeCursorZeroLength, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetRichBeforeCursorZeroLength START");
    // channel is nullptr to prove the short-circuit happens before channel check.
    inputMethodAbility_.dataChannelProxyWrap_ = nullptr;
    RichTextData richText;
    // Pre-fill a span to verify it gets cleared by the short-circuit.
    RichTextSpan span;
    span.type = SpanType::TEXT;
    span.content = "dummy";
    richText.spans.push_back(span);
    auto ret = inputMethodAbility_.GetRichBeforeCursor(MIN_RICH_TEXT_LENGTH, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(richText.spans.empty());
}

/**
 * @tc.name: testGetRichBeforeCursorZeroLengthAsync
 * @tc.desc: InputMethodAbility GetRichBeforeCursor with number=0 and async callback.
 *           The callback is invoked synchronously with NO_ERROR and empty RichTextData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetRichBeforeCursorZeroLengthAsync, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetRichBeforeCursorZeroLengthAsync START");
    inputMethodAbility_.dataChannelProxyWrap_ = nullptr;
    bool callbackInvoked = false;
    int32_t callbackCode = -1;
    AsyncIpcCallBack callback = [&callbackInvoked, &callbackCode](int32_t code, const ResponseData &data) {
        callbackInvoked = true;
        callbackCode = code;
        EXPECT_TRUE(std::holds_alternative<RichTextData>(data));
        if (std::holds_alternative<RichTextData>(data)) {
            EXPECT_TRUE(std::get<RichTextData>(data).spans.empty());
        }
    };
    RichTextData richText;
    auto ret = inputMethodAbility_.GetRichBeforeCursor(MIN_RICH_TEXT_LENGTH, richText, callback);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(richText.spans.empty());
    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(callbackCode, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testGetRichAfterCursorZeroLength
 * @tc.desc: InputMethodAbility GetRichAfterCursor with number=0 returns empty RichTextData
 *           immediately without IPC, regardless of channel state (nullptr here).
 *           Covers the MIN_RICH_TEXT_LENGTH short-circuit for the sync path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetRichAfterCursorZeroLength, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetRichAfterCursorZeroLength START");
    inputMethodAbility_.dataChannelProxyWrap_ = nullptr;
    RichTextData richText;
    // Pre-fill a span to verify it gets cleared by the short-circuit.
    RichTextSpan span;
    span.type = SpanType::TEXT;
    span.content = "dummy";
    richText.spans.push_back(span);
    auto ret = inputMethodAbility_.GetRichAfterCursor(MIN_RICH_TEXT_LENGTH, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(richText.spans.empty());
}

/**
 * @tc.name: testGetRichAfterCursorZeroLengthAsync
 * @tc.desc: InputMethodAbility GetRichAfterCursor with number=0 and async callback.
 *           The callback is invoked synchronously with NO_ERROR and empty RichTextData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testGetRichAfterCursorZeroLengthAsync, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testGetRichAfterCursorZeroLengthAsync START");
    inputMethodAbility_.dataChannelProxyWrap_ = nullptr;
    bool callbackInvoked = false;
    int32_t callbackCode = -1;
    AsyncIpcCallBack callback = [&callbackInvoked, &callbackCode](int32_t code, const ResponseData &data) {
        callbackInvoked = true;
        callbackCode = code;
        EXPECT_TRUE(std::holds_alternative<RichTextData>(data));
        if (std::holds_alternative<RichTextData>(data)) {
            EXPECT_TRUE(std::get<RichTextData>(data).spans.empty());
        }
    };
    RichTextData richText;
    auto ret = inputMethodAbility_.GetRichAfterCursor(MIN_RICH_TEXT_LENGTH, richText, callback);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(richText.spans.empty());
    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(callbackCode, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testProxyWrapGetRichBeforeCursorDirect
 * @tc.desc: Directly call InputDataChannelProxyWrap::GetRichBeforeCursor (bypassing
 *           InputMethodAbility) to guarantee ProxyWrap branch coverage without device.
 *           Sync (callback==nullptr) + async (callback!=nullptr) + channel==nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testProxyWrapGetRichBeforeCursorDirect, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testProxyWrapGetRichBeforeCursorDirect START");
    int32_t number = 5;

    // Case 1: sync call with nullptr remote channel -> work fails -> ERROR_IMA_DATA_CHANNEL_ABNORMAL.
    auto channelProxy = std::make_shared<InputDataChannelProxy>(nullptr);
    auto channelWrap = std::make_shared<InputDataChannelProxyWrap>(channelProxy, nullptr);
    ASSERT_NE(channelWrap, nullptr);
    RichTextData syncRichText;
    auto ret = channelWrap->GetRichBeforeCursor(number, syncRichText, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(syncRichText.spans.empty());

    // Case 2: async call with nullptr remote channel -> work fails -> ERROR_IMA_DATA_CHANNEL_ABNORMAL.
    RichTextData asyncRichText;
    AsyncIpcCallBack cb = [](int32_t code, const ResponseData &data) {};
    ret = channelWrap->GetRichBeforeCursor(number, asyncRichText, cb);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(asyncRichText.spans.empty());

    // Case 3: channel is nullptr -> Request returns ERROR_IMA_CHANNEL_NULLPTR.
    auto nullChannelWrap = std::make_shared<InputDataChannelProxyWrap>(nullptr, nullptr);
    RichTextData nullRichText;
    ret = nullChannelWrap->GetRichBeforeCursor(number, nullRichText, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_CHANNEL_NULLPTR);
    EXPECT_TRUE(nullRichText.spans.empty());
}

/**
 * @tc.name: testProxyWrapGetRichAfterCursorDirect
 * @tc.desc: Directly call InputDataChannelProxyWrap::GetRichAfterCursor (bypassing
 *           InputMethodAbility) to guarantee ProxyWrap branch coverage without device.
 *           Sync (callback==nullptr) + async (callback!=nullptr) + channel==nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodAbilityExceptionTest, testProxyWrapGetRichAfterCursorDirect, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodAbilityExceptionTest testProxyWrapGetRichAfterCursorDirect START");
    int32_t number = 5;

    // Case 1: sync call with nullptr remote channel -> work fails -> ERROR_IMA_DATA_CHANNEL_ABNORMAL.
    auto channelProxy = std::make_shared<InputDataChannelProxy>(nullptr);
    auto channelWrap = std::make_shared<InputDataChannelProxyWrap>(channelProxy, nullptr);
    ASSERT_NE(channelWrap, nullptr);
    RichTextData syncRichText;
    auto ret = channelWrap->GetRichAfterCursor(number, syncRichText, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(syncRichText.spans.empty());

    // Case 2: async call with nullptr remote channel -> work fails -> ERROR_IMA_DATA_CHANNEL_ABNORMAL.
    RichTextData asyncRichText;
    AsyncIpcCallBack cb = [](int32_t code, const ResponseData &data) {};
    ret = channelWrap->GetRichAfterCursor(number, asyncRichText, cb);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(asyncRichText.spans.empty());

    // Case 3: channel is nullptr -> Request returns ERROR_IMA_CHANNEL_NULLPTR.
    auto nullChannelWrap = std::make_shared<InputDataChannelProxyWrap>(nullptr, nullptr);
    RichTextData nullRichText;
    ret = nullChannelWrap->GetRichAfterCursor(number, nullRichText, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_CHANNEL_NULLPTR);
    EXPECT_TRUE(nullRichText.spans.empty());
}
} // namespace MiscServices
} // namespace OHOS
