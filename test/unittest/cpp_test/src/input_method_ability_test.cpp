/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "input_method_ability.h"

#include "input_method_controller.h"
#undef private

#include <gtest/gtest.h>
#include <string_ex.h>
#include <unistd.h>

#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "global.h"
#include "i_input_data_channel.h"
#include "input_attribute.h"
#include "input_control_channel_stub.h"
#include "input_data_channel_proxy.h"
#include "input_data_channel_stub.h"
#include "input_method_agent_stub.h"
#include "input_method_core_proxy.h"
#include "input_method_core_stub.h"
#include "input_method_panel.h"
#include "message_handler.h"
#include "scope_utils.h"
#include "tdd_util.h"
#include "text_listener.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
constexpr uint32_t DEALY_TIME = 1;
class InputMethodAbilityTest : public testing::Test {
public:
    static std::mutex imeListenerCallbackLock_;
    static std::condition_variable imeListenerCv_;
    static bool showKeyboard_;
    static constexpr int CURSOR_DIRECTION_BASE_VALUE = 2011;
    static sptr<InputMethodController> imc_;
    static sptr<OnTextChangedListener> textListener_;
    static sptr<InputMethodAbility> inputMethodAbility_;
    static uint32_t windowId_;
    static int32_t security_;
    static uint64_t currentImeTokenId_;
    static uint64_t defaultImeTokenId_;
    static int32_t currentImeUid_;

    class InputMethodEngineListenerImpl : public InputMethodEngineListener {
    public:
        InputMethodEngineListenerImpl() = default;
        ~InputMethodEngineListenerImpl() = default;

        void OnKeyboardStatus(bool isShow)
        {
            showKeyboard_ = isShow;
            InputMethodAbilityTest::imeListenerCv_.notify_one();
            IMSA_HILOGI("InputMethodEngineListenerImpl OnKeyboardStatus");
        }

        void OnInputStart()
        {
            IMSA_HILOGI("InputMethodEngineListenerImpl OnInputStart");
        }

        void OnInputStop()
        {
            IMSA_HILOGI("InputMethodEngineListenerImpl OnInputStop");
        }

        void OnSetCallingWindow(uint32_t windowId)
        {
            windowId_ = windowId;
            IMSA_HILOGI("InputMethodEngineListenerImpl OnSetCallingWindow");
        }

        void OnSetSubtype(const SubProperty &property)
        {
            IMSA_HILOGI("InputMethodEngineListenerImpl OnSetSubtype");
        }

        void OnSecurityChange(int32_t security)
        {
            security_ = security;
            IMSA_HILOGI("InputMethodEngineListenerImpl OnSecurityChange");
        }

        void ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
        {
            IMSA_HILOGI("InputMethodEngineListenerImpl ReceivePrivateCommand");
        }
    };

    static void SetUpTestCase(void)
    {
        // Set the tokenID to the tokenID of the current ime
        TddUtil::StorageSelfTokenID();
        std::shared_ptr<Property> property = InputMethodController::GetInstance()->GetCurrentInputMethod();
        auto currentIme = property != nullptr ? property->name : "default.inputmethod.unittest";
        currentImeTokenId_ = TddUtil::GetTestTokenID(currentIme);
        currentImeUid_ = TddUtil::GetUid(currentIme);
        auto ret = InputMethodController::GetInstance()->GetDefaultInputMethod(property);
        auto defaultIme = ret == ErrorCode::NO_ERROR ? property->name : "default.inputmethod.unittest";
        defaultImeTokenId_ = TddUtil::GetTestTokenID(defaultIme);
        {
            TokenScope scope(currentImeTokenId_);
            inputMethodAbility_ = InputMethodAbility::GetInstance();
            inputMethodAbility_->SetCoreAndAgent();
        }
        TextListener::ResetParam();
        TddUtil::InitWindow(true);
        imc_ = InputMethodController::GetInstance();
        textListener_ = new TextListener();
    }
    static void TearDownTestCase(void)
    {
        IMSA_HILOGI("InputMethodAbilityTest::TearDownTestCase");
        imc_->Close();
        TextListener::ResetParam();
        TddUtil::DestroyWindow();
        TddUtil::RestoreSelfTokenID();
    }
    static void GetIMCAttachIMA()
    {
        imc_->SetTextListener(textListener_);
        imc_->clientInfo_.state = ClientState::ACTIVE;
        imc_->isBound_.store(true);
        imc_->isEditable_.store(true);
        auto agent = inputMethodAbility_->agentStub_->AsObject();
        imc_->SetAgent(agent);

        sptr<IInputDataChannel> channel = iface_cast<IInputDataChannel>(imc_->clientInfo_.channel);
        inputMethodAbility_->SetInputDataChannel(channel->AsObject());
        IMSA_HILOGI("end");
    }
    static void GetIMCDetachIMA()
    {
        imc_->OnInputStop();
        inputMethodAbility_->ClearDataChannel(inputMethodAbility_->dataChannelObject_);
        IMSA_HILOGI("end");
    }
    void SetUp()
    {
        IMSA_HILOGI("InputMethodAbilityTest::SetUp");
    }
    void TearDown()
    {
        IMSA_HILOGI("InputMethodAbilityTest::TearDown");
    }
    void CheckPanelStatusInfo(const std::shared_ptr<InputMethodPanel> &panel, const PanelStatusInfo &info)
    {
        TextListener::ResetParam();
        info.visible ? CheckPanelInfoInShow(panel, info) : CheckPanelInfoInHide(panel, info);
    }
    void CheckPanelInfoInShow(const std::shared_ptr<InputMethodPanel> &panel, const PanelStatusInfo &info)
    {
        auto ret = inputMethodAbility_->ShowPanel(panel);
        EXPECT_EQ(ret, ErrorCode::NO_ERROR);
        if (info.panelInfo.panelFlag != FLG_CANDIDATE_COLUMN) {
            if (info.panelInfo.panelType == SOFT_KEYBOARD) {
                EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::SHOW));
            } else {
                EXPECT_FALSE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::SHOW));
            }
            EXPECT_TRUE(TextListener::WaitNotifyPanelStatusInfoCallback(
                { { info.panelInfo.panelType, info.panelInfo.panelFlag }, info.visible, info.trigger }));
            return;
        }
        EXPECT_FALSE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::SHOW));
        EXPECT_FALSE(TextListener::WaitNotifyPanelStatusInfoCallback(
            { { info.panelInfo.panelType, info.panelInfo.panelFlag }, info.visible, info.trigger }));
    }
    void CheckPanelInfoInHide(const std::shared_ptr<InputMethodPanel> &panel, const PanelStatusInfo &info)
    {
        AccessScope scope(currentImeTokenId_, currentImeUid_);
        auto ret = inputMethodAbility_->HidePanel(panel);
        EXPECT_EQ(ret, ErrorCode::NO_ERROR);
        if (info.panelInfo.panelFlag != FLG_CANDIDATE_COLUMN) {
            if (info.panelInfo.panelType == SOFT_KEYBOARD) {
                EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::HIDE));
            } else {
                EXPECT_FALSE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::HIDE));
            };
            EXPECT_TRUE(TextListener::WaitNotifyPanelStatusInfoCallback(
                { { info.panelInfo.panelType, info.panelInfo.panelFlag }, info.visible, info.trigger }));
            return;
        }
        EXPECT_FALSE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::HIDE));
        EXPECT_FALSE(TextListener::WaitNotifyPanelStatusInfoCallback(
            { { info.panelInfo.panelType, info.panelInfo.panelFlag }, info.visible, info.trigger }));
    }
};

std::mutex InputMethodAbilityTest::imeListenerCallbackLock_;
std::condition_variable InputMethodAbilityTest::imeListenerCv_;
bool InputMethodAbilityTest::showKeyboard_ = true;
sptr<InputMethodController> InputMethodAbilityTest::imc_;
sptr<OnTextChangedListener> InputMethodAbilityTest::textListener_;
sptr<InputMethodAbility> InputMethodAbilityTest::inputMethodAbility_;
uint32_t InputMethodAbilityTest::windowId_ = 0;
int32_t InputMethodAbilityTest::security_ = -1;
uint64_t InputMethodAbilityTest::currentImeTokenId_ = 0;
uint64_t InputMethodAbilityTest::defaultImeTokenId_ = 0;
int32_t InputMethodAbilityTest::currentImeUid_ = 0;

/**
* @tc.name: testSerializedInputAttribute
* @tc.desc: Checkout the serialization of InputAttribute.
* @tc.type: FUNC
*/
HWTEST_F(InputMethodAbilityTest, testSerializedInputAttribute, TestSize.Level0)
{
    InputAttribute inAttribute;
    inAttribute.inputPattern = InputAttribute::PATTERN_PASSWORD;
    MessageParcel data;
    EXPECT_TRUE(InputAttribute::Marshalling(inAttribute, data));
    InputAttribute outAttribute;
    EXPECT_TRUE(InputAttribute::Unmarshalling(outAttribute, data));
    EXPECT_TRUE(outAttribute.GetSecurityFlag());
}

/**
* @tc.name: testShowKeyboardInputMethodCoreProxy
* @tc.desc: Test InputMethodCoreProxy ShowKeyboard
* @tc.type: FUNC
* @tc.require: issueI5NXHK
*/
HWTEST_F(InputMethodAbilityTest, testShowKeyboardInputMethodCoreProxy, TestSize.Level0)
{
    IMSA_HILOGI("testShowKeyboardInputMethodCoreProxy start.");
    sptr<InputMethodCoreStub> coreStub = new InputMethodCoreStub();
    sptr<IInputMethodCore> core = coreStub;
    auto msgHandler = new (std::nothrow) MessageHandler();
    coreStub->SetMessageHandler(msgHandler);
    sptr<InputDataChannelStub> channelStub = new InputDataChannelStub();

    MessageParcel data;
    data.WriteRemoteObject(core->AsObject());
    data.WriteRemoteObject(channelStub->AsObject());
    sptr<IRemoteObject> coreObject = data.ReadRemoteObject();
    sptr<IRemoteObject> channelObject = data.ReadRemoteObject();

    sptr<InputMethodCoreProxy> coreProxy = new InputMethodCoreProxy(coreObject);
    sptr<InputDataChannelProxy> channelProxy = new InputDataChannelProxy(channelObject);
    auto ret = coreProxy->ShowKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_IME);
    delete msgHandler;
}

/**
* @tc.name: testShowKeyboardWithoutImeListener
* @tc.desc: InputMethodAbility ShowKeyboard without imeListener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testShowKeyboardWithoutImeListener, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testShowKeyboardWithoutImeListener start.");
    auto ret = inputMethodAbility_->ShowKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_IME);
}

/**
* @tc.name: testHideKeyboardWithoutImeListener
* @tc.desc: InputMethodAbility HideKeyboard without imeListener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testHideKeyboardWithoutImeListener, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testHideKeyboardWithoutImeListener start.");
    auto ret = inputMethodAbility_->HideKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_IME);
}

/**
* @tc.name: testStartInputWithoutPanel
* @tc.desc: InputMethodAbility StartInput Without Panel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testStartInputWithoutPanel, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testStartInputWithoutAttach start.");
    inputMethodAbility_->SetImeListener(std::make_shared<InputMethodEngineListenerImpl>());
    sptr<InputDataChannelStub> channelStub = new InputDataChannelStub();
    InputClientInfo clientInfo;
    clientInfo.channel = channelStub;
    auto ret = inputMethodAbility_->StartInput(clientInfo, false);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    clientInfo.isShowKeyboard = true;
    ret = inputMethodAbility_->StartInput(clientInfo, false);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testHideKeyboardSelf
* @tc.desc: InputMethodAbility HideKeyboardSelf
* @tc.type: FUNC
* @tc.require:
* @tc.author: Hollokin
*/
HWTEST_F(InputMethodAbilityTest, testHideKeyboardSelf, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testHideKeyboardSelf START");
    imc_->Attach(textListener_);
    std::unique_lock<std::mutex> lock(InputMethodAbilityTest::imeListenerCallbackLock_);
    InputMethodAbilityTest::showKeyboard_ = true;
    inputMethodAbility_->SetImeListener(std::make_shared<InputMethodEngineListenerImpl>());
    auto ret = inputMethodAbility_->HideKeyboardSelf();
    InputMethodAbilityTest::imeListenerCv_.wait_for(
        lock, std::chrono::seconds(DEALY_TIME), [] { return InputMethodAbilityTest::showKeyboard_ == false; });
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_FALSE(InputMethodAbilityTest::showKeyboard_);
}

/**
* @tc.name: testMoveCursor
* @tc.desc: InputMethodAbility MoveCursor
* @tc.type: FUNC
* @tc.require:
* @tc.author: Hollokin
*/
HWTEST_F(InputMethodAbilityTest, testMoveCursor, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility MoveCursor Test START");
    constexpr int32_t keyCode = 4;
    auto ret = inputMethodAbility_->MoveCursor(keyCode); // move cursor right
    std::unique_lock<std::mutex> lock(TextListener::textListenerCallbackLock_);
    TextListener::textListenerCv_.wait_for(
        lock, std::chrono::seconds(DEALY_TIME), [] { return TextListener::direction_ == keyCode; });
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::direction_, keyCode);
}

/**
* @tc.name: testInsertText
* @tc.desc: InputMethodAbility InsertText
* @tc.type: FUNC
* @tc.require:
* @tc.author: Hollokin
*/
HWTEST_F(InputMethodAbilityTest, testInsertText, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility InsertText Test START");
    std::string text = "text";
    std::u16string u16Text = Str8ToStr16(text);
    auto ret = inputMethodAbility_->InsertText(text);
    std::unique_lock<std::mutex> lock(TextListener::textListenerCallbackLock_);
    TextListener::textListenerCv_.wait_for(
        lock, std::chrono::seconds(DEALY_TIME), [u16Text] { return TextListener::insertText_ == u16Text; });
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::insertText_, u16Text);
}

/**
* @tc.name: testSendFunctionKey
* @tc.desc: InputMethodAbility SendFunctionKey
* @tc.type: FUNC
* @tc.require:
* @tc.author: Hollokin
*/
HWTEST_F(InputMethodAbilityTest, testSendFunctionKey, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility SendFunctionKey Test START");
    constexpr int32_t funcKey = 1;
    auto ret = inputMethodAbility_->SendFunctionKey(funcKey);
    std::unique_lock<std::mutex> lock(TextListener::textListenerCallbackLock_);
    TextListener::textListenerCv_.wait_for(
        lock, std::chrono::seconds(DEALY_TIME), [] { return TextListener::key_ == funcKey; });
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::key_, funcKey);
}

/**
* @tc.name: testSendExtendAction
* @tc.desc: InputMethodAbility SendExtendAction
* @tc.type: FUNC
* @tc.require:
* @tc.author: chenyu
*/
HWTEST_F(InputMethodAbilityTest, testSendExtendAction, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility SendExtendAction Test START");
    constexpr int32_t action = 1;
    auto ret = inputMethodAbility_->SendExtendAction(action);
    std::unique_lock<std::mutex> lock(TextListener::textListenerCallbackLock_);
    TextListener::textListenerCv_.wait_for(
        lock, std::chrono::seconds(DEALY_TIME), [] { return TextListener::action_ == action; });
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::action_, action);
}

/**
* @tc.name: testDeleteText
* @tc.desc: InputMethodAbility DeleteForward & DeleteBackward
* @tc.type: FUNC
* @tc.require:
* @tc.author: Hollokin
*/
HWTEST_F(InputMethodAbilityTest, testDeleteText, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testDelete Test START");
    int32_t deleteForwardLenth = 1;
    auto ret = inputMethodAbility_->DeleteForward(deleteForwardLenth);
    std::unique_lock<std::mutex> lock(TextListener::textListenerCallbackLock_);
    TextListener::textListenerCv_.wait_for(lock, std::chrono::seconds(DEALY_TIME),
        [deleteForwardLenth] { return TextListener::deleteBackwardLength_ == deleteForwardLenth; });
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::deleteBackwardLength_, deleteForwardLenth);

    int32_t deleteBackwardLenth = 2;
    ret = inputMethodAbility_->DeleteBackward(deleteBackwardLenth);
    TextListener::textListenerCv_.wait_for(lock, std::chrono::seconds(DEALY_TIME),
        [deleteBackwardLenth] { return TextListener::deleteForwardLength_ == deleteBackwardLenth; });
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::deleteForwardLength_, deleteBackwardLenth);
}

/**
* @tc.name: testGetEnterKeyType
* @tc.desc: InputMethodAbility GetEnterKeyType & GetInputPattern
* @tc.type: FUNC
* @tc.require:
* @tc.author: Hollokin
*/
HWTEST_F(InputMethodAbilityTest, testGetEnterKeyType, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetEnterKeyType START");
    Configuration config;
    EnterKeyType keyType = EnterKeyType::NEXT;
    config.SetEnterKeyType(keyType);
    TextInputType textInputType = TextInputType::DATETIME;
    config.SetTextInputType(textInputType);
    imc_->OnConfigurationChange(config);
    int32_t keyType2;
    auto ret = inputMethodAbility_->GetEnterKeyType(keyType2);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(keyType2, (int)keyType);
    int32_t inputPattern;
    ret = inputMethodAbility_->GetInputPattern(inputPattern);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(inputPattern, (int)textInputType);
}

/**
* @tc.name: testGetTextConfig
* @tc.desc: InputMethodAbility GetTextConfig
* @tc.type: FUNC
* @tc.require:
* @tc.author: Hollokin
*/
HWTEST_F(InputMethodAbilityTest, testGetTextConfig, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetTextConfig START");
    TextConfig textConfig;
    textConfig.inputAttribute = { .inputPattern = 0, .enterKeyType = 1 };
    auto ret = imc_->Attach(textListener_, false, textConfig);
    TextTotalConfig textTotalConfig;
    ret = inputMethodAbility_->GetTextConfig(textTotalConfig);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(textTotalConfig.inputAttribute.inputPattern, textConfig.inputAttribute.inputPattern);
    EXPECT_EQ(textTotalConfig.inputAttribute.enterKeyType, textConfig.inputAttribute.enterKeyType);
}

/**
* @tc.name: testSelectByRange_001
* @tc.desc: InputMethodAbility SelectByRange
* @tc.type: FUNC
* @tc.require:
* @tc.author: Zhaolinglan
*/
HWTEST_F(InputMethodAbilityTest, testSelectByRange_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testSelectByRange_001 START");
    constexpr int32_t start = 1;
    constexpr int32_t end = 2;
    auto ret = inputMethodAbility_->SelectByRange(start, end);
    std::unique_lock<std::mutex> lock(TextListener::textListenerCallbackLock_);
    TextListener::textListenerCv_.wait_for(lock, std::chrono::seconds(DEALY_TIME),
        [] { return TextListener::selectionStart_ == start && TextListener::selectionEnd_ == end; });
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::selectionStart_, start);
    EXPECT_EQ(TextListener::selectionEnd_, end);
}

/**
* @tc.name: testSelectByRange_002
* @tc.desc: InputMethodAbility SelectByRange
* @tc.type: FUNC
* @tc.require:
* @tc.author: chenyu
*/
HWTEST_F(InputMethodAbilityTest, testSelectByRange_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testSelectByRange_002 START");
    int32_t start = -2;
    int32_t end = 2;
    auto ret = inputMethodAbility_->SelectByRange(start, end);
    EXPECT_EQ(ret, ErrorCode::ERROR_PARAMETER_CHECK_FAILED);

    start = 2;
    end = -2;
    ret = inputMethodAbility_->SelectByRange(start, end);
    EXPECT_EQ(ret, ErrorCode::ERROR_PARAMETER_CHECK_FAILED);
}

/**
* @tc.name: testSelectByMovement
* @tc.desc: InputMethodAbility SelectByMovement
* @tc.type: FUNC
* @tc.require:
* @tc.author: Zhaolinglan
*/
HWTEST_F(InputMethodAbilityTest, testSelectByMovement, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testSelectByMovement START");
    constexpr int32_t direction = 1;
    auto ret = inputMethodAbility_->SelectByMovement(direction);
    std::unique_lock<std::mutex> lock(TextListener::textListenerCallbackLock_);
    TextListener::textListenerCv_.wait_for(lock, std::chrono::seconds(DEALY_TIME), [] {
        return TextListener::selectionDirection_ == direction + InputMethodAbilityTest::CURSOR_DIRECTION_BASE_VALUE;
    });
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::selectionDirection_, direction + InputMethodAbilityTest::CURSOR_DIRECTION_BASE_VALUE);
}

/**
* @tc.name: testGetTextAfterCursor
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testGetTextAfterCursor, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetTextAfterCursor START");
    int32_t number = 3;
    std::u16string text;
    auto ret = inputMethodAbility_->GetTextAfterCursor(number, text);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(text, Str8ToStr16(TextListener::TEXT_AFTER_CURSOR));
}

/**
* @tc.name: testGetTextBeforeCursor
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testGetTextBeforeCursor, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetTextBeforeCursor START");
    int32_t number = 5;
    std::u16string text;
    auto ret = inputMethodAbility_->GetTextBeforeCursor(number, text);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(text, Str8ToStr16(TextListener::TEXT_BEFORE_CURSOR));
}

/**
* @tc.name: testGetTextIndexAtCursor
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testGetTextIndexAtCursor, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetTextIndexAtCursor START");
    int32_t index;
    auto ret = inputMethodAbility_->GetTextIndexAtCursor(index);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(index, TextListener::TEXT_INDEX);
}

/**
* @tc.name: testCreatePanel001
* @tc.desc: It's allowed to create one SOFT_KEYBOARD panel, but two is denied.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testCreatePanel001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testCreatePanel001 START. You can not create two SOFT_KEYBOARD panel.");
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    std::shared_ptr<InputMethodPanel> softKeyboardPanel1 = nullptr;
    PanelInfo panelInfo = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FIXED };
    auto ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo, softKeyboardPanel1);
    EXPECT_TRUE(softKeyboardPanel1 != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    std::shared_ptr<InputMethodPanel> softKeyboardPanel2 = nullptr;
    ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo, softKeyboardPanel2);
    EXPECT_TRUE(softKeyboardPanel2 == nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_OPERATE_PANEL);

    ret = inputMethodAbility_->DestroyPanel(softKeyboardPanel1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(softKeyboardPanel2);
    EXPECT_EQ(ret, ErrorCode::ERROR_BAD_PARAMETERS);
}

/**
* @tc.name: testCreatePanel002
* @tc.desc: It's allowed to create one STATUS_BAR panel, but two is denied.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testCreatePanel002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testCreatePanel002 START. You can not create two STATUS_BAR panel.");
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    std::shared_ptr<InputMethodPanel> statusBar1 = nullptr;
    PanelInfo panelInfo = { .panelType = STATUS_BAR };
    auto ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo, statusBar1);
    EXPECT_TRUE(statusBar1 != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    std::shared_ptr<InputMethodPanel> statusBar2 = nullptr;
    ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo, statusBar2);
    EXPECT_TRUE(statusBar2 == nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_OPERATE_PANEL);

    ret = inputMethodAbility_->DestroyPanel(statusBar1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(statusBar2);
    EXPECT_EQ(ret, ErrorCode::ERROR_BAD_PARAMETERS);
}

/**
* @tc.name: testCreatePanel003
* @tc.desc: It's allowed to create one STATUS_BAR panel and one SOFT_KEYBOARD panel.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testCreatePanel003, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testCreatePanel006 START. Allowed to create one SOFT_KEYBOARD panel and "
                "one STATUS_BAR panel.");
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    std::shared_ptr<InputMethodPanel> softKeyboardPanel = nullptr;
    PanelInfo panelInfo1 = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FIXED };
    auto ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo1, softKeyboardPanel);
    EXPECT_TRUE(softKeyboardPanel != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    PanelInfo panelInfo2 = { .panelType = STATUS_BAR };
    std::shared_ptr<InputMethodPanel> statusBar = nullptr;
    ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo2, statusBar);
    EXPECT_TRUE(statusBar != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(softKeyboardPanel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(statusBar);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testCreatePanel004
* @tc.desc: It's allowed to create one STATUS_BAR panel and one SOFT_KEYBOARD panel.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testCreatePanel004, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testCreatePanel006 START. Allowed to create one SOFT_KEYBOARD panel and "
                "one STATUS_BAR panel.");
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    std::shared_ptr<InputMethodPanel> inputMethodPanel = nullptr;
    PanelInfo panelInfo1 = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FIXED };
    auto ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo1, inputMethodPanel);
    EXPECT_TRUE(inputMethodPanel != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(inputMethodPanel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    PanelInfo panelInfo2 = { .panelType = STATUS_BAR };
    ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo2, inputMethodPanel);
    EXPECT_TRUE(inputMethodPanel != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(inputMethodPanel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    panelInfo1.panelFlag = FLG_FLOATING;
    ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo1, inputMethodPanel);
    EXPECT_TRUE(inputMethodPanel != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(inputMethodPanel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testCreatePanel005
* @tc.desc: It's allowed to create one SOFT_KEYBOARD panel, but two is denied.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testCreatePanel005, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testCreatePanel005 START.");
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    std::shared_ptr<InputMethodPanel> softKeyboardPanel1 = nullptr;
    PanelInfo panelInfo = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FIXED };
    auto ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo, softKeyboardPanel1);
    EXPECT_TRUE(softKeyboardPanel1 != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(softKeyboardPanel1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    std::shared_ptr<InputMethodPanel> softKeyboardPanel2 = nullptr;
    ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo, softKeyboardPanel2);
    EXPECT_TRUE(softKeyboardPanel2 != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(softKeyboardPanel2);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testCreatePanel006
* @tc.desc: It's allowed to create one SOFT_KEYBOARD panel, but two is denied.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(InputMethodAbilityTest, testCreatePanel006, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testCreatePanel006 START.");
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    std::shared_ptr<InputMethodPanel> softKeyboardPanel1 = nullptr;
    PanelInfo panelInfo = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FIXED };
    auto ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo, softKeyboardPanel1);
    EXPECT_TRUE(softKeyboardPanel1 != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    std::shared_ptr<InputMethodPanel> softKeyboardPanel2 = nullptr;
    ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo, softKeyboardPanel2);
    EXPECT_TRUE(softKeyboardPanel2 == nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_OPERATE_PANEL);

    ret = inputMethodAbility_->DestroyPanel(softKeyboardPanel1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    std::shared_ptr<InputMethodPanel> softKeyboardPanel3 = nullptr;
    ret = inputMethodAbility_->CreatePanel(nullptr, panelInfo, softKeyboardPanel3);
    EXPECT_TRUE(softKeyboardPanel3 != nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = inputMethodAbility_->DestroyPanel(softKeyboardPanel2);
    EXPECT_EQ(ret, ErrorCode::ERROR_BAD_PARAMETERS);

    ret = inputMethodAbility_->DestroyPanel(softKeyboardPanel3);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testSetCallingWindow001
* @tc.desc: InputMethodAbility SetCallingWindow
* @tc.type: FUNC
* @tc.require:
* @tc.author: Hollokin
*/
HWTEST_F(InputMethodAbilityTest, testSetCallingWindow001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testSetCallingWindow001 START");
    std::unique_lock<std::mutex> lock(InputMethodAbilityTest::imeListenerCallbackLock_);
    InputMethodAbilityTest::showKeyboard_ = true;
    inputMethodAbility_->SetImeListener(std::make_shared<InputMethodEngineListenerImpl>());
    uint32_t windowId = 10;
    inputMethodAbility_->SetCallingWindow(windowId);
    InputMethodAbilityTest::imeListenerCv_.wait_for(lock, std::chrono::seconds(DEALY_TIME), [windowId] {
        return InputMethodAbilityTest::windowId_ == windowId;
    });
    EXPECT_EQ(InputMethodAbilityTest::windowId_, windowId);
}

/**
* @tc.name: testNotifyPanelStatusInfo_001
* @tc.desc: ShowKeyboard HideKeyboard SOFT_KEYBOARD FLG_FIXED
* @tc.type: FUNC
* @tc.require:
* @tc.author: chenyu
*/
HWTEST_F(InputMethodAbilityTest, testNotifyPanelStatusInfo_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyPanelStatusInfo_001 START");
    imc_->Attach(textListener_);
    PanelInfo info = { .panelType = STATUS_BAR };
    auto panel = std::make_shared<InputMethodPanel>();
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    auto ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    auto panel1 = std::make_shared<InputMethodPanel>();
    PanelInfo info1 = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FIXED };
    ret = inputMethodAbility_->CreatePanel(nullptr, info1, panel1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    TextListener::ResetParam();
    ret = inputMethodAbility_->ShowKeyboard();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::SHOW));
    EXPECT_TRUE(TextListener::WaitNotifyPanelStatusInfoCallback({ info1, true, Trigger::IMF }));

    TextListener::ResetParam();
    ret = inputMethodAbility_->HideKeyboard();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::HIDE));
    EXPECT_TRUE(TextListener::WaitNotifyPanelStatusInfoCallback({ info1, false, Trigger::IMF }));

    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = inputMethodAbility_->DestroyPanel(panel1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testNotifyPanelStatusInfo_002
* @tc.desc: ShowPanel HidePanel SOFT_KEYBOARD  FLG_FLOATING
* @tc.type: FUNC
* @tc.require:
* @tc.author: chenyu
*/
HWTEST_F(InputMethodAbilityTest, testNotifyPanelStatusInfo_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyPanelStatusInfo_002 START");
    imc_->Attach(textListener_);
    PanelInfo info = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FLOATING };
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    auto panel = std::make_shared<InputMethodPanel>();
    auto ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    // ShowPanel
    CheckPanelStatusInfo(panel, { info, true, Trigger::IME_APP });
    // HidePanel
    CheckPanelStatusInfo(panel, { info, false, Trigger::IME_APP });

    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testNotifyPanelStatusInfo_003
* @tc.desc: ShowPanel HidePanel STATUS_BAR
* @tc.type: FUNC
* @tc.require:
* @tc.author: chenyu
*/
HWTEST_F(InputMethodAbilityTest, testNotifyPanelStatusInfo_003, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyPanelStatusInfo_003 START");
    imc_->Attach(textListener_);
    PanelInfo info = { .panelType = STATUS_BAR };
    auto panel = std::make_shared<InputMethodPanel>();
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    auto ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    // ShowPanel
    CheckPanelStatusInfo(panel, { info, true, Trigger::IME_APP });
    // HidePanel
    CheckPanelStatusInfo(panel, { info, false, Trigger::IME_APP });

    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testNotifyPanelStatusInfo_004
* @tc.desc: ShowPanel HidePanel SOFT_KEYBOARD  FLG_CANDIDATE_COLUMN
* @tc.type: FUNC
* @tc.require:
* @tc.author: chenyu
*/
HWTEST_F(InputMethodAbilityTest, testNotifyPanelStatusInfo_004, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyPanelStatusInfo_004 START");
    imc_->Attach(textListener_);
    PanelInfo info = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_CANDIDATE_COLUMN };
    auto panel = std::make_shared<InputMethodPanel>();
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    auto ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    // ShowPanel
    CheckPanelStatusInfo(panel, { info, true, Trigger::IME_APP });
    // HidePanel
    CheckPanelStatusInfo(panel, { info, false, Trigger::IME_APP });

    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testNotifyPanelStatusInfo_005
* @tc.desc: HideKeyboardSelf
* @tc.type: FUNC
* @tc.require:
* @tc.author: chenyu
*/
HWTEST_F(InputMethodAbilityTest, testNotifyPanelStatusInfo_005, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyPanelStatusInfo_005 START");
    PanelInfo info = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FLOATING };
    imc_->Attach(textListener_);

    // has no panel
    TextListener::ResetParam();
    auto ret = inputMethodAbility_->HideKeyboardSelf();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::HIDE));
    EXPECT_FALSE(TextListener::WaitNotifyPanelStatusInfoCallback({ info, false, Trigger::IME_APP }));

    AccessScope scope(currentImeTokenId_, currentImeUid_);
    auto panel = std::make_shared<InputMethodPanel>();
    ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = inputMethodAbility_->ShowPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    // has panel
    TextListener::ResetParam();
    ret = inputMethodAbility_->HideKeyboardSelf();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(TextListener::WaitSendKeyboardStatusCallback(KeyboardStatus::HIDE));
    EXPECT_TRUE(TextListener::WaitNotifyPanelStatusInfoCallback({ info, false, Trigger::IME_APP }));

    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testNotifyKeyboardHeight_001
* @tc.desc: NotifyKeyboardHeight SOFT_KEYBOARD  FLG_FIXED
* @tc.type: FUNC
* @tc.require:
* @tc.author: mashaoyin
*/
HWTEST_F(InputMethodAbilityTest, testNotifyKeyboardHeight_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyKeyboardHeight_001 START");
    imc_->Attach(textListener_);
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    PanelInfo info = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FIXED };
    auto panel = std::make_shared<InputMethodPanel>();
    auto ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    panel->Resize(1, 1);
    TextListener::ResetParam();
    inputMethodAbility_->NotifyKeyboardHeight(panel);
    EXPECT_TRUE(TextListener::WaitNotifyKeyboardHeightCallback(1));

    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testNotifyKeyboardHeight_002
* @tc.desc: NotifyKeyboardHeight STATUS_BAR  FLG_FIXED
* @tc.type: FUNC
* @tc.require:
* @tc.author: mashaoyin
*/
HWTEST_F(InputMethodAbilityTest, testNotifyKeyboardHeight_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyKeyboardHeight_002 START");
    imc_->Attach(textListener_);
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    PanelInfo info = { .panelType = STATUS_BAR, .panelFlag = FLG_FIXED };
    auto panel = std::make_shared<InputMethodPanel>();
    auto ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    panel->Resize(1, 1);
    TextListener::ResetParam();
    inputMethodAbility_->NotifyKeyboardHeight(panel);
    EXPECT_TRUE(TextListener::WaitNotifyKeyboardHeightCallback(0));

    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testNotifyKeyboardHeight_003
* @tc.desc: NotifyKeyboardHeight SOFT_KEYBOARD  FLG_CANDIDATE_COLUMN
* @tc.type: FUNC
* @tc.require:
* @tc.author: mashaoyin
*/
HWTEST_F(InputMethodAbilityTest, testNotifyKeyboardHeight_003, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyKeyboardHeight_003 START");
    imc_->Attach(textListener_);
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    PanelInfo info = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_CANDIDATE_COLUMN };
    auto panel = std::make_shared<InputMethodPanel>();
    auto ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    panel->Resize(1, 1);
    inputMethodAbility_->NotifyKeyboardHeight(panel);
    TextListener::ResetParam();
    EXPECT_TRUE(TextListener::WaitNotifyKeyboardHeightCallback(0));
    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testNotifyKeyboardHeight_004
* @tc.desc: NotifyKeyboardHeight Attach with hard keyboard
* @tc.type: FUNC
* @tc.require:
* @tc.author: mashaoyin
*/
HWTEST_F(InputMethodAbilityTest, testNotifyKeyboardHeight_004, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyKeyboardHeight_004 START");
    TextListener::ResetParam();
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    PanelInfo info = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_CANDIDATE_COLUMN };
    auto panel = std::make_shared<InputMethodPanel>();
    auto ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    panel->Resize(1, 1);
    imc_->Attach(textListener_);
    EXPECT_TRUE(TextListener::WaitNotifyKeyboardHeightCallback(0));
    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testNotifyKeyboardHeight_005
* @tc.desc: NotifyKeyboardHeight Attach
* @tc.type: FUNC
* @tc.require:
* @tc.author: mashaoyin
*/
HWTEST_F(InputMethodAbilityTest, testNotifyKeyboardHeight_005, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testNotifyKeyboardHeight_005 START");
    TextListener::ResetParam();
    AccessScope scope(currentImeTokenId_, currentImeUid_);
    PanelInfo info = { .panelType = SOFT_KEYBOARD, .panelFlag = FLG_FIXED };
    auto panel = std::make_shared<InputMethodPanel>();
    auto ret = inputMethodAbility_->CreatePanel(nullptr, info, panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    panel->Resize(1, 1);
    imc_->Attach(textListener_);
    EXPECT_TRUE(TextListener::WaitNotifyKeyboardHeightCallback(1));
    ret = inputMethodAbility_->DestroyPanel(panel);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
* @tc.name: testOnSecurityChange
* @tc.desc: OnSecurityChange
* @tc.type: FUNC
* @tc.require:
* @tc.author: chenyu
*/
HWTEST_F(InputMethodAbilityTest, testOnSecurityChange, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testOnSecurityChange START");
    int32_t security = 32;
    inputMethodAbility_->SetImeListener(std::make_shared<InputMethodEngineListenerImpl>());
    auto ret = inputMethodAbility_->OnSecurityChange(security);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(InputMethodAbilityTest::security_, security);
}

/**
 * @tc.name: testSendPrivateCommand_001
 * @tc.desc: IMA SendPrivateCommand current is not default ime.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: mashaoyin
 */
HWTEST_F(InputMethodAbilityTest, testSendPrivateCommand_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testSendPrivateCommand_001 Test START");
    TextListener::ResetParam();
    InputMethodAbilityTest::GetIMCDetachIMA();
    TddUtil::RestoreSelfTokenID();
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    auto ret = inputMethodAbility_->SendPrivateCommand(privateCommand);
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_DEFAULT_IME);
}

/**
 * @tc.name: testSendPrivateCommand_002
 * @tc.desc: IMA SendPrivateCommand current data specification, default ime, not bound.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: mashaoyin
 */
HWTEST_F(InputMethodAbilityTest, testSendPrivateCommand_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testSendPrivateCommand_002 Test START");
    InputMethodAbilityTest::GetIMCDetachIMA();
    TokenScope tokenScope(InputMethodAbilityTest::defaultImeTokenId_);
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = std::string("stringValue");
    privateCommand.insert({ "value1", privateDataValue1 });
    auto ret = inputMethodAbility_->SendPrivateCommand(privateCommand);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testSendPrivateCommand_003
 * @tc.desc: IMA SendPrivateCommand with correct data specification and all data type.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: mashaoyin
 */
HWTEST_F(InputMethodAbilityTest, testSendPrivateCommand_003, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testSendPrivateCommand_003 Test START");
    TextListener::ResetParam();
    InputMethodAbilityTest::GetIMCAttachIMA();
    TokenScope tokenScope(InputMethodAbilityTest::defaultImeTokenId_);
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = std::string("stringValue");
    PrivateDataValue privateDataValue2 = true;
    PrivateDataValue privateDataValue3 = 100;
    privateCommand.emplace("value1", privateDataValue1);
    privateCommand.emplace("value2", privateDataValue2);
    privateCommand.emplace("value3", privateDataValue3);
    auto ret = inputMethodAbility_->SendPrivateCommand(privateCommand);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(TextListener::WaitSendPrivateCommandCallback(privateCommand));
    InputMethodAbilityTest::GetIMCDetachIMA();
}

/**
 * @tc.name: testGetCallingWindowInfo_001
 * @tc.desc: GetCallingWindowInfo with IMC not bound
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testGetCallingWindowInfo_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetCallingWindowInfo_001 Test START");
    InputMethodAbilityTest::GetIMCDetachIMA();
    CallingWindowInfo windowInfo;
    int32_t ret = InputMethodAbilityTest::inputMethodAbility_->GetCallingWindowInfo(windowInfo);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testGetCallingWindowInfo_002
 * @tc.desc: GetCallingWindowInfo with panel not created
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testGetCallingWindowInfo_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetCallingWindowInfo_002 Test START");
    AccessScope accessScope(InputMethodAbilityTest::currentImeTokenId_, InputMethodAbilityTest::currentImeUid_);
    // bind IMC
    InputMethodAbilityTest::GetIMCAttachIMA();
    // no panel is created
    InputMethodAbilityTest::inputMethodAbility_->panels_.Clear();
    CallingWindowInfo windowInfo;
    int32_t ret = InputMethodAbilityTest::inputMethodAbility_->GetCallingWindowInfo(windowInfo);
    EXPECT_EQ(ret, ErrorCode::ERROR_PANEL_NOT_FOUND);
    InputMethodAbilityTest::GetIMCDetachIMA();
}

/**
 * @tc.name: testGetCallingWindowInfo_003
 * @tc.desc: GetCallingWindowInfo with only status_bar created
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testGetCallingWindowInfo_003, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetCallingWindowInfo_003 Test START");
    AccessScope accessScope(InputMethodAbilityTest::currentImeTokenId_, InputMethodAbilityTest::currentImeUid_);
    // bind IMC
    InputMethodAbilityTest::GetIMCAttachIMA();
    // only STATUS_BAR panel in IMA
    auto inputMethodPanel = std::make_shared<InputMethodPanel>();
    PanelInfo info = { PanelType::STATUS_BAR };
    InputMethodAbilityTest::inputMethodAbility_->CreatePanel(nullptr, info, inputMethodPanel);
    CallingWindowInfo windowInfo;
    int32_t ret = InputMethodAbilityTest::inputMethodAbility_->GetCallingWindowInfo(windowInfo);
    EXPECT_EQ(ret, ErrorCode::ERROR_PANEL_NOT_FOUND);
    InputMethodAbilityTest::inputMethodAbility_->DestroyPanel(inputMethodPanel);
    InputMethodAbilityTest::GetIMCDetachIMA();
}

/**
 * @tc.name: testGetCallingWindowInfo_004
 * @tc.desc: GetCallingWindowInfo with invalid windowid
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testGetCallingWindowInfo_004, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetCallingWindowInfo_004 Test START");
    AccessScope accessScope(InputMethodAbilityTest::currentImeTokenId_, InputMethodAbilityTest::currentImeUid_);
    // bind imc
    InputMethodAbilityTest::GetIMCAttachIMA();
    // SOFT_KEYBOARD panel exists
    auto inputMethodPanel = std::make_shared<InputMethodPanel>();
    PanelInfo info = { PanelType::SOFT_KEYBOARD, PanelFlag::FLG_FIXED };
    InputMethodAbilityTest::inputMethodAbility_->CreatePanel(nullptr, info, inputMethodPanel);
    // invalid window id
    InputMethodAbilityTest::imc_->clientInfo_.config.windowId = INVALID_WINDOW_ID;
    CallingWindowInfo windowInfo;
    int32_t ret = InputMethodAbilityTest::inputMethodAbility_->GetCallingWindowInfo(windowInfo);
    EXPECT_EQ(ret, ErrorCode::ERROR_GET_TEXT_CONFIG);
    InputMethodAbilityTest::inputMethodAbility_->DestroyPanel(inputMethodPanel);
    InputMethodAbilityTest::GetIMCDetachIMA();
}

/**
 * @tc.name: testGetCallingWindowInfo_005
 * @tc.desc: GetCallingWindowInfo success
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testGetCallingWindowInfo_005, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbility testGetCallingWindowInfo_005 Test START");
    AccessScope accessScope(InputMethodAbilityTest::currentImeTokenId_, InputMethodAbilityTest::currentImeUid_);
    // SOFT_KEYBOARD window is created
    InputMethodAbilityTest::inputMethodAbility_->panels_.Clear();
    auto inputMethodPanel = std::make_shared<InputMethodPanel>();
    PanelInfo info = { PanelType::SOFT_KEYBOARD, PanelFlag::FLG_FIXED };
    InputMethodAbilityTest::inputMethodAbility_->CreatePanel(nullptr, info, inputMethodPanel);
    // bind IMC
    InputMethodAbilityTest::GetIMCAttachIMA();
    InputMethodAbilityTest::imc_->textConfig_.windowId = TddUtil::WindowManager::currentWindowId_;
    // get window info success
    CallingWindowInfo windowInfo;
    int32_t ret = InputMethodAbilityTest::inputMethodAbility_->GetCallingWindowInfo(windowInfo);
    EXPECT_TRUE(ret == ErrorCode::NO_ERROR || ret == ErrorCode::ERROR_WINDOW_MANAGER);
    InputMethodAbilityTest::GetIMCDetachIMA();
    InputMethodAbilityTest::inputMethodAbility_->DestroyPanel(inputMethodPanel);
}

/**
 * @tc.name: testSetPreviewText_001
 * @tc.desc: IMA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testSetPreviewText_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testSetPreviewText_001 Test START");
    TextListener::ResetParam();
    std::string text = "test";
    Range range = { 1, 2 };
    InputMethodAbilityTest::GetIMCAttachIMA();
    InputMethodAbilityTest::imc_->textConfig_.inputAttribute.isTextPreviewSupported = true;
    auto ret = InputMethodAbilityTest::inputMethodAbility_->SetPreviewText(text, range);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(TextListener::previewText_, text);
    EXPECT_EQ(TextListener::previewRange_, range);
    InputMethodAbilityTest::GetIMCDetachIMA();
}

/**
 * @tc.name: testSetPreviewText_002
 * @tc.desc: IMA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testSetPreviewText_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testSetPreviewText_002 Test START");
    TextListener::ResetParam();
    std::string text = "test";
    Range range = { 1, 2 };
    InputMethodAbilityTest::inputMethodAbility_->ClearDataChannel(
        InputMethodAbilityTest::inputMethodAbility_->dataChannelObject_);
    auto ret = InputMethodAbilityTest::inputMethodAbility_->SetPreviewText(text, range);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
    EXPECT_NE(TextListener::previewText_, text);
    EXPECT_FALSE(TextListener::previewRange_ == range);
}

/**
 * @tc.name: testSetPreviewText_003
 * @tc.desc: IMA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testSetPreviewText_003, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testSetPreviewText_003 Test START");
    TextListener::ResetParam();
    std::string text = "test";
    Range range = { 1, 2 };
    InputMethodAbilityTest::GetIMCAttachIMA();
    InputMethodAbilityTest::imc_->textConfig_.inputAttribute.isTextPreviewSupported = false;
    auto ret = InputMethodAbilityTest::inputMethodAbility_->SetPreviewText(text, range);
    EXPECT_EQ(ret, ErrorCode::ERROR_TEXT_PREVIEW_NOT_SUPPORTED);
    EXPECT_NE(TextListener::previewText_, text);
    EXPECT_FALSE(TextListener::previewRange_ == range);
    InputMethodAbilityTest::GetIMCDetachIMA();
}

/**
 * @tc.name: testFinishTextPreview_001
 * @tc.desc: IMA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testFinishTextPreview_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testFinishTextPreview_001 Test START");
    TextListener::ResetParam();
    InputMethodAbilityTest::GetIMCAttachIMA();
    InputMethodAbilityTest::imc_->textConfig_.inputAttribute.isTextPreviewSupported = true;
    auto ret = InputMethodAbilityTest::inputMethodAbility_->FinishTextPreview();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(TextListener::isFinishTextPreviewCalled_);
    InputMethodAbilityTest::GetIMCDetachIMA();
}

/**
 * @tc.name: testFinishTextPreview_002
 * @tc.desc: IMA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testFinishTextPreview_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testFinishTextPreview_002 Test START");
    TextListener::ResetParam();
    InputMethodAbilityTest::inputMethodAbility_->ClearDataChannel(
        InputMethodAbilityTest::inputMethodAbility_->dataChannelObject_);
    auto ret = InputMethodAbilityTest::inputMethodAbility_->FinishTextPreview();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
    EXPECT_FALSE(TextListener::isFinishTextPreviewCalled_);
}

/**
 * @tc.name: testFinishTextPreview_003
 * @tc.desc: IMA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaolinglan
 */
HWTEST_F(InputMethodAbilityTest, testFinishTextPreview_003, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodAbilityTest testFinishTextPreview_003 Test START");
    TextListener::ResetParam();
    InputMethodAbilityTest::GetIMCAttachIMA();
    InputMethodAbilityTest::imc_->textConfig_.inputAttribute.isTextPreviewSupported = false;
    auto ret = InputMethodAbilityTest::inputMethodAbility_->FinishTextPreview();
    EXPECT_EQ(ret, ErrorCode::ERROR_TEXT_PREVIEW_NOT_SUPPORTED);
    EXPECT_FALSE(TextListener::isFinishTextPreviewCalled_);
    InputMethodAbilityTest::GetIMCDetachIMA();
}
} // namespace MiscServices
} // namespace OHOS
