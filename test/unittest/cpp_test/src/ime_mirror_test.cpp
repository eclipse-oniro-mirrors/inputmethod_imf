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
#include "refbase.h"
#include "wm_common.h"

struct AniEnv;
typedef struct AniEnv ani_env;
class AniObject;
typedef AniObject *ani_object;
namespace OHOS {
namespace Rosen {
class RSTransaction;
class Window : virtual public RefBase {};
class WindowOption : virtual public RefBase {};

class IWindowChangeListener : virtual public RefBase {
public:
    virtual void OnSizeChange(Rect rect, WindowSizeChangeReason reason,
        const std::shared_ptr<RSTransaction> &rsTransaction = nullptr)
    {
    }
};

class IKeyboardPanelInfoChangeListener : virtual public RefBase {
public:
    virtual void OnKeyboardPanelInfoChanged(const KeyboardPanelInfo &keyboardPanelInfo) {}
};

class IWindowVisibilityChangedListener : virtual public RefBase {
public:
    virtual void OnWindowVisibilityChangedCallback(const bool isVisible) {}
};
} // namespace Rosen
} // namespace OHOS

// Prevent window.h from redefining these types when included via input_method_panel.h
#define OHOS_ROSEN_WINDOW_H

#define private public
#include "input_method_ability.h"
#include "input_method_controller.h"
#include "task_manager.h"
#undef private

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "global.h"
#include "input_attribute.h"
#include "input_client_info.h"
#include "input_method_agent_proxy.h"
#include "input_method_agent_service_impl.h"
#include "input_method_core_service_impl.h"
#include "ime_mirror_manager.h"
#include "mock_input_method_system_ability_proxy.h"
#include "mock_iremote_object.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
constexpr int32_t TEST_SA_ID = 1600004; // INPUT_METHOD_SYSTEM_ABILITY_ID
const std::string IME_MIRROR_NAME_LOCAL = "proxyIme_IME_MIRROR";

// ============================================================================
// Group 1: ImeMirrorManager Tests
// ============================================================================

class ImeMirrorManagerTest : public testing::Test {
public:
    static void SetUpTestSuite()
    {
        TaskManager::GetInstance().SetInited(true);
    }

    void SetUp() override
    {
        ima_ = &InputMethodAbility::GetInstance();
        ima_->imeMirrorMgr_.SetImeMirrorEnable(false);
        ima_->imeMirrorMgr_.UnSubscribeSaStart(TEST_SA_ID);
    }

    void TearDown() override {}

protected:
    InputMethodAbility *ima_ = nullptr;
};

/**
 * @tc.name: SetImeMirrorEnable_True_then_IsImeMirrorEnable_ReturnsTrue
 * @tc.desc: Verify SetImeMirrorEnable(true) makes IsImeMirrorEnable() return true
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorManagerTest, SetImeMirrorEnable_True_then_IsImeMirrorEnable_ReturnsTrue, TestSize.Level1)
{
    ima_->imeMirrorMgr_.SetImeMirrorEnable(true);
    EXPECT_TRUE(ima_->imeMirrorMgr_.IsImeMirrorEnable());
}

/**
 * @tc.name: SetImeMirrorEnable_False_then_IsImeMirrorEnable_ReturnsFalse
 * @tc.desc: Verify SetImeMirrorEnable(false) makes IsImeMirrorEnable() return false
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorManagerTest, SetImeMirrorEnable_False_then_IsImeMirrorEnable_ReturnsFalse, TestSize.Level1)
{
    ima_->imeMirrorMgr_.SetImeMirrorEnable(true);
    EXPECT_TRUE(ima_->imeMirrorMgr_.IsImeMirrorEnable());

    ima_->imeMirrorMgr_.SetImeMirrorEnable(false);
    EXPECT_FALSE(ima_->imeMirrorMgr_.IsImeMirrorEnable());
}

/**
 * @tc.name: SubscribeSaStart_NullHandler_ReturnsFalse
 * @tc.desc: Verify SubscribeSaStart returns false when handler is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorManagerTest, SubscribeSaStart_NullHandler_ReturnsFalse, TestSize.Level1)
{
    auto result = ima_->imeMirrorMgr_.SubscribeSaStart(nullptr, TEST_SA_ID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SubscribeSaStart_ValidHandler_ReturnsTrue
 * @tc.desc: Verify SubscribeSaStart returns true when SystemAbilityManager is available
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorManagerTest, SubscribeSaStart_ValidHandler_ReturnsTrue, TestSize.Level1)
{
    ima_->imeMirrorMgr_.UnSubscribeSaStart(TEST_SA_ID);
    bool called = false;
    auto handler = [&called]() { called = true; };
    auto result = ima_->imeMirrorMgr_.SubscribeSaStart(handler, TEST_SA_ID);
    EXPECT_TRUE(result);
}

// ============================================================================
// Group 2: InputMethodAbility Mirror Tests
// ============================================================================

class ImeMirrorAbilityTest : public testing::Test {
public:
    static sptr<NiceMock<MockInputMethodSystemAbilityProxy>> mockProxy_;
    static InputMethodAbility *ima_;

    static void SetUpTestSuite()
    {
        ima_ = &InputMethodAbility::GetInstance();
        mockProxy_ = new NiceMock<MockInputMethodSystemAbilityProxy>();

        // Inject mock proxy into IMA
        ima_->abilityManager_ = mockProxy_;

        // Set default ON_CALL for permissive behavior
        ON_CALL(*mockProxy_, BindImeMirror(_, _)).WillByDefault(Return(ErrorCode::NO_ERROR));
        ON_CALL(*mockProxy_, UnbindImeMirror()).WillByDefault(Return(ErrorCode::NO_ERROR));

        TaskManager::GetInstance().SetInited(true);
    }

    static void TearDownTestSuite()
    {
        ima_->abilityManager_ = nullptr;
        ima_->agentStub_ = nullptr;
        ima_->coreStub_ = nullptr;
        mockProxy_ = nullptr;
    }

    void SetUp() override
    {
        ima_->isBound_.store(false);
        ima_->imeMirrorMgr_.SetImeMirrorEnable(false);
        ima_->abilityManager_ = mockProxy_;

        if (ima_->agentStub_ == nullptr) {
            ima_->agentStub_ = new InputMethodAgentServiceImpl();
        }
        if (ima_->coreStub_ == nullptr) {
            ima_->coreStub_ = new InputMethodCoreServiceImpl();
        }

        ON_CALL(*mockProxy_, BindImeMirror(_, _)).WillByDefault(Return(ErrorCode::NO_ERROR));
        ON_CALL(*mockProxy_, UnbindImeMirror()).WillByDefault(Return(ErrorCode::NO_ERROR));

        TaskManager::GetInstance().SetInited(true);
    }

    void TearDown() override {}
};

sptr<NiceMock<MockInputMethodSystemAbilityProxy>> ImeMirrorAbilityTest::mockProxy_ = nullptr;
InputMethodAbility *ImeMirrorAbilityTest::ima_ = nullptr;

/**
 * @tc.name: BindImeMirror_AlreadyBound_ReturnsNoError
 * @tc.desc: Verify BindImeMirror returns NO_ERROR immediately when already bound
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorAbilityTest, BindImeMirror_AlreadyBound_ReturnsNoError, TestSize.Level1)
{
    ima_->isBound_.store(true);

    auto ret = ima_->BindImeMirror();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: BindImeMirror_NullProxy_ReturnsErrorServiceStartFailed
 * @tc.desc: Verify BindImeMirror returns ERROR_SERVICE_START_FAILED when proxy is null
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorAbilityTest, BindImeMirror_NullProxy_ReturnsErrorServiceStartFailed, TestSize.Level1)
{
    ima_->abilityManager_ = nullptr;

    auto ret = ima_->BindImeMirror();
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_AI_APP_IME);
}

/**
 * @tc.name: BindImeMirror_NullAgentStub_ReturnsErrorNullPointer
 * @tc.desc: Verify BindImeMirror returns ERROR_NULL_POINTER when agentStub_ is null
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorAbilityTest, BindImeMirror_NullAgentStub_ReturnsErrorNullPointer, TestSize.Level1)
{
    ima_->agentStub_ = nullptr;

    auto ret = ima_->BindImeMirror();
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);
}

/**
 * @tc.name: BindImeMirror_Success_SetsBoundAndEnable
 * @tc.desc: Verify successful BindImeMirror sets isBound_ true and ImeMirrorEnable true
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorAbilityTest, BindImeMirror_Success_SetsBoundAndEnable, TestSize.Level1)
{
    auto ret = ima_->BindImeMirror();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(ima_->isBound_.load());
    EXPECT_TRUE(ima_->imeMirrorMgr_.IsImeMirrorEnable());
}

/**
 * @tc.name: BindImeMirror_ProxyReturnsError_PropagatesError
 * @tc.desc: Verify BindImeMirror propagates error when proxy->BindImeMirror fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorAbilityTest, BindImeMirror_ProxyReturnsError_PropagatesError, TestSize.Level1)
{
    ima_->isBound_.store(false);
    ON_CALL(*mockProxy_, BindImeMirror(_, _)).WillByDefault(Return(ErrorCode::ERROR_NOT_AI_APP_IME));

    auto ret = ima_->BindImeMirror();
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_AI_APP_IME);
    EXPECT_FALSE(ima_->isBound_.load());
    EXPECT_FALSE(ima_->imeMirrorMgr_.IsImeMirrorEnable());
}

/**
 * @tc.name: UnbindImeMirror_ClearsBoundAndEnable
 * @tc.desc: Verify UnbindImeMirror clears isBound_ and ImeMirrorEnable
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorAbilityTest, UnbindImeMirror_ClearsBoundAndEnable, TestSize.Level1)
{
    ima_->isBound_.store(false);
    auto ret = ima_->BindImeMirror();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(ima_->isBound_.load());
    EXPECT_TRUE(ima_->imeMirrorMgr_.IsImeMirrorEnable());

    ret = ima_->UnbindImeMirror();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_FALSE(ima_->isBound_.load());
    EXPECT_FALSE(ima_->imeMirrorMgr_.IsImeMirrorEnable());
}

/**
 * @tc.name: GetInputDataChannelProxyWrap_MirrorEnabled_ReturnsNull
 * @tc.desc: Verify GetInputDataChannelProxyWrap returns nullptr when ImeMirror is enabled
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorAbilityTest, GetInputDataChannelProxyWrap_MirrorEnabled_ReturnsNull, TestSize.Level1)
{
    ima_->imeMirrorMgr_.SetImeMirrorEnable(true);

    auto result = ima_->GetInputDataChannelProxyWrap();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GetInputDataChannelProxyWrap_MirrorDisabled_ReturnsChannel
 * @tc.desc: Verify GetInputDataChannelProxyWrap returns the stored channel when mirror is disabled
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorAbilityTest, GetInputDataChannelProxyWrap_MirrorDisabled_ReturnsChannel, TestSize.Level1)
{
    ima_->imeMirrorMgr_.SetImeMirrorEnable(false);
    auto result = ima_->GetInputDataChannelProxyWrap();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: BindUnbindImeMirror_RepeatBothSucceed
 * @tc.desc: Verify bind twice then unbind twice all succeed
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorAbilityTest, BindUnbindImeMirror_RepeatBothSucceed, TestSize.Level1)
{
    ima_->isBound_.store(false);
    auto ret = ima_->BindImeMirror();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(ima_->isBound_.load());

    ret = ima_->BindImeMirror();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    ret = ima_->UnbindImeMirror();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_FALSE(ima_->isBound_.load());

    ret = ima_->UnbindImeMirror();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

// ============================================================================
// Group 3: InputMethodController Mirror Tests
// ============================================================================

class ImeMirrorControllerTest : public testing::Test {
public:
    static sptr<NiceMock<MockInputMethodSystemAbilityProxy>> mockProxy_;
    static sptr<InputMethodController> imc_;

    static void SetUpTestSuite()
    {
        imc_ = InputMethodController::GetInstance();
        mockProxy_ = new NiceMock<MockInputMethodSystemAbilityProxy>();

        MockInputMethodSystemAbilityProxy::SetImsaProxyForTest(imc_, mockProxy_);

        ON_CALL(*mockProxy_, BindImeMirror(_, _)).WillByDefault(Return(ErrorCode::NO_ERROR));
        ON_CALL(*mockProxy_, UnbindImeMirror()).WillByDefault(Return(ErrorCode::NO_ERROR));

        TaskManager::GetInstance().SetInited(true);
    }

    static void TearDownTestSuite()
    {
        MockInputMethodSystemAbilityProxy::SetImsaProxyForTest(imc_, nullptr);
        mockProxy_ = nullptr;
    }

    void SetUp() override
    {
        // Reset IMC state
        imc_->agentInfoList_.clear();
        imc_->isBound_.store(false);
        imc_->isEditable_.store(false);
        imc_->textConfig_ = TextConfig();
    }

    void TearDown() override {}

protected:
    void AddMirrorAgent(sptr<IRemoteObject> agentObj)
    {
        InputMethodController::AgentInfo info;
        info.agentObject = agentObj;
        info.agent = std::make_shared<InputMethodAgentProxy>(agentObj);
        info.imeType = ImeType::IME_MIRROR;
        imc_->agentInfoList_.push_back(info);
    }

    void AddNormalAgent(sptr<IRemoteObject> agentObj)
    {
        InputMethodController::AgentInfo info;
        info.agentObject = agentObj;
        info.agent = std::make_shared<InputMethodAgentProxy>(agentObj);
        info.imeType = ImeType::NONE;
        imc_->agentInfoList_.push_back(info);
    }
};

sptr<NiceMock<MockInputMethodSystemAbilityProxy>> ImeMirrorControllerTest::mockProxy_ = nullptr;
sptr<InputMethodController> ImeMirrorControllerTest::imc_ = nullptr;

/**
 * @tc.name: SetAgent_WithMirrorName_SetsImeTypeToMirror
 * @tc.desc: Verify SetAgent with IME_MIRROR_NAME_LOCAL sets imeType to IME_MIRROR
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorControllerTest, SetAgent_WithMirrorName_SetsImeTypeToMirror, TestSize.Level1)
{
    auto agentObj = new NiceMock<MockIRemoteObject>();
    imc_->SetAgent(agentObj, IME_MIRROR_NAME_LOCAL);

    ASSERT_EQ(imc_->agentInfoList_.size(), 1u);
    EXPECT_EQ(imc_->agentInfoList_[0].imeType, ImeType::IME_MIRROR);
}

/**
 * @tc.name: GetAgent_SkipsMirrorAgents
 * @tc.desc: Verify GetAgent skips mirror agents and returns a normal agent
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorControllerTest, GetAgent_SkipsMirrorAgents, TestSize.Level1)
{
    auto mirrorObj = new NiceMock<MockIRemoteObject>();
    AddMirrorAgent(mirrorObj);

    auto normalObj = new NiceMock<MockIRemoteObject>();
    AddNormalAgent(normalObj);

    auto agent = imc_->GetAgent();
    ASSERT_NE(agent, nullptr);
    EXPECT_EQ(imc_->agentInfoList_.size(), 2u);
}

/**
 * @tc.name: OnInputReady_MirrorName_DoesNotSetBindImeInfo
 * @tc.desc: Verify OnInputReady with IME_MIRROR_NAME_LOCAL does not set bind/editable state
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorControllerTest, OnInputReady_MirrorName_DoesNotSetBindImeInfo, TestSize.Level1)
{
    auto agentObj = new NiceMock<MockIRemoteObject>();
    BindImeInfo imeInfo;
    imeInfo.bundleName = IME_MIRROR_NAME_LOCAL;
    imeInfo.pid = 100;

    imc_->OnInputReady(agentObj, imeInfo);

    EXPECT_FALSE(imc_->isBound_.load());
    EXPECT_FALSE(imc_->isEditable_.load());
    ASSERT_EQ(imc_->agentInfoList_.size(), 1u);
    EXPECT_EQ(imc_->agentInfoList_[0].imeType, ImeType::IME_MIRROR);
}

/**
 * @tc.name: OnImeMirrorStop_RemovesMirrorAgent
 * @tc.desc: Verify OnImeMirrorStop removes the matching mirror agent from agentInfoList
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorControllerTest, OnImeMirrorStop_RemovesMirrorAgent, TestSize.Level1)
{
    auto mirrorObj = new NiceMock<MockIRemoteObject>();
    AddMirrorAgent(mirrorObj);
    ASSERT_EQ(imc_->agentInfoList_.size(), 1u);

    imc_->OnImeMirrorStop(mirrorObj);
    EXPECT_TRUE(imc_->agentInfoList_.empty());
}

/**
 * @tc.name: OnImeMirrorStop_WrongObject_DoesNothing
 * @tc.desc: Verify OnImeMirrorStop with non-matching object does not remove any agent
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorControllerTest, OnImeMirrorStop_WrongObject_DoesNothing, TestSize.Level1)
{
    auto mirrorObj = new NiceMock<MockIRemoteObject>();
    AddMirrorAgent(mirrorObj);

    auto wrongObj = new NiceMock<MockIRemoteObject>();
    imc_->OnImeMirrorStop(wrongObj);

    EXPECT_EQ(imc_->agentInfoList_.size(), 1u);
}

/**
 * @tc.name: SendRequestToAllAgents_MirrorSkippedOnSecurity
 * @tc.desc: Verify mirror agent is skipped when security flag is set
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorControllerTest, SendRequestToAllAgents_MirrorSkippedOnSecurity, TestSize.Level1)
{
    auto mirrorObj = new NiceMock<MockIRemoteObject>();
    AddMirrorAgent(mirrorObj);

    auto normalObj = new NiceMock<MockIRemoteObject>();
    AddNormalAgent(normalObj);

    imc_->textConfig_.inputAttribute.inputPattern = InputAttribute::PATTERN_PASSWORD;
    ASSERT_TRUE(imc_->textConfig_.inputAttribute.IsSecurityImeFlag());

    int32_t callCount = 0;
    auto ret = imc_->SendRequestToAllAgents([&callCount](std::shared_ptr<IInputMethodAgent> agent) {
        callCount++;
        return ErrorCode::NO_ERROR;
    });

    EXPECT_EQ(callCount, 1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: SendRequestToImeMirrorAgent_SecurityFlag_ReturnsPermissionDenied
 * @tc.desc: Verify SendRequestToImeMirrorAgent returns permission denied on security flag
 * @tc.type: FUNC
 */
HWTEST_F(ImeMirrorControllerTest, SendRequestToImeMirrorAgent_SecurityFlag_ReturnsPermissionDenied, TestSize.Level1)
{
    auto mirrorObj = new NiceMock<MockIRemoteObject>();
    AddMirrorAgent(mirrorObj);

    imc_->textConfig_.inputAttribute.inputPattern = InputAttribute::PATTERN_PASSWORD;
    ASSERT_TRUE(imc_->textConfig_.inputAttribute.IsSecurityImeFlag());

    bool taskCalled = false;
    auto ret = imc_->SendRequestToImeMirrorAgent([&taskCalled](std::shared_ptr<IInputMethodAgent> agent) {
        taskCalled = true;
        return ErrorCode::NO_ERROR;
    });

    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    EXPECT_FALSE(taskCalled);
}
} // namespace MiscServices
} // namespace OHOS
