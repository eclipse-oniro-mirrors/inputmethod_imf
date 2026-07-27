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

#include "inputmethod_extension_context.h"

#include <gtest/gtest.h>

#include "ability_manager_client.h"
#include "connection_manager.h"
#include "global.h"
#include "ability_info.h"

#undef LOG_TAG
#define LOG_TAG "ImeExtCtxTest"

using namespace testing::ext;
namespace OHOS {
namespace AbilityRuntime {

class InputMethodExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void InputMethodExtensionContextTest::SetUpTestCase(void)
{
    IMSA_HILOGI("InputMethodExtensionContextTest::SetUpTestCase");
}

void InputMethodExtensionContextTest::TearDownTestCase(void)
{
    IMSA_HILOGI("InputMethodExtensionContextTest::TearDownTestCase");
}

void InputMethodExtensionContextTest::SetUp(void)
{
    IMSA_HILOGI("InputMethodExtensionContextTest::SetUp");
}

void InputMethodExtensionContextTest::TearDown(void)
{
    IMSA_HILOGI("InputMethodExtensionContextTest::TearDown");
}

/**
 * @tc.name: InputMethodExtensionContextTest_Constructor001
 * @tc.desc: Verify construction and destruction of InputMethodExtensionContext
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_Constructor001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_Constructor001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    ASSERT_NE(context, nullptr);
}

/**
 * @tc.name: InputMethodExtensionContextTest_IsContext001
 * @tc.desc: Verify IsContext returns true for CONTEXT_TYPE_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_IsContext001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_IsContext001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    EXPECT_TRUE(context->IsContext(InputMethodExtensionContext::CONTEXT_TYPE_ID));
}

/**
 * @tc.name: InputMethodExtensionContextTest_IsContext002
 * @tc.desc: Verify IsContext returns false for a different type id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_IsContext002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_IsContext002 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    EXPECT_FALSE(context->IsContext(99999));
}

/**
 * @tc.name: InputMethodExtensionContextTest_GetAbilityInfoType001
 * @tc.desc: Verify GetAbilityInfoType returns UNKNOWN when info is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_GetAbilityInfoType001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_GetAbilityInfoType001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    auto type = context->GetAbilityInfoType();
    EXPECT_EQ(type, AppExecFwk::AbilityType::UNKNOWN);
}

/**
 * @tc.name: InputMethodExtensionContextTest_StartAbility001
 * @tc.desc: Verify StartAbility returns result from AbilityManagerClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_StartAbility001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_StartAbility001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    AAFwk::Want want;
    ErrCode ret = context->StartAbility(want);
    // In test environment, result depends on whether AbilityManagerService is available
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: InputMethodExtensionContextTest_StartAbilityWithOptions001
 * @tc.desc: Verify StartAbility with StartOptions returns result from AbilityManagerClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_StartAbilityWithOptions001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_StartAbilityWithOptions001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    AAFwk::Want want;
    AAFwk::StartOptions startOptions;
    ErrCode ret = context->StartAbility(want, startOptions);
    // In test environment, result depends on whether AbilityManagerService is available
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: InputMethodExtensionContextTest_StartAbilityWithAccount001
 * @tc.desc: Verify StartAbilityWithAccount returns result from AbilityManagerClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_StartAbilityWithAccount001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_StartAbilityWithAccount001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    AAFwk::Want want;
    ErrCode ret = context->StartAbilityWithAccount(want, 100);
    // In test environment, result depends on whether AbilityManagerService is available
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: InputMethodExtensionContextTest_StartAbilityWithAccountWithOptions001
 * @tc.desc: Verify StartAbilityWithAccount with StartOptions returns result from AbilityManagerClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest,
    InputMethodExtensionContextTest_StartAbilityWithAccountWithOptions001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_StartAbilityWithAccountWithOptions001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    AAFwk::Want want;
    AAFwk::StartOptions startOptions;
    ErrCode ret = context->StartAbilityWithAccount(want, 100, startOptions);
    // In test environment, result depends on whether AbilityManagerService is available
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: InputMethodExtensionContextTest_ConnectAbility001
 * @tc.desc: Verify ConnectAbility returns bool based on ConnectionManager result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_ConnectAbility001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_ConnectAbility001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    AAFwk::Want want;
    sptr<AbilityConnectCallback> callback = nullptr;
    bool ret = context->ConnectAbility(want, callback);
    // Without a valid token, ConnectionManager returns error
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: InputMethodExtensionContextTest_ConnectAbilityWithAccount001
 * @tc.desc: Verify ConnectAbilityWithAccount returns bool based on ConnectionManager result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_ConnectAbilityWithAccount001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_ConnectAbilityWithAccount001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    AAFwk::Want want;
    sptr<AbilityConnectCallback> callback = nullptr;
    bool ret = context->ConnectAbilityWithAccount(want, 100, callback);
    // Without a valid token, ConnectionManager returns error
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: InputMethodExtensionContextTest_DisconnectAbility001
 * @tc.desc: Verify DisconnectAbility returns result from ConnectionManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_DisconnectAbility001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_DisconnectAbility001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    AAFwk::Want want;
    sptr<AbilityConnectCallback> callback = nullptr;
    ErrCode ret = context->DisconnectAbility(want, callback);
    // Without a valid connection, returns error
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: InputMethodExtensionContextTest_TerminateAbility001
 * @tc.desc: Verify TerminateAbility returns result from AbilityManagerClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_TerminateAbility001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_TerminateAbility001 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    ErrCode ret = context->TerminateAbility();
    // In test environment, result depends on whether AbilityManagerService is available
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: InputMethodExtensionContextTest_GetAbilityInfoType002
 * @tc.desc: Verify GetAbilityInfoType returns type when info is set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionContextTest, InputMethodExtensionContextTest_GetAbilityInfoType002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionContextTest_GetAbilityInfoType002 start.");
    auto context = std::make_shared<InputMethodExtensionContext>();
    auto info = std::make_shared<AppExecFwk::AbilityInfo>();
    info->type = AppExecFwk::AbilityType::EXTENSION;
    context->SetAbilityInfo(info);
    auto type = context->GetAbilityInfoType();
    EXPECT_EQ(type, AppExecFwk::AbilityType::EXTENSION);
}

} //namespace AbilityRuntime
} //namespace OHOS