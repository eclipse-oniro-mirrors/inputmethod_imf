/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <unistd.h>

#include <string>
#include <vector>

#include "global.h"
#include "input_method_controller.h"
#include "input_method_property.h"
#include "scope_utils.h"
#include "tdd_util.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {

class ImeMultiUserTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

    static sptr<InputMethodController> imc_;
    static std::string bundleName;
    static std::vector<std::string> extName;
};

sptr<InputMethodController> ImeMultiUserTest::imc_;
std::string ImeMultiUserTest::bundleName = "com.example.testIme";
std::vector<std::string> ImeMultiUserTest::extName { "InputMethodExtAbility", "InputMethodExtAbility2" };
static constexpr uint32_t WAIT_IME_READY_TIME = 1;

void ImeMultiUserTest::SetUpTestCase(void)
{
    IMSA_HILOGI("ImeMultiUserTest::SetUpTestCase");
    TddUtil::StorageSelfTokenID();
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    TddUtil::EnabledAllIme();
    imc_ = InputMethodController::GetInstance();
}

void ImeMultiUserTest::TearDownTestCase(void)
{
    IMSA_HILOGI("ImeMultiUserTest::TearDownTestCase");
    InputMethodController::GetInstance()->Close();
    TddUtil::RestoreSelfTokenID();
}

void ImeMultiUserTest::SetUp()
{
    IMSA_HILOGI("ImeMultiUserTest::SetUp");
}

void ImeMultiUserTest::TearDown()
{
    IMSA_HILOGI("ImeMultiUserTest::TearDown");
}

/**
 * @tc.name: testMultiUserListInputMethod_001
 * @tc.desc: Test ListInputMethod for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListInputMethod_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListInputMethod 001 Test START");

    // Restore to native token ID and set UID to 0
    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    std::vector<Property> props;
    int32_t ret = imc_->ListInputMethod(props, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(props.size() >= 1);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserListInputMethod_002
 * @tc.desc: Test ListInputMethod for U100 user with SYSTEM_APP trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListInputMethod_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListInputMethod 002 Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    std::vector<Property> props;
    int32_t ret = imc_->ListInputMethod(props, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(props.size() >= 1);
}

/**
 * @tc.name: testMultiUserListInputMethodWithEnable_001
 * @tc.desc: Test ListInputMethod with enable=true for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListInputMethodWithEnable_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListInputMethodWithEnable 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    std::vector<Property> props;
    int32_t ret = imc_->ListInputMethod(true, props, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(props.size() >= 1);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserListInputMethodWithEnable_002
 * @tc.desc: Test ListInputMethod with enable=true for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListInputMethodWithEnable_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListInputMethodWithEnable 002 Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    std::vector<Property> props;
    int32_t ret = imc_->ListInputMethod(true, props, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(props.size() >= 1);
}

/**
 * @tc.name: testMultiUserGetInputMethodConfig_001
 * @tc.desc: Test GetInputMethodConfig for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetInputMethodConfig_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetInputMethodConfig 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    AppExecFwk::ElementName inputMethodConfig;
    auto ret = imc_->GetInputMethodConfig(inputMethodConfig, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_GE(inputMethodConfig.GetBundleName().length(), 0);
    EXPECT_GE(inputMethodConfig.GetAbilityName().length(), 0);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserGetInputMethodConfig_002
 * @tc.desc: Test GetInputMethodConfig for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetInputMethodConfig_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetInputMethodConfig 002 Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    AppExecFwk::ElementName inputMethodConfig;
    auto ret = imc_->GetInputMethodConfig(inputMethodConfig, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_GE(inputMethodConfig.GetBundleName().length(), 0);
    EXPECT_GE(inputMethodConfig.GetAbilityName().length(), 0);
}

/**
 * @tc.name: testMultiUserListInputMethodSubtype_001
 * @tc.desc: Test ListInputMethodSubtype for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListInputMethodSubtype_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListInputMethodSubtype 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    Property property;
    property.name = bundleName;
    property.id = extName[0];

    std::vector<SubProperty> subProps;
    int32_t ret = imc_->ListInputMethodSubtype(property, subProps, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserListInputMethodSubtype_002
 * @tc.desc: Test ListInputMethodSubtype for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListInputMethodSubtype_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListInputMethodSubtype 002 Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    Property property;
    property.name = bundleName;
    property.id = extName[0];

    std::vector<SubProperty> subProps;
    int32_t ret = imc_->ListInputMethodSubtype(property, subProps, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testMultiUserListCurrentInputMethodSubtype_001
 * @tc.desc: Test ListCurrentInputMethodSubtype for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListCurrentInputMethodSubtype_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListCurrentInputMethodSubtype 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    std::vector<SubProperty> subProps;
    int32_t ret = imc_->ListCurrentInputMethodSubtype(subProps, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserListCurrentInputMethodSubtype_002
 * @tc.desc: Test ListCurrentInputMethodSubtype for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListCurrentInputMethodSubtype_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListCurrentInputMethodSubtype 002 Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    std::vector<SubProperty> subProps;
    int32_t ret = imc_->ListCurrentInputMethodSubtype(subProps, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testMultiUserGetCurrentInputMethod_001
 * @tc.desc: Test GetCurrentInputMethod for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetCurrentInputMethod_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetCurrentInputMethod 001 Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    std::shared_ptr<Property> property = imc_->GetCurrentInputMethod(userId);
    EXPECT_TRUE(property != nullptr);
}

/**
 * @tc.name: testMultiUserGetCurrentInputMethod_002
 * @tc.desc: Test GetCurrentInputMethod for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetCurrentInputMethod_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetCurrentInputMethod 002 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    std::shared_ptr<Property> property = imc_->GetCurrentInputMethod(userId);
    EXPECT_TRUE(property != nullptr);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserGetCurrentInputMethodSubtype_001
 * @tc.desc: Test GetCurrentInputMethodSubtype for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetCurrentInputMethodSubtype_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetCurrentInputMethodSubtype 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    std::shared_ptr<SubProperty> subProperty = imc_->GetCurrentInputMethodSubtype(userId);
    EXPECT_TRUE(subProperty != nullptr);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserGetCurrentInputMethodSubtype_002
 * @tc.desc: Test GetCurrentInputMethodSubtype for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetCurrentInputMethodSubtype_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetCurrentInputMethodSubtype 002 Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);
    int32_t userId = TddUtil::GetCurrentUserId();
    std::shared_ptr<SubProperty> subProperty = imc_->GetCurrentInputMethodSubtype(userId);
    EXPECT_TRUE(subProperty != nullptr);
}

/**
 * @tc.name: testMultiUserGetDefaultInputMethod_001
 * @tc.desc: Test GetDefaultInputMethod for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetDefaultInputMethod_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetDefaultInputMethod 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    std::shared_ptr<Property> property = nullptr;
    int32_t ret = imc_->GetDefaultInputMethod(property, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(property != nullptr);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserGetDefaultInputMethod_002
 * @tc.desc: Test GetDefaultInputMethod for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetDefaultInputMethod_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetDefaultInputMethod 002 Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    std::shared_ptr<Property> property = nullptr;
    int32_t ret = imc_->GetDefaultInputMethod(property, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(property != nullptr);
}

/**
 * @tc.name: testMultiUserSwitchInputMethod_001
 * @tc.desc: Test SwitchInputMethod for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserSwitchInputMethod_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testSwitchInputMethod 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t ret = imc_->SwitchInputMethod(SwitchTrigger::NATIVE_SA, bundleName, extName[0], userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    sleep(WAIT_IME_READY_TIME);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserSwitchInputMethod_002
 * @tc.desc: Test SwitchInputMethod for U100 user with SYSTEM_APP trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserSwitchInputMethod_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testSwitchInputMethod 002 Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t ret = imc_->SwitchInputMethod(SwitchTrigger::SYSTEM_APP, bundleName, extName[0], userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    sleep(WAIT_IME_READY_TIME);
}

/**
 * @tc.name: testMultiUserSwitchInputMethod_002
 * @tc.desc: Test SwitchInputMethod for U100 user with SYSTEM_APP trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserSwitchInputMethod_003, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testSwitchInputMethod 003 Test START");

    int32_t userId = -100;
    int32_t ret = imc_->SwitchInputMethod(SwitchTrigger::CURRENT_IME, bundleName, extName[0], userId);
    EXPECT_EQ(ret, ErrorCode::ERROR_USER_NOT_EXIST);

    sleep(WAIT_IME_READY_TIME);
}

/**
 * @tc.name: testMultiUserSwitchInputMethod_004
 * @tc.desc: Test SwitchInputMethod for U100 user with SYSTEM_APP trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserSwitchInputMethod_004, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testSwitchInputMethod 004 Test START");
    UidScope uidScope(20000000);

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t ret = imc_->SwitchInputMethod(SwitchTrigger::SYSTEM_APP, bundleName, extName[0], userId);
    EXPECT_EQ(ret, ErrorCode::ERROR_INVALID_USER_OPERATION);

    sleep(WAIT_IME_READY_TIME);
}

/**
 * @tc.name: testMultiUserSwitchInputMethod_00
 * @tc.desc: Test SwitchInputMethod for U100 user with SYSTEM_APP trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserSwitchInputMethod_005, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testSwitchInputMethod 005 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t ret = imc_->SwitchInputMethod(SwitchTrigger::SYSTEM_APP, bundleName, extName[0], userId);
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION);

    sleep(WAIT_IME_READY_TIME);
    TddUtil::StorageSelfTokenID();
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserRequestHideInput_001
 * @tc.desc: Test RequestHideInput for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserRequestHideInput_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testRequestHideInput 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t ret = imc_->RequestHideInput(0, false, 0, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = imc_->RequestHideInput(0, false, 0, -2);
    EXPECT_NE(ret, ErrorCode::NO_ERROR);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserRequestHideInput_002
 * @tc.desc: Test RequestHideInput for U100 user with SYSTEM_APP trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserRequestHideInput_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testRequestHideInput 002 Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t ret = imc_->RequestHideInput(0, false, 0, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}


/**
 * @tc.name: testMultiUserIsCurrentImeByPid_001
 * @tc.desc: Test IsCurrentImeByPid for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserIsCurrentImeByPid_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testIsCurrentImeByPid 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t pid = 1000;
    bool result = imc_->IsCurrentImeByPid(pid, userId);
    EXPECT_TRUE(result || !result);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserIsCurrentImeByPid_002
 * @tc.desc: Test IsCurrentImeByPid for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserIsCurrentImeByPid_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testIsCurrentImeByPid 002 Test START");
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t pid = 1000;
    bool result = imc_->IsCurrentImeByPid(pid, userId);
    EXPECT_TRUE(result || !result);
}

/**
 * @tc.name: testMultiUserIsDefaultImeSet_001
 * @tc.desc: Test IsDefaultImeSet for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserIsDefaultImeSet_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testIsDefaultImeSet 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    bool isSet = imc_->IsDefaultImeSet(userId);
    EXPECT_TRUE(isSet || !isSet);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserIsDefaultImeSet_002
 * @tc.desc: Test IsDefaultImeSet for U100 user
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserIsDefaultImeSet_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testIsDefaultImeSet 002 Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    bool isSet = imc_->IsDefaultImeSet(userId);
    EXPECT_TRUE(isSet || !isSet);
}


/**
 * @tc.name: testMultiUserEnableIme_001
 * @tc.desc: Test EnableIme for U100 user with NATIVE_SA trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserEnableIme_001, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testEnableIme 001 Test START");

    TddUtil::RestoreSelfTokenID();
    UidScope uidScope(0);
    TddUtil::GrantNativePermission();

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t ret = imc_->EnableIme(bundleName, extName[0], EnabledStatus::BASIC_MODE, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

/**
 * @tc.name: testMultiUserEnableIme_002
 * @tc.desc: Test EnableIme for U100 user with SYSTEM_APP trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserEnableIme_002, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testEnableIme 002 Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = TddUtil::GetCurrentUserId();
    int32_t ret = imc_->EnableIme(bundleName, extName[0], EnabledStatus::BASIC_MODE, userId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testMultiUserSwitchInputMethod_InvalidUserId
 * @tc.desc: Test SwitchInputMethod with invalid userId=-2
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserSwitchInputMethod_InvalidUserId, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testSwitchInputMethod InvalidUserId Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = -2;
    int32_t ret = imc_->SwitchInputMethod(SwitchTrigger::SYSTEM_APP, bundleName, extName[0], userId);
    EXPECT_NE(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testMultiUserGetCurrentInputMethod_InvalidUserId
 * @tc.desc: Test GetCurrentInputMethod with invalid userId=-2
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetCurrentInputMethod_InvalidUserId, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetCurrentInputMethod InvalidUserId Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = -2;
    std::shared_ptr<Property> property = imc_->GetCurrentInputMethod(userId);
    EXPECT_TRUE(property == nullptr);
}

/**
 * @tc.name: testMultiUserGetCurrentInputMethodSubtype_InvalidUserId
 * @tc.desc: Test GetCurrentInputMethodSubtype with invalid userId=-2
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetCurrentInputMethodSubtype_InvalidUserId, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetCurrentInputMethodSubtype InvalidUserId Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = -2;
    std::shared_ptr<SubProperty> subProperty = imc_->GetCurrentInputMethodSubtype(userId);
    EXPECT_TRUE(subProperty == nullptr);
}

/**
 * @tc.name: testMultiUserGetDefaultInputMethod_InvalidUserId
 * @tc.desc: Test GetDefaultInputMethod with invalid userId=-2
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetDefaultInputMethod_InvalidUserId, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetDefaultInputMethod InvalidUserId Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = -2;
    std::shared_ptr<Property> property = nullptr;
    int32_t ret = imc_->GetDefaultInputMethod(property, userId);
    EXPECT_NE(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testMultiUserGetInputMethodConfig_InvalidUserId
 * @tc.desc: Test GetInputMethodConfig with invalid userId=-2
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserGetInputMethodConfig_InvalidUserId, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testGetInputMethodConfig InvalidUserId Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = -2;
    AppExecFwk::ElementName inputMethodConfig;
    int32_t ret = imc_->GetInputMethodConfig(inputMethodConfig, userId);
    EXPECT_NE(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testMultiUserListInputMethod_InvalidUserId
 * @tc.desc: Test ListInputMethod with invalid userId=-2
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListInputMethod_InvalidUserId, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListInputMethod InvalidUserId Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = -2;
    std::vector<Property> props;
    int32_t ret = imc_->ListInputMethod(props, userId);
    EXPECT_NE(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testMultiUserListCurrentInputMethodSubtype_InvalidUserId
 * @tc.desc: Test ListCurrentInputMethodSubtype with invalid userId=-2
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: huangyaohua
 */
HWTEST_F(ImeMultiUserTest, testMultiUserListCurrentInputMethodSubtype_InvalidUserId, TestSize.Level1)
{
    IMSA_HILOGI("multiuser testListCurrentInputMethodSubtype InvalidUserId Test START");

    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
    UidScope uidScope(0);

    int32_t userId = -2;
    std::vector<SubProperty> subProps;
    int32_t ret = imc_->ListCurrentInputMethodSubtype(subProps, userId);
    EXPECT_NE(ret, ErrorCode::NO_ERROR);
}

} // namespace MiscServices
} // namespace OHOS
