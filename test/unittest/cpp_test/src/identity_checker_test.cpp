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
#include "input_method_system_ability.h"
#undef private

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdint>
#include <regex>
#include <sstream>
#include <string>

#include "global.h"
using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
constexpr uint32_t INVAL_TOKEN_ID = -1;
constexpr uint32_t INVAL_WINDOW_ID = 0;

class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject(u"mock_i_remote_object") { }
    ~MockIRemoteObject() { }
    MOCK_METHOD(int, SendRequest, (uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD(bool, IsProxyObject, (), (const, override));
    MOCK_METHOD(bool, CheckObjectLegality, (), (const, override));
    MOCK_METHOD(bool, AddDeathRecipient, (const sptr<DeathRecipient> &recipient), (override));
    MOCK_METHOD(bool, RemoveDeathRecipient, (const sptr<DeathRecipient> &recipient), (override));
    MOCK_METHOD(bool, Marshalling, (Parcel & parcel), (const, override));
    MOCK_METHOD(sptr<IRemoteBroker>, AsInterface, (), (override));
    MOCK_METHOD(int, Dump, (int fd, const std::vector<std::u16string> &args), (override));
    MOCK_METHOD(int32_t, GetObjectRefCount, (), (override));

    std::u16string GetObjectDescriptor() const
    {
        std::u16string descriptor = std::u16string();
        return descriptor;
    }
};

class IdentityCheckerTest : public testing::Test {
public:
    class IdentityCheckerMock : public IdentityChecker {
    public:
        IdentityCheckerMock() = default;
        virtual ~IdentityCheckerMock() = default;
        bool IsFocused(int64_t callingPid, uint32_t callingTokenId, int64_t focusedPid = INVALID_PID,
            bool isAttach = false, sptr<IRemoteObject> abilityToken = nullptr) override
        {
            return isFocused_;
        }
        bool IsSystemApp(uint64_t fullTokenId) override
        {
            return isSystemApp_;
        }
        bool IsBundleNameValid(uint32_t tokenId, const std::string &validBundleName) override
        {
            return isBundleNameValid_;
        }
        bool HasPermission(uint32_t tokenId, const std::string &permission) override
        {
            return hasPermission_;
        }
        bool IsBroker(Security::AccessToken::AccessTokenID tokenId) override
        {
            return isBroker_;
        }
        bool IsNativeSa(Security::AccessToken::AccessTokenID tokenId) override
        {
            return isNativeSa_;
        }
        bool IsFormShell(Security::AccessToken::AccessTokenID tokenId) override
        {
            return isFromShell_;
        }
        std::string GetBundleNameByToken(uint32_t tokenId) override
        {
            return "";
        }
        bool IsSpecialSaUid() override
        {
            return true;
        }
        bool IsFocusedUIExtension(uint32_t callingTokenId, sptr<IRemoteObject> abilityToken = nullptr) override
        {
            return isFocusedUIExtension_;
        }
        static bool isFocused_;
        static bool isSystemApp_;
        static bool isBundleNameValid_;
        static bool hasPermission_;
        static bool isBroker_;
        static bool isNativeSa_;
        static bool isFromShell_;
        static bool isFocusedUIExtension_;
    };
    static constexpr uint32_t MAIN_USER_ID = 100;
    static const constexpr char *CURRENT_IME = "testBundleName/testExtname";
    static const constexpr char *CURRENT_SUBNAME = "testSubName";
    static const constexpr char *CURRENT_BUNDLENAME = "testBundleName";
    static const constexpr char *CURRENT_EXTNAME = "testExtName";
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static sptr<InputMethodSystemAbility> service_;
    static std::shared_ptr<IdentityCheckerMock> identityCheckerMock_;
    static std::shared_ptr<IdentityCheckerImpl> identityCheckerImpl_;
};
bool IdentityCheckerTest::IdentityCheckerMock::isFocused_ = false;
bool IdentityCheckerTest::IdentityCheckerMock::isSystemApp_ = false;
bool IdentityCheckerTest::IdentityCheckerMock::isBundleNameValid_ = false;
bool IdentityCheckerTest::IdentityCheckerMock::hasPermission_ = false;
bool IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
bool IdentityCheckerTest::IdentityCheckerMock::isNativeSa_ = false;
bool IdentityCheckerTest::IdentityCheckerMock::isFromShell_ = false;
bool IdentityCheckerTest::IdentityCheckerMock::isFocusedUIExtension_ = false;

void IdentityCheckerTest::SetUpTestCase(void)
{
    IMSA_HILOGI("IdentityCheckerTest::SetUpTestCase");
    service_ = new (std::nothrow) InputMethodSystemAbility();
    if (service_ == nullptr) {
        return;
    }
    service_->OnStart();
    ImeCfgManager::GetInstance().imeConfigs_ = {
        { MAIN_USER_ID, CURRENT_IME, CURRENT_SUBNAME, false }
    };
    identityCheckerImpl_ = std::make_shared<IdentityCheckerImpl>();
}

void IdentityCheckerTest::TearDownTestCase(void)
{
    IMSA_HILOGI("IdentityCheckerTest::TearDownTestCase");
    service_->OnStop();
}

void IdentityCheckerTest::SetUp(void)
{
    identityCheckerMock_ = std::make_shared<IdentityCheckerMock>();
    service_->identityChecker_ = identityCheckerMock_;
    IMSA_HILOGI("IdentityCheckerTest::SetUp");
}

void IdentityCheckerTest::TearDown(void)
{
    service_->identityChecker_ = identityCheckerImpl_;
    identityCheckerMock_ = nullptr;
    IMSA_HILOGI("IdentityCheckerTest::TearDown");
}

sptr<InputMethodSystemAbility> IdentityCheckerTest::service_;
std::shared_ptr<IdentityCheckerTest::IdentityCheckerMock> IdentityCheckerTest::identityCheckerMock_;
std::shared_ptr<IdentityCheckerImpl> IdentityCheckerTest::identityCheckerImpl_;

/**
 * @tc.name: testStartInput_001
 * @tc.desc: not broker, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStartInput_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStartInput_001 start");
    service_->identityChecker_ = identityCheckerImpl_;
    InputClientInfoInner inputClientInfo;
    std::vector<sptr<IRemoteObject>> agents;
    std::vector<BindImeInfo> imeInfos;
    int32_t ret = IdentityCheckerTest::service_->StartInput(inputClientInfo, agents, imeInfos);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: testStartInput_002
 * @tc.desc: is broker, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStartInput_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStartInput_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = false;
    InputClientInfoInner inputClientInfo;
    std::vector<sptr<IRemoteObject>> agents;
    std::vector<BindImeInfo> imeInfos;
    int32_t ret = IdentityCheckerTest::service_->StartInput(inputClientInfo, agents, imeInfos);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_REBOOT_OLD_IME_NOT_STOP);
}

/**
 * @tc.name: testStartInput_003
 * @tc.desc: is broker, is focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStartInput_003, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStartInput_003 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = true;
    InputClientInfoInner inputClientInfo;
    std::vector<sptr<IRemoteObject>> agents;
    std::vector<BindImeInfo> imeInfos;
    int32_t ret = IdentityCheckerTest::service_->StartInput(inputClientInfo, agents, imeInfos);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_REBOOT_OLD_IME_NOT_STOP);
}

/**
 * @tc.name: testStartInput_004
 * @tc.desc: not broker, is focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStartInput_004, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStartInput_004 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = true;
    InputClientInfoInner inputClientInfo;
    std::vector<sptr<IRemoteObject>> agents;
    std::vector<BindImeInfo> imeInfos;
    int32_t ret = IdentityCheckerTest::service_->StartInput(inputClientInfo, agents, imeInfos);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_REBOOT_OLD_IME_NOT_STOP);
}

/**
 * @tc.name: testStopInput_001
 * @tc.desc: not broker, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStopInput_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStopInput_001 start");
    service_->identityChecker_ = identityCheckerImpl_;
    int32_t ret = IdentityCheckerTest::service_->HideInput(nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: testStopInput_002
 * @tc.desc: is broker, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStopInput_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStopInput_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = false;
    int32_t ret = IdentityCheckerTest::service_->HideInput(nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testStopInput_003
 * @tc.desc: is broker, is focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStopInput_003, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStopInput_003 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = true;
    InputClientInfo clientInfo {};
    int32_t ret = IdentityCheckerTest::service_->HideInput(nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testStopInput_004
 * @tc.desc: not broker, is focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStopInput_004, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStopInput_004 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = true;
    InputClientInfo clientInfo {};
    int32_t ret = IdentityCheckerTest::service_->HideInput(nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: testStopInputSession_001
 * @tc.desc: not broker, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStopInputSession_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStopInputSession_001 start");
    service_->identityChecker_ = identityCheckerImpl_;
    int32_t ret = IdentityCheckerTest::service_->StopInputSession();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: testStopInputSession_002
 * @tc.desc: is broker, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStopInputSession_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStopInputSession_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = false;
    int32_t ret = IdentityCheckerTest::service_->StopInputSession();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testStopInputSession_003
 * @tc.desc: is broker, is focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStopInputSession_003, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStopInputSession_003 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = true;
    InputClientInfo clientInfo {};
    int32_t ret = IdentityCheckerTest::service_->StopInputSession();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testStopInputSession_004
 * @tc.desc: not broker, is focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testStopInputSession_004, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testStopInputSession_004 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = true;
    InputClientInfo clientInfo {};
    int32_t ret = IdentityCheckerTest::service_->StopInputSession();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testSetCoreAndAgent_001
 * @tc.desc: not current ime
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testSetCoreAndAgent_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testSetCoreAndAgent_001 start");
    service_->identityChecker_ = identityCheckerImpl_;
    int32_t ret = IdentityCheckerTest::service_->SetCoreAndAgent(nullptr, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_CURRENT_IME);
}

/**
 * @tc.name: testSetCoreAndAgent_002
 * @tc.desc: not current ime
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testSetCoreAndAgent_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testSetCoreAndAgent_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBundleNameValid_ = true;
    int32_t ret = IdentityCheckerTest::service_->SetCoreAndAgent(nullptr, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_CURRENT_IME);
}

/**
 * @tc.name: testUnRegisteredProxyIme_001
 * @tc.desc: not a sys_basic native sa
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testUnRegisteredProxyIme_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testUnRegisteredProxyIme_001 start");
    IdentityCheckerTest::IdentityCheckerMock::isNativeSa_ = false;
    int32_t ret = IdentityCheckerTest::service_->UnRegisteredProxyIme(
        static_cast<int32_t>(UnRegisteredType::REMOVE_PROXY_IME), nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
}

/**
 * @tc.name: testIsCurrentIme_001
 * @tc.desc: not current ime
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testIsCurrentIme_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testIsCurrentIme_001 start");
    service_->identityChecker_ = identityCheckerImpl_;
    bool ret = IdentityCheckerTest::service_->IsCurrentIme(MAIN_USER_ID, 0);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: testIsCurrentIme_002
 * @tc.desc: not current ime
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testIsCurrentIme_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testIsCurrentIme_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBundleNameValid_ = true;
    bool ret = IdentityCheckerTest::service_->IsCurrentIme(MAIN_USER_ID, 0);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: testHideCurrentInput_001
 * @tc.desc: is broker
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testHideCurrentInput_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testHideCurrentInput_001 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    int32_t ret = IdentityCheckerTest::service_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testHideCurrentInput_002
 * @tc.desc: is not broker, has no PERMISSION_CONNECT_IME_ABILITY
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testHideCurrentInput_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testHideCurrentInput_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::hasPermission_ = false;
    int32_t ret = IdentityCheckerTest::service_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
}

/**
 * @tc.name: testHideCurrentInput_003
 * @tc.desc: is not broker, has PERMISSION_CONNECT_IME_ABILITY, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testHideCurrentInput_003, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testHideCurrentInput_003 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::hasPermission_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = false;
    int32_t ret = IdentityCheckerTest::service_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testShowCurrentInput_001
 * @tc.desc: is broker
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testShowCurrentInput_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testShowCurrentInput_001 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    int32_t ret = IdentityCheckerTest::service_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testShowCurrentInput_002
 * @tc.desc: is not broker, has no PERMISSION_CONNECT_IME_ABILITY
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testShowCurrentInput_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testShowCurrentInput_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::hasPermission_ = false;
    int32_t ret = IdentityCheckerTest::service_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
}

/**
 * @tc.name: testShowCurrentInput_003
 * @tc.desc: is not broker, has PERMISSION_CONNECT_IME_ABILITY, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testShowCurrentInput_003, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testShowCurrentInput_003 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::hasPermission_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = false;
    int32_t ret = IdentityCheckerTest::service_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testPanelStatusChange_001
 * @tc.desc: not current ime
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testPanelStatusChange_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testPanelStatusChange_001 start");
    service_->identityChecker_ = identityCheckerImpl_;
    InputWindowStatus status = InputWindowStatus::SHOW;
    ImeWindowInfo info {};
    int32_t ret = IdentityCheckerTest::service_->PanelStatusChange(static_cast<uint32_t>(status), info);
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_CURRENT_IME);
}

/**
 * @tc.name: testPanelStatusChange_002
 * @tc.desc: not current ime
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testPanelStatusChange_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testPanelStatusChange_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBundleNameValid_ = true;
    InputWindowStatus status = InputWindowStatus::SHOW;
    ImeWindowInfo info {};
    int32_t ret = IdentityCheckerTest::service_->PanelStatusChange(static_cast<uint32_t>(status), info);
    EXPECT_EQ(ret, ErrorCode::ERROR_NOT_CURRENT_IME);
}

/**
 * @tc.name: testUpdateListenEventFlag_001
 * @tc.desc: not system app, not native SA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testUpdateListenEventFlag_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testUpdateListenEventFlag_001 start");
    service_->identityChecker_ = identityCheckerImpl_;
    InputClientInfoInner clientInfo {};
    int32_t ret = IdentityCheckerTest::service_->UpdateListenEventFlag(clientInfo, EVENT_IME_SHOW_MASK);
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION);

    ret = IdentityCheckerTest::service_->UpdateListenEventFlag(clientInfo, EVENT_IME_HIDE_MASK);
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION);

    ret = IdentityCheckerTest::service_->UpdateListenEventFlag(clientInfo, EVENT_IME_CHANGE_MASK);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_NULLPTR);
}

/**
 * @tc.name: testUpdateListenEventFlag_002
 * @tc.desc: is system app, not native SA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testUpdateListenEventFlag_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testUpdateListenEventFlag_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isSystemApp_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isNativeSa_ = false;
    InputClientInfoInner clientInfo {};
    int32_t ret = IdentityCheckerTest::service_->UpdateListenEventFlag(clientInfo, EVENT_IME_SHOW_MASK);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_NULLPTR);

    ret = IdentityCheckerTest::service_->UpdateListenEventFlag(clientInfo, EVENT_IME_HIDE_MASK);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_NULLPTR);

    ret = IdentityCheckerTest::service_->UpdateListenEventFlag(clientInfo, EVENT_IME_CHANGE_MASK);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_NULLPTR);
}

/**
 * @tc.name: testUpdateListenEventFlag_003
 * @tc.desc: is native SA, not system app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testUpdateListenEventFlag_003, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testUpdateListenEventFlag_003 start");
    IdentityCheckerTest::IdentityCheckerMock::isSystemApp_ = false;
    IdentityCheckerTest::IdentityCheckerMock::isNativeSa_ = true;
    InputClientInfoInner clientInfo {};
    int32_t ret = IdentityCheckerTest::service_->UpdateListenEventFlag(clientInfo, EVENT_IME_SHOW_MASK);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_NULLPTR);

    ret = IdentityCheckerTest::service_->UpdateListenEventFlag(clientInfo, EVENT_IME_HIDE_MASK);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_NULLPTR);

    ret = IdentityCheckerTest::service_->UpdateListenEventFlag(clientInfo, EVENT_IME_CHANGE_MASK);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_NULLPTR);
}

/**
 * @tc.name: testDisplayOptionalInputMethod_001
 * @tc.desc: has no PERMISSION
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testDisplayOptionalInputMethod_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testDisplayOptionalInputMethod_001 start");
    service_->identityChecker_ = identityCheckerImpl_;
    int32_t ret = IdentityCheckerTest::service_->DisplayOptionalInputMethod();
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_SERVICE_SPECIFIC);
}

/**
 * @tc.name: testSwitchInputMethod_001
 * @tc.desc: has no PERMISSION_CONNECT_IME_ABILITY, and not currentIme switch subtype
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testSwitchInputMethod_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testSwitchInputMethod_001 start");
    ImeEnabledCfg cfg;
    ImeEnabledInfo enabledInfo{ CURRENT_BUNDLENAME, CURRENT_EXTNAME, EnabledStatus::BASIC_MODE };
    enabledInfo.extraInfo.isDefaultIme = true;
    cfg.enabledInfos.push_back(enabledInfo);
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.insert_or_assign(MAIN_USER_ID, cfg);
    service_->identityChecker_ = identityCheckerImpl_;
    int32_t ret = IdentityCheckerTest::service_->SwitchInputMethod(
        CURRENT_BUNDLENAME, CURRENT_SUBNAME, static_cast<uint32_t>(SwitchTrigger::CURRENT_IME));
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
}

/**
 * @tc.name: testSwitchInputMethod_003
 * @tc.desc: has PERMISSION_CONNECT_IME_ABILITY, not currentIme switch subtype
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testSwitchInputMethod_003, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testSwitchInputMethod_003 start");
    ImeEnabledCfg cfg;
    ImeEnabledInfo enabledInfo{ CURRENT_BUNDLENAME, CURRENT_EXTNAME, EnabledStatus::BASIC_MODE };
    enabledInfo.extraInfo.isDefaultIme = true;
    cfg.enabledInfos.push_back(enabledInfo);
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.insert_or_assign(MAIN_USER_ID, cfg);
    IdentityCheckerTest::IdentityCheckerMock::hasPermission_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isBundleNameValid_ = false;
    int32_t ret = IdentityCheckerTest::service_->SwitchInputMethod(
        CURRENT_BUNDLENAME, CURRENT_SUBNAME, static_cast<uint32_t>(SwitchTrigger::CURRENT_IME));
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_GET_IME_INFO_FAILED);
}

/**
 * @tc.name: testSwitchInputMethod_004
 * @tc.desc: has PERMISSION_CONNECT_IME_ABILITY, not currentIme switch subtype
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testSwitchInputMethod_004, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testSwitchInputMethod_004 start");
    ImeEnabledCfg cfg;
    ImeEnabledInfo enabledInfo{ CURRENT_BUNDLENAME, CURRENT_EXTNAME, EnabledStatus::BASIC_MODE };
    enabledInfo.extraInfo.isDefaultIme = true;
    cfg.enabledInfos.push_back(enabledInfo);
    ImeEnabledInfoManager::GetInstance().imeEnabledCfg_.insert_or_assign(MAIN_USER_ID, cfg);
    service_->identityChecker_ = identityCheckerImpl_;
    IdentityCheckerTest::IdentityCheckerMock::isFromShell_ = true;
    IdentityCheckerTest::IdentityCheckerMock::isBundleNameValid_ = false;
    int32_t ret = IdentityCheckerTest::service_->SwitchInputMethod(
        CURRENT_BUNDLENAME, CURRENT_SUBNAME, static_cast<uint32_t>(SwitchTrigger::NATIVE_SA));
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_GET_IME_INFO_FAILED);
}

/**
 * @tc.name: testHideCurrentInputDeprecated_001
 * @tc.desc: is broker
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testHideCurrentInputDeprecated_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testHideCurrentInputDeprecated_001 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    int32_t ret = IdentityCheckerTest::service_->HideCurrentInputDeprecated();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testHideCurrentInputDeprecated_002
 * @tc.desc: is not broker, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testHideCurrentInputDeprecated_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testHideCurrentInputDeprecated_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = false;
    int32_t ret = IdentityCheckerTest::service_->HideCurrentInputDeprecated();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: testHideCurrentInputDeprecated_003
 * @tc.desc: is not broker, is focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testHideCurrentInputDeprecated_003, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testHideCurrentInputDeprecated_003 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = true;
    int32_t ret = IdentityCheckerTest::service_->HideCurrentInputDeprecated();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testShowCurrentInputDeprecated_001
 * @tc.desc: is broker
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testShowCurrentInputDeprecated_001, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testShowCurrentInputDeprecated_001 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = true;
    int32_t ret = IdentityCheckerTest::service_->ShowCurrentInputDeprecated();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: testShowCurrentInputDeprecated_002
 * @tc.desc: is not broker, not focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testShowCurrentInputDeprecated_002, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testShowCurrentInputDeprecated_002 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = false;
    int32_t ret = IdentityCheckerTest::service_->ShowCurrentInputDeprecated();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: testShowCurrentInputDeprecated_003
 * @tc.desc: is not broker, is focused app
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testShowCurrentInputDeprecated_003, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testShowCurrentInputDeprecated_003 start");
    IdentityCheckerTest::IdentityCheckerMock::isBroker_ = false;
    IdentityCheckerTest::IdentityCheckerMock::isFocused_ = true;
    int32_t ret = IdentityCheckerTest::service_->ShowCurrentInputDeprecated();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

TEST_F(IdentityCheckerTest, OnExtension_extensionIsEmpty_ReturnsOK)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(service_->OnExtension("", data, reply), 0);
}

TEST_F(IdentityCheckerTest, OnExtension_dataIsEmpty_ReturnsBadParam)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(service_->OnExtension("restore", data, reply), ErrorCode::ERROR_BAD_PARAMETERS);
}

TEST_F(IdentityCheckerTest, OnExtension_BundleNameIsInvalid_ReturnsBadParam)
{
    MessageParcel data;
    data.WriteString("[{\"type\":\"default_input_method\",\"detail\":\"com.invalid.bundleName\"}]");
    MessageParcel reply;
    EXPECT_EQ(service_->OnExtension("restore", data, reply), ErrorCode::ERROR_BAD_PARAMETERS);
}

TEST_F(IdentityCheckerTest, GetRestoreBundleName_EmptyJsonString_ReturnsEmpty)
{
    MessageParcel data;
    data.WriteString("");
    std::string bundleName = service_->GetRestoreBundleName(data);
    EXPECT_EQ(bundleName, "");
}

TEST_F(IdentityCheckerTest, GetRestoreBundleName_InvalidJsonString_ReturnsEmpty)
{
    MessageParcel data;
    data.WriteString("{invalid json}");
    std::string bundleName = service_->GetRestoreBundleName(data);
    EXPECT_EQ(bundleName, "");
}

TEST_F(IdentityCheckerTest, GetRestoreBundleName_ValidJsonWithoutDefaultInputMethod_ReturnsEmpty)
{
    MessageParcel data;
    data.WriteString("[{\"type\":\"other_type\",\"detail\":\"some_detail\"}]");
    std::string bundleName = service_->GetRestoreBundleName(data);
    EXPECT_EQ(bundleName, "");
}

TEST_F(IdentityCheckerTest, GetRestoreBundleName_ValidJsonWithDefaultInputMethod_ReturnsBundleName)
{
    MessageParcel data;
    data.WriteString("[{\"type\":\"default_input_method\",\"detail\":\"com.example.inputmethod\"}]");
    std::string bundleName = service_->GetRestoreBundleName(data);
    EXPECT_EQ(bundleName, "com.example.inputmethod");
}

TEST_F(IdentityCheckerTest, GetRestoreBundleName_MissingTypeOrDetail_ReturnsEmpty)
{
    MessageParcel data;
    data.WriteString("[{\"type\":\"default_input_method\"}]");
    std::string bundleName = service_->GetRestoreBundleName(data);
    EXPECT_EQ(bundleName, "");
}

/**
 * @tc.name: testIsFocusedUIExtension
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testIsFocusedUIExtension, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testIsFocusedUIExtension start");
    sptr<IRemoteObject> abilityToken = nullptr;
    uint32_t callingTokenId = INVAL_TOKEN_ID;
    auto ret = identityCheckerImpl_->IsFocusedUIExtension(callingTokenId, abilityToken);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: testGetUIExtensionWindowId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(IdentityCheckerTest, testGetUIExtensionWindowId, TestSize.Level1)
{
    IMSA_HILOGI("IdentityCheckerTest testGetUIExtensionWindowId start");
    sptr<IRemoteObject> abilityToken = nullptr;
    auto ret = identityCheckerImpl_->GetUIExtensionWindowId(abilityToken);
    EXPECT_EQ(ret, INVAL_WINDOW_ID);

    abilityToken = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(abilityToken, nullptr);
    ret = identityCheckerImpl_->GetUIExtensionWindowId(abilityToken);
    EXPECT_EQ(ret, INVAL_WINDOW_ID);
}
} // namespace MiscServices
} // namespace OHOS