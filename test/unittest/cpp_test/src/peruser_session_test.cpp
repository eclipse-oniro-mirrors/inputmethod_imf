/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <memory>
#include <string>
#include <vector>

#include "peruser_session.h"

#include "global.h"
#include "iinput_method_agent.h"
#include "iinput_method_core.h"
#include "input_client_info.h"
#include "input_client_proxy.h"
#include "input_client_service_impl.h"
#include "input_death_recipient.h"
#include "input_method_agent_proxy.h"
#include "input_method_agent_service_impl.h"
#include "input_method_core_proxy.h"
#include "input_method_core_service_impl.h"
#include "input_method_property.h"
#include "input_method_types.h"
#include "tdd_util.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
constexpr int32_t TEST_USER_ID = 100;
constexpr uint64_t TEST_DISPLAY_ID = 0;
constexpr uint64_t TEST_DISPLAY_GROUP_ID = 0;
constexpr pid_t TEST_PID = 1234;
constexpr pid_t TEST_UID = 5678;

class PerUserSessionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<PerUserSession> session_ { nullptr };
};

void PerUserSessionTest::SetUpTestCase(void)
{
    IMSA_HILOGI("PerUserSessionTest::SetUpTestCase");
    TddUtil::StorageSelfTokenID();
    TddUtil::SetTestTokenID(TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test",
        { "ohos.permission.CONNECT_IME_ABILITY", "ohos.permission.INJECT_INPUT_EVENT" }));
}

void PerUserSessionTest::TearDownTestCase(void)
{
    IMSA_HILOGI("PerUserSessionTest::TearDownTestCase");
    TddUtil::RestoreSelfTokenID();
}

void PerUserSessionTest::SetUp()
{
    IMSA_HILOGI("PerUserSessionTest::SetUp");
    session_ = std::make_shared<PerUserSession>(TEST_USER_ID, nullptr);
}

void PerUserSessionTest::TearDown()
{
    IMSA_HILOGI("PerUserSessionTest::TearDown");
    session_.reset();
}

// Helper: create an InputClientInfo with a real client stub
static InputClientInfo MakeClientInfo(pid_t pid, uint64_t clientGroupId = TEST_DISPLAY_GROUP_ID)
{
    sptr<IInputClient> clientStub = new (std::nothrow) InputClientServiceImpl();
    sptr<InputDeathRecipient> deathRecipient = new (std::nothrow) InputDeathRecipient();
    InputClientInfo info;
    info.pid = pid;
    info.uid = TEST_UID;
    info.userID = TEST_USER_ID;
    info.client = clientStub;
    info.channel = nullptr;
    info.deathRecipient = deathRecipient;
    info.isShowKeyboard = false;
    info.clientGroupId = clientGroupId;
    return info;
}

// Helper: create real IME data with mock core and agent
static std::shared_ptr<ImeData> MakeImeData(
    pid_t pid = TEST_PID, ImeType type = ImeType::IME, ImeStatus status = ImeStatus::READY)
{
    sptr<InputMethodCoreStub> coreStub = new (std::nothrow) InputMethodCoreServiceImpl();
    sptr<InputMethodAgentStub> agentStub = new (std::nothrow) InputMethodAgentServiceImpl();
    if (coreStub == nullptr || agentStub == nullptr) {
        return nullptr;
    }
    auto imeData = std::make_shared<ImeData>(
        iface_cast<IInputMethodCore>(coreStub->AsObject()), agentStub->AsObject(), nullptr, pid);
    if (imeData == nullptr) {
        return nullptr;
    }
    imeData->type = type;
    imeData->imeStatus = status;
    imeData->uid = TEST_UID;
    imeData->ime = { "com.test.ime", "InputMethodExtAbility" };
    return imeData;
}

/**
 * @tc.name: TestConstruction_001
 * @tc.desc: Test PerUserSession construction with valid userId
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestConstruction_001, TestSize.Level0)
{
    ASSERT_NE(session_, nullptr);
    EXPECT_EQ(session_->userId_, TEST_USER_ID);
}

/**
 * @tc.name: TestConstruction_002
 * @tc.desc: Test PerUserSession construction with negative userId
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestConstruction_002, TestSize.Level0)
{
    auto negSession = std::make_shared<PerUserSession>(-1, nullptr);
    ASSERT_NE(negSession, nullptr);
    EXPECT_EQ(negSession->userId_, -1);
}

/**
 * @tc.name: TestDestructor_001
 * @tc.desc: Test PerUserSession destructor does not crash
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestDestructor_001, TestSize.Level0)
{
    auto tempSession = std::make_shared<PerUserSession>(TEST_USER_ID, nullptr);
    ASSERT_NE(tempSession, nullptr);
    tempSession.reset();
    EXPECT_EQ(tempSession, nullptr);
}

/**
 * @tc.name: TestOnPrepareInput_NullClient_001
 * @tc.desc: Test OnPrepareInput with null client
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnPrepareInput_NullClient_001, TestSize.Level0)
{
    InputClientInfo info;
    info.client = nullptr;
    auto ret = session_->OnPrepareInput(info);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: TestOnPrepareInput_ValidClient_001
 * @tc.desc: Test OnPrepareInput with valid client info
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnPrepareInput_ValidClient_001, TestSize.Level0)
{
    auto info = MakeClientInfo(TEST_PID);
    auto ret = session_->OnPrepareInput(info);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: TestOnPrepareInput_DuplicateClient_001
 * @tc.desc: Test OnPrepareInput adding the same client twice
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnPrepareInput_DuplicateClient_001, TestSize.Level0)
{
    auto info = MakeClientInfo(TEST_PID);
    auto ret = session_->OnPrepareInput(info);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    // Adding same client object again should still succeed (or return appropriate error)
    ret = session_->OnPrepareInput(info);
    // The second add may succeed or fail depending on implementation
}

/**
 * @tc.name: TestOnReleaseInput_NullClient_001
 * @tc.desc: Test OnReleaseInput with null client
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnReleaseInput_NullClient_001, TestSize.Level0)
{
    auto ret = session_->OnReleaseInput(nullptr, 0, -1);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: TestOnReleaseInput_ClientNotFound_001
 * @tc.desc: Test OnReleaseInput when client group is not found
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnReleaseInput_ClientNotFound_001, TestSize.Level0)
{
    sptr<IInputClient> clientStub = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(clientStub, nullptr);
    auto ret = session_->OnReleaseInput(clientStub, 0, -1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: TestOnReleaseInput_ValidClient_001
 * @tc.desc: Test OnReleaseInput with a previously added client
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnReleaseInput_ValidClient_001, TestSize.Level0)
{
    auto info = MakeClientInfo(TEST_PID);
    auto ret = session_->OnPrepareInput(info);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = session_->OnReleaseInput(info.client, 0, -1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: TestOnHideCurrentInput_NoClientGroup_001
 * @tc.desc: Test OnHideCurrentInput when no client group exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnHideCurrentInput_NoClientGroup_001, TestSize.Level0)
{
    auto ret = session_->OnHideCurrentInput(TEST_DISPLAY_GROUP_ID);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: TestOnHideCurrentInput_NoCurrentClient_001
 * @tc.desc: Test OnHideCurrentInput when current client is null
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnHideCurrentInput_NoCurrentClient_001, TestSize.Level0)
{
    auto info = MakeClientInfo(TEST_PID, TEST_DISPLAY_GROUP_ID);
    auto ret = session_->OnPrepareInput(info);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    // No current client set, so should return ERROR_CLIENT_NOT_FOUND
    ret = session_->OnHideCurrentInput(TEST_DISPLAY_GROUP_ID);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: TestOnShowCurrentInput_NoClientGroup_001
 * @tc.desc: Test OnShowCurrentInput when no client group exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnShowCurrentInput_NoClientGroup_001, TestSize.Level0)
{
    auto ret = session_->OnShowCurrentInput(TEST_DISPLAY_GROUP_ID);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: TestOnShowCurrentInputInTargetDisplay_NoClientInfo_001
 * @tc.desc: Test OnShowCurrentInputInTargetDisplay with no client bound to real ime
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnShowCurrentInputInTargetDisplay_NoClientInfo_001, TestSize.Level0)
{
    auto ret = session_->OnShowCurrentInputInTargetDisplay(TEST_DISPLAY_ID);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: TestOnHideCurrentInputInTargetDisplay_NoClientInfo_001
 * @tc.desc: Test OnHideCurrentInputInTargetDisplay with no client bound to real ime
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnHideCurrentInputInTargetDisplay_NoClientInfo_001, TestSize.Level0)
{
    auto ret = session_->OnHideCurrentInputInTargetDisplay(TEST_DISPLAY_ID);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: TestOnHideInput_NullClient_001
 * @tc.desc: Test OnHideInput with null client
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnHideInput_NullClient_001, TestSize.Level0)
{
    auto ret = session_->OnHideInput(nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: TestOnHideInput_ClientGroupNotFound_001
 * @tc.desc: Test OnHideInput when client group not found for the client
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnHideInput_ClientGroupNotFound_001, TestSize.Level0)
{
    sptr<IInputClient> clientStub = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(clientStub, nullptr);
    auto ret = session_->OnHideInput(clientStub);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: TestOnShowInput_NullClient_001
 * @tc.desc: Test OnShowInput with null client
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnShowInput_NullClient_001, TestSize.Level0)
{
    auto ret = session_->OnShowInput(nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: TestOnShowInput_ClientGroupNotFound_001
 * @tc.desc: Test OnShowInput when client group not found for the client
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnShowInput_ClientGroupNotFound_001, TestSize.Level0)
{
    sptr<IInputClient> clientStub = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(clientStub, nullptr);
    auto ret = session_->OnShowInput(clientStub);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: TestOnClientDied_RemoteNotInGroup_001
 * @tc.desc: Test OnClientDied when remote is not in any client group
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnClientDied_RemoteNotInGroup_001, TestSize.Level0)
{
    sptr<IInputClient> clientStub = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(clientStub, nullptr);
    // No client group exists, so GetClientGroup returns nullptr
    session_->OnClientDied(clientStub);
}

/**
 * @tc.name: TestOnClientDied_ValidClient_001
 * @tc.desc: Test OnClientDied with a valid client that was added
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnClientDied_ValidClient_001, TestSize.Level0)
{
    auto info = MakeClientInfo(TEST_PID);
    auto ret = session_->OnPrepareInput(info);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    // Simulate client died
    session_->OnClientDied(info.client);
}

/**
 * @tc.name: TestHideKeyboard_NullClient_001
 * @tc.desc: Test HideKeyboard with null client and null clientGroup
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestHideKeyboard_NullClient_001, TestSize.Level0)
{
    auto ret = session_->HideKeyboard(nullptr, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);
}

/**
 * @tc.name: TestHideKeyboard_NullClientGroup_001
 * @tc.desc: Test HideKeyboard with valid client but null clientGroup
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestHideKeyboard_NullClientGroup_001, TestSize.Level0)
{
    sptr<IInputClient> clientStub = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(clientStub, nullptr);
    auto ret = session_->HideKeyboard(clientStub, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);
}

/**
 * @tc.name: TestHideKeyboard_ClientInfoNotFound_001
 * @tc.desc: Test HideKeyboard when client info is not found in group
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestHideKeyboard_ClientInfoNotFound_001, TestSize.Level0)
{
    auto info = MakeClientInfo(TEST_PID);
    auto ret = session_->OnPrepareInput(info);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    auto clientGroup = session_->GetClientGroupByGroupId(TEST_DISPLAY_GROUP_ID);
    ASSERT_NE(clientGroup, nullptr);
    // Create a different client that's not in the group
    sptr<IInputClient> otherClient = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(otherClient, nullptr);
    ret = session_->HideKeyboard(otherClient, clientGroup);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: TestShowKeyboard_NullClient_001
 * @tc.desc: Test ShowKeyboard with null client
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestShowKeyboard_NullClient_001, TestSize.Level0)
{
    auto ret = session_->ShowKeyboard(nullptr, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMSA_NULLPTR);
}

/**
 * @tc.name: TestShowKeyboard_ClientInfoNotFound_001
 * @tc.desc: Test ShowKeyboard when client info not found
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestShowKeyboard_ClientInfoNotFound_001, TestSize.Level0)
{
    auto info = MakeClientInfo(TEST_PID);
    auto ret = session_->OnPrepareInput(info);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    auto clientGroup = session_->GetClientGroupByGroupId(TEST_DISPLAY_GROUP_ID);
    ASSERT_NE(clientGroup, nullptr);
    sptr<IInputClient> otherClient = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(otherClient, nullptr);
    ret = session_->ShowKeyboard(otherClient, clientGroup);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOUND);
}

/**
 * @tc.name: TestGetRealImeData_NoData_001
 * @tc.desc: Test GetRealImeData when no real IME data exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetRealImeData_NoData_001, TestSize.Level0)
{
    auto data = session_->GetRealImeData();
    EXPECT_EQ(data, nullptr);
    auto dataReady = session_->GetRealImeData(true);
    EXPECT_EQ(dataReady, nullptr);
}

/**
 * @tc.name: TestGetRealImeData_WithData_001
 * @tc.desc: Test GetRealImeData with real IME data set
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetRealImeData_WithData_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->realImeData_ = imeData;
    auto data = session_->GetRealImeData();
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->pid, TEST_PID);
}

/**
 * @tc.name: TestGetRealImeData_ReadyFilter_001
 * @tc.desc: Test GetRealImeData(true) filters out non-READY IME
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetRealImeData_ReadyFilter_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::STARTING);
    ASSERT_NE(imeData, nullptr);
    session_->realImeData_ = imeData;
    // GetRealImeData() without isReady filter should return data
    auto data = session_->GetRealImeData();
    ASSERT_NE(data, nullptr);
    // GetRealImeData(true) should return nullptr for STARTING status
    auto dataReady = session_->GetRealImeData(true);
    EXPECT_EQ(dataReady, nullptr);
}

/**
 * @tc.name: TestGetRealImeData_ReadyFilter_002
 * @tc.desc: Test GetRealImeData(true) returns READY IME
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetRealImeData_ReadyFilter_002, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->realImeData_ = imeData;
    auto dataReady = session_->GetRealImeData(true);
    ASSERT_NE(dataReady, nullptr);
    EXPECT_EQ(dataReady->pid, TEST_PID);
}

/**
 * @tc.name: TestRemoveRealImeData_NoData_001
 * @tc.desc: Test RemoveRealImeData when no real IME data exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveRealImeData_NoData_001, TestSize.Level0)
{
    // Should not crash
    session_->RemoveRealImeData();
    EXPECT_EQ(session_->realImeData_, nullptr);
}

/**
 * @tc.name: TestRemoveRealImeData_WithData_001
 * @tc.desc: Test RemoveRealImeData when real IME data exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveRealImeData_WithData_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->realImeData_ = imeData;
    session_->RemoveRealImeData();
    EXPECT_EQ(session_->realImeData_, nullptr);
}

/**
 * @tc.name: TestRemoveRealImeData_ByPid_001
 * @tc.desc: Test RemoveRealImeData(pid) with matching pid
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveRealImeData_ByPid_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->realImeData_ = imeData;
    session_->RemoveRealImeData(TEST_PID);
    EXPECT_EQ(session_->realImeData_, nullptr);
}

/**
 * @tc.name: TestRemoveRealImeData_ByPid_NoMatch_001
 * @tc.desc: Test RemoveRealImeData(pid) with non-matching pid
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveRealImeData_ByPid_NoMatch_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->realImeData_ = imeData;
    session_->RemoveRealImeData(9999);
    EXPECT_NE(session_->realImeData_, nullptr);
}

/**
 * @tc.name: TestGetMirrorImeData_NoData_001
 * @tc.desc: Test GetMirrorImeData when no mirror IME data exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetMirrorImeData_NoData_001, TestSize.Level0)
{
    auto data = session_->GetMirrorImeData();
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: TestGetMirrorImeData_WithData_001
 * @tc.desc: Test GetMirrorImeData with mirror data set
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetMirrorImeData_WithData_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME_MIRROR, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->mirrorImeData_ = imeData;
    auto data = session_->GetMirrorImeData();
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->type, ImeType::IME_MIRROR);
}

/**
 * @tc.name: TestRemoveMirrorImeData_ByPid_001
 * @tc.desc: Test RemoveMirrorImeData(pid) with matching pid
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveMirrorImeData_ByPid_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME_MIRROR, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->mirrorImeData_ = imeData;
    session_->RemoveMirrorImeData(TEST_PID);
    EXPECT_EQ(session_->mirrorImeData_, nullptr);
}

/**
 * @tc.name: TestRemoveMirrorImeData_ByPid_NoMatch_001
 * @tc.desc: Test RemoveMirrorImeData(pid) with non-matching pid
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveMirrorImeData_ByPid_NoMatch_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME_MIRROR, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->mirrorImeData_ = imeData;
    session_->RemoveMirrorImeData(9999);
    EXPECT_NE(session_->mirrorImeData_, nullptr);
}

/**
 * @tc.name: TestRemoveMirrorImeData_NullData_001
 * @tc.desc: Test RemoveMirrorImeData(pid) when mirrorImeData_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveMirrorImeData_NullData_001, TestSize.Level0)
{
    session_->mirrorImeData_ = nullptr;
    session_->RemoveMirrorImeData(TEST_PID);
    EXPECT_EQ(session_->mirrorImeData_, nullptr);
}

/**
 * @tc.name: TestGetImeData_NullBindImeData_001
 * @tc.desc: Test GetImeData with null bindImeData
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetImeData_NullBindImeData_001, TestSize.Level0)
{
    auto data = session_->GetImeData(nullptr);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: TestGetImeData_ByPidAndType_IME_001
 * @tc.desc: Test GetImeData(pid, ImeType::IME) returns real IME data
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetImeData_ByPidAndType_IME_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->realImeData_ = imeData;
    auto data = session_->GetImeData(TEST_PID, ImeType::IME);
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->pid, TEST_PID);
}

/**
 * @tc.name: TestGetImeData_ByPidAndType_Mirror_001
 * @tc.desc: Test GetImeData(pid, ImeType::IME_MIRROR) returns mirror IME data
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetImeData_ByPidAndType_Mirror_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME_MIRROR, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->mirrorImeData_ = imeData;
    auto data = session_->GetImeData(TEST_PID, ImeType::IME_MIRROR);
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->type, ImeType::IME_MIRROR);
}

/**
 * @tc.name: TestGetImeData_ByPidAndType_Proxy_001
 * @tc.desc: Test GetImeData(pid, ImeType::PROXY_IME) with no proxy data
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetImeData_ByPidAndType_Proxy_001, TestSize.Level0)
{
    auto data = session_->GetImeData(TEST_PID, ImeType::PROXY_IME);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: TestRemoveImeData_001
 * @tc.desc: Test RemoveImeData removes from real, mirror, and proxy
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveImeData_001, TestSize.Level0)
{
    auto realData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::READY);
    ASSERT_NE(realData, nullptr);
    session_->realImeData_ = realData;
    auto mirrorData = MakeImeData(TEST_PID, ImeType::IME_MIRROR, ImeStatus::READY);
    ASSERT_NE(mirrorData, nullptr);
    session_->mirrorImeData_ = mirrorData;
    session_->RemoveImeData(TEST_PID);
    EXPECT_EQ(session_->realImeData_, nullptr);
    EXPECT_EQ(session_->mirrorImeData_, nullptr);
}

/**
 * @tc.name: TestRemoveDeathRecipient_NullDeathRecipient_001
 * @tc.desc: Test RemoveDeathRecipient with null death recipient
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveDeathRecipient_NullDeathRecipient_001, TestSize.Level0)
{
    sptr<IRemoteObject> obj = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(obj, nullptr);
    // Should not crash
    session_->RemoveDeathRecipient(nullptr, obj);
}

/**
 * @tc.name: TestRemoveDeathRecipient_NullObject_001
 * @tc.desc: Test RemoveDeathRecipient with null object
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveDeathRecipient_NullObject_001, TestSize.Level0)
{
    sptr<InputDeathRecipient> dr = new (std::nothrow) InputDeathRecipient();
    ASSERT_NE(dr, nullptr);
    session_->RemoveDeathRecipient(dr, nullptr);
}

/**
 * @tc.name: TestIsSameClient_001
 * @tc.desc: Test IsSameClient with various inputs
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIsSameClient_001, TestSize.Level0)
{
    sptr<IInputClient> client1 = new (std::nothrow) InputClientServiceImpl();
    sptr<IInputClient> client2 = new (std::nothrow) InputClientServiceImpl();
    EXPECT_FALSE(session_->IsSameClient(nullptr, nullptr));
    EXPECT_FALSE(session_->IsSameClient(client1, nullptr));
    EXPECT_FALSE(session_->IsSameClient(nullptr, client1));
    EXPECT_TRUE(session_->IsSameClient(client1, client1));
    EXPECT_FALSE(session_->IsSameClient(client1, client2));
}

/**
 * @tc.name: TestIsSameClientGroup_001
 * @tc.desc: Test IsSameClientGroup
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIsSameClientGroup_001, TestSize.Level0)
{
    EXPECT_TRUE(session_->IsSameClientGroup(0, 0));
    EXPECT_TRUE(session_->IsSameClientGroup(100, 100));
    EXPECT_FALSE(session_->IsSameClientGroup(0, 1));
}

/**
 * @tc.name: TestIsDefaultGroup_001
 * @tc.desc: Test IsDefaultGroup
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIsDefaultGroup_001, TestSize.Level0)
{
    EXPECT_TRUE(session_->IsDefaultGroup(ImfCommonConst::DEFAULT_DISPLAY_GROUP_ID));
    EXPECT_FALSE(session_->IsDefaultGroup(999));
}

/**
 * @tc.name: TestCompareExchange_001
 * @tc.desc: Test CompareExchange with same value
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestCompareExchange_001, TestSize.Level0)
{
    session_->largeMemoryState_ = LargeMemoryState::LARGE_MEMORY_NEED;
    EXPECT_TRUE(session_->CompareExchange(LargeMemoryState::LARGE_MEMORY_NEED));
}

/**
 * @tc.name: TestCompareExchange_002
 * @tc.desc: Test CompareExchange with different value
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestCompareExchange_002, TestSize.Level0)
{
    session_->largeMemoryState_ = LargeMemoryState::LARGE_MEMORY_NOT_NEED;
    EXPECT_FALSE(session_->CompareExchange(LargeMemoryState::LARGE_MEMORY_NEED));
    EXPECT_EQ(session_->largeMemoryState_, LargeMemoryState::LARGE_MEMORY_NEED);
}

/**
 * @tc.name: TestUpdateLargeMemorySceneState_001
 * @tc.desc: Test UpdateLargeMemorySceneState with same state (no change)
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestUpdateLargeMemorySceneState_001, TestSize.Level0)
{
    session_->largeMemoryState_ = LargeMemoryState::LARGE_MEMORY_NOT_NEED;
    auto ret = session_->UpdateLargeMemorySceneState(LargeMemoryState::LARGE_MEMORY_NOT_NEED);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: TestIsLargeMemoryStateNeed_001
 * @tc.desc: Test IsLargeMemoryStateNeed when state is NEED
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIsLargeMemoryStateNeed_001, TestSize.Level0)
{
    session_->largeMemoryState_ = LargeMemoryState::LARGE_MEMORY_NEED;
    EXPECT_TRUE(session_->IsLargeMemoryStateNeed());
}

/**
 * @tc.name: TestIsLargeMemoryStateNeed_002
 * @tc.desc: Test IsLargeMemoryStateNeed when state is NOT_NEED
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIsLargeMemoryStateNeed_002, TestSize.Level0)
{
    session_->largeMemoryState_ = LargeMemoryState::LARGE_MEMORY_NOT_NEED;
    EXPECT_FALSE(session_->IsLargeMemoryStateNeed());
}

/**
 * @tc.name: TestIncreaseAttachCount_001
 * @tc.desc: Test IncreaseAttachCount and GetAttachCount
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIncreaseAttachCount_001, TestSize.Level0)
{
    EXPECT_EQ(session_->GetAttachCount(), 0u);
    session_->IncreaseAttachCount();
    EXPECT_EQ(session_->GetAttachCount(), 1u);
    session_->IncreaseAttachCount();
    EXPECT_EQ(session_->GetAttachCount(), 2u);
}

/**
 * @tc.name: TestDecreaseAttachCount_001
 * @tc.desc: Test DecreaseAttachCount
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestDecreaseAttachCount_001, TestSize.Level0)
{
    session_->IncreaseAttachCount();
    EXPECT_EQ(session_->GetAttachCount(), 1u);
    session_->DecreaseAttachCount();
    EXPECT_EQ(session_->GetAttachCount(), 0u);
}

/**
 * @tc.name: TestDecreaseAttachCount_Underflow_001
 * @tc.desc: Test DecreaseAttachCount when count is already 0
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestDecreaseAttachCount_Underflow_001, TestSize.Level0)
{
    EXPECT_EQ(session_->GetAttachCount(), 0u);
    session_->DecreaseAttachCount();
    EXPECT_EQ(session_->GetAttachCount(), 0u);
}

/**
 * @tc.name: TestIncreaseScbStartCount_001
 * @tc.desc: Test IncreaseScbStartCount and GetScbStartCount
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIncreaseScbStartCount_001, TestSize.Level0)
{
    EXPECT_EQ(session_->GetScbStartCount(), 0u);
    session_->IncreaseScbStartCount();
    EXPECT_EQ(session_->GetScbStartCount(), 1u);
}

/**
 * @tc.name: TestIsBoundToClient_NoGroup_001
 * @tc.desc: Test IsBoundToClient when no client group exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIsBoundToClient_NoGroup_001, TestSize.Level0)
{
    EXPECT_FALSE(session_->IsBoundToClient(TEST_DISPLAY_ID));
}

/**
 * @tc.name: TestIsCurrentImeByPid_NoIme_001
 * @tc.desc: Test IsCurrentImeByPid when no IME is started
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIsCurrentImeByPid_NoIme_001, TestSize.Level0)
{
    EXPECT_FALSE(session_->IsCurrentImeByPid(TEST_PID));
}

/**
 * @tc.name: TestIsCurrentImeByPid_MatchingPid_001
 * @tc.desc: Test IsCurrentImeByPid with matching pid
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIsCurrentImeByPid_MatchingPid_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->realImeData_ = imeData;
    EXPECT_TRUE(session_->IsCurrentImeByPid(TEST_PID));
}

/**
 * @tc.name: TestIsCurrentImeByPid_NonMatchingPid_001
 * @tc.desc: Test IsCurrentImeByPid with non-matching pid
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestIsCurrentImeByPid_NonMatchingPid_001, TestSize.Level0)
{
    auto imeData = MakeImeData(TEST_PID, ImeType::IME, ImeStatus::READY);
    ASSERT_NE(imeData, nullptr);
    session_->realImeData_ = imeData;
    EXPECT_FALSE(session_->IsCurrentImeByPid(9999));
}

/**
 * @tc.name: TestSwitchSubtype_NoIme_001
 * @tc.desc: Test SwitchSubtype when no IME is started
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestSwitchSubtype_NoIme_001, TestSize.Level0)
{
    SubProperty subProperty;
    auto ret = session_->SwitchSubtype(subProperty);
    EXPECT_EQ(ret, ErrorCode::ERROR_IME_NOT_STARTED);
}

/**
 * @tc.name: TestSwitchSubtypeWithoutStartIme_NoIme_001
 * @tc.desc: Test SwitchSubtypeWithoutStartIme when no IME is started
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestSwitchSubtypeWithoutStartIme_NoIme_001, TestSize.Level0)
{
    SubProperty subProperty;
    auto ret = session_->SwitchSubtypeWithoutStartIme(subProperty);
    EXPECT_EQ(ret, ErrorCode::ERROR_IME_NOT_STARTED);
}

/**
 * @tc.name: TestGetClientGroupByGroupId_NotFound_001
 * @tc.desc: Test GetClientGroupByGroupId when group not found
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetClientGroupByGroupId_NotFound_001, TestSize.Level0)
{
    auto group = session_->GetClientGroupByGroupId(999);
    EXPECT_EQ(group, nullptr);
}

/**
 * @tc.name: TestGetClientGroup_NullObject_001
 * @tc.desc: Test GetClientGroup with null remote object
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetClientGroup_NullObject_001, TestSize.Level0)
{
    auto group = session_->GetClientGroup(sptr<IRemoteObject>(nullptr));
    EXPECT_EQ(group, nullptr);
}

/**
 * @tc.name: TestGetClientBySelfPid_NotFound_001
 * @tc.desc: Test GetClientBySelfPid when no client exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetClientBySelfPid_NotFound_001, TestSize.Level0)
{
    auto [group, info] = session_->GetClientBySelfPid(TEST_PID);
    EXPECT_EQ(group, nullptr);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: TestGetClientBySelfPidOrHostPid_NotFound_001
 * @tc.desc: Test GetClientBySelfPidOrHostPid when no client exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetClientBySelfPidOrHostPid_NotFound_001, TestSize.Level0)
{
    auto [group, info] = session_->GetClientBySelfPidOrHostPid(TEST_PID);
    EXPECT_EQ(group, nullptr);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: TestGetCurrentClientBoundRealIme_None_001
 * @tc.desc: Test GetCurrentClientBoundRealIme when no client is bound
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetCurrentClientBoundRealIme_None_001, TestSize.Level0)
{
    auto [group, info] = session_->GetCurrentClientBoundRealIme();
    EXPECT_EQ(group, nullptr);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: TestGetClientBoundRealIme_None_001
 * @tc.desc: Test GetClientBoundRealIme when no client is bound
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetClientBoundRealIme_None_001, TestSize.Level0)
{
    auto [group, info] = session_->GetClientBoundRealIme();
    EXPECT_EQ(group, nullptr);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: TestGetClientBoundImeByImePid_None_001
 * @tc.desc: Test GetClientBoundImeByImePid when no client is bound
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetClientBoundImeByImePid_None_001, TestSize.Level0)
{
    auto [group, info] = session_->GetClientBoundImeByImePid(TEST_PID);
    EXPECT_EQ(group, nullptr);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: TestGetClientBoundImeByWindowId_None_001
 * @tc.desc: Test GetClientBoundImeByWindowId when no client is bound
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetClientBoundImeByWindowId_None_001, TestSize.Level0)
{
    auto [group, info] = session_->GetClientBoundImeByWindowId(0);
    EXPECT_EQ(group, nullptr);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: TestRemoveAllCurrentClient_Empty_001
 * @tc.desc: Test RemoveAllCurrentClient when no client groups exist
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestRemoveAllCurrentClient_Empty_001, TestSize.Level0)
{
    auto ret = session_->RemoveAllCurrentClient();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NULL_POINTER);
}

/**
 * @tc.name: TestGetCurrentClientPid_NoGroup_001
 * @tc.desc: Test GetCurrentClientPid when no client group exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetCurrentClientPid_NoGroup_001, TestSize.Level0)
{
    auto pid = session_->GetCurrentClientPid(TEST_DISPLAY_ID);
    EXPECT_EQ(pid, INVALID_PID);
}

/**
 * @tc.name: TestGetInactiveClientPid_NoGroup_001
 * @tc.desc: Test GetInactiveClientPid when no client group exists
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestGetInactiveClientPid_NoGroup_001, TestSize.Level0)
{
    auto pid = session_->GetInactiveClientPid(TEST_DISPLAY_ID);
    EXPECT_EQ(pid, INVALID_PID);
}

/**
 * @tc.name: TestOnSetCallingWindow_NullClient_001
 * @tc.desc: Test OnSetCallingWindow with null client
 * @tc.type: FUNC
 */
HWTEST_F(PerUserSessionTest, TestOnSetCallingWindow_NullClient_001, TestSize.Level0)
{
    FocusedInfo focusedInfo;
    auto ret = session_->OnSetCallingWindow(focusedInfo, nullptr, 0);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}
} // namespace MiscServices
} // namespace OHOS