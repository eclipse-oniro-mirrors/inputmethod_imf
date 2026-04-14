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

#define private public
#define protected public
#include "ime_system_channel.h"
#include "system_cmd_channel_service_impl.h"
#undef private
#include <gtest/gtest.h>

#include "identity_checker_mock.h"
#include "scope_utils.h"
#include "tdd_util.h"
using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
class OnSystemCmdListenerImpl : public OnSystemCmdListener {
    void ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) override { }
    void NotifyPanelStatus(const SysPanelStatus &sysPanelStatus) override { }
};
class ImeSystemChannelTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static sptr<ImeSystemCmdChannel> imeSystemChannel_;
    static sptr<SystemCmdChannelServiceImpl> systemCmdChannelServiceImpl_;
    static sptr<OnSystemCmdListener> sysCmdListener_;
    static uint64_t permissionTokenId_;
};
sptr<ImeSystemCmdChannel> ImeSystemChannelTest::imeSystemChannel_;
sptr<OnSystemCmdListener> ImeSystemChannelTest::sysCmdListener_;
sptr<SystemCmdChannelServiceImpl> ImeSystemChannelTest::systemCmdChannelServiceImpl_;
uint64_t ImeSystemChannelTest::permissionTokenId_ = 0;

void ImeSystemChannelTest::SetUpTestCase(void)
{
    TddUtil::StorageSelfTokenID();
    imeSystemChannel_ = ImeSystemCmdChannel::GetInstance();
    systemCmdChannelServiceImpl_ = new (std::nothrow) SystemCmdChannelServiceImpl();
    sysCmdListener_ = new (std::nothrow) OnSystemCmdListenerImpl();
    permissionTokenId_ =
        TddUtil::AllocTestTokenID(true, "ohos.inputMethod.test", { "ohos.permission.CONNECT_IME_ABILITY" });
}

void ImeSystemChannelTest::TearDownTestCase(void)
{
    IMSA_HILOGI("ImeSystemChannelTest::TearDownTestCase");
    imeSystemChannel_->ConnectSystemCmd(nullptr);
    imeSystemChannel_->ClearSystemCmdAgent();
    TddUtil::RestoreSelfTokenID();
}

void ImeSystemChannelTest::SetUp(void)
{
    IMSA_HILOGI("ImeSystemChannelTest::SetUp");
}

void ImeSystemChannelTest::TearDown(void)
{
    IMSA_HILOGI("ImeSystemChannelTest::TearDown");
}

/**
 * @tc.name: testConnectSystemCmd001
 * @tc.desc: SystemCmdChannel ConnectSystemCmd.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testConnectSystemCmd001, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testConnectSystemCmd001 Test START");
    auto ret = imeSystemChannel_->ConnectSystemCmd(sysCmdListener_);
    EXPECT_EQ(ret, ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION);
}

/**
 * @tc.name: testConnectSystemCmd002
 * @tc.desc: SystemCmdChannel ConnectSystemCmd.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testConnectSystemCmd002, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testConnectSystemCmd002 Test START");
    TokenScope scope(ImeSystemChannelTest::permissionTokenId_);
    auto ret = imeSystemChannel_->ConnectSystemCmd(sysCmdListener_);
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);
}

/**
 * @tc.name: testSendPrivateCommand001
 * @tc.desc: SystemCmdChannel SendPrivateCommand without agent (should return ERROR_CLIENT_NOT_BOUND)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testSendPrivateCommand001, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testSendPrivateCommand001 Test START");
    TokenScope scope(ImeSystemChannelTest::permissionTokenId_);
    // Ensure no agent is set
    imeSystemChannel_->ClearSystemCmdAgent();
    // Prepare test data: empty command map
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    // Verify that SendPrivateCommand returns ERROR_CLIENT_NOT_BOUND when agent is nullptr
    auto ret = imeSystemChannel_->SendPrivateCommand(privateCommand);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
}

/**
 * @tc.name: testImeSystemChannel_nullptr
 * @tc.desc: SystemCmdChannel ReceivePrivateCommand.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testImeSystemChannel_nullptr, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testImeSystemChannel_nullptr Test START");
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = std::string("stringValue");
    privateCommand.emplace("value1", privateDataValue1);
    imeSystemChannel_->systemCmdListener_ = nullptr;
    imeSystemChannel_->OnConnectCmdReady(nullptr);
    imeSystemChannel_->GetSmartMenuConfig();
    int32_t ret = imeSystemChannel_->ReceivePrivateCommand(privateCommand);
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_NULL_POINTER);
    ret = imeSystemChannel_->NotifyPanelStatus({ InputType::NONE, 0, 0, 0 });
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);
}

/**
 * @tc.name: testSystemCmdChannelServiceImpl
 * @tc.desc: SystemCmdChannel test SystemCmdChannelServiceImpl is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testSystemCmdChannelServiceImpl_nullptr, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testSystemCmdChannelServiceImpl_nullptr Test START");
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = std::string("stringValue");
    privateCommand.emplace("value1", privateDataValue1);
    int32_t ret = systemCmdChannelServiceImpl_->SendPrivateCommand(privateCommand);
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_NULL_POINTER);
    ret = systemCmdChannelServiceImpl_->NotifyPanelStatus({ InputType::NONE, 0, 0, 0 });
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);
}
/**
 * @tc.name: testIsSystemApp001
 * @tc.desc: Test IsSystemApp with first call returning false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsSystemApp001, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsSystemApp002 TEST START");
    auto ret = imeSystemChannel_->IsSystemApp();
    EXPECT_FALSE(ret);
    TokenScope scope(ImeSystemChannelTest::permissionTokenId_);
    ret = imeSystemChannel_->IsSystemApp();
    EXPECT_TRUE(ret);
    auto ret1 = imeSystemChannel_->IsSystemApp();
    EXPECT_EQ(ret, ret1);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_001
 * @tc.desc: Test IsUserPrivateCommandValid with empty command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_001, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_001 Test START");
    // Prepare test data: empty command map
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    // Verify that empty command returns false
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_002
 * @tc.desc: Test IsUserPrivateCommandValid with 6 commands (exceeds limit)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_002, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_002 Test START");
    // Prepare test data: 6 commands (exceeds MAX_PRIVATE_COMMAND_COUNT which is 5)
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = std::string("testValue");
    privateCommand.emplace("key1", privateDataValue1);
    privateCommand.emplace("key2", privateDataValue1);
    privateCommand.emplace("key3", privateDataValue1);
    privateCommand.emplace("key4", privateDataValue1);
    privateCommand.emplace("key5", privateDataValue1);
    privateCommand.emplace("key6", privateDataValue1);
    // Verify that 6 commands returns false (exceeds limit)
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_003
 * @tc.desc: Test IsUserPrivateCommandValid with 1 string command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_003, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_003 Test START");
    // Prepare test data: 1 command with string type
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = std::string("testStringValue");
    privateCommand.emplace("stringKey", privateDataValue1);
    // Verify that 1 string command returns true
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_004
 * @tc.desc: Test IsUserPrivateCommandValid with 1 bool command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_004, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_004 Test START");
    // Prepare test data: 1 command with bool type
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = true;
    privateCommand.emplace("boolKey", privateDataValue1);
    // Verify that 1 bool command returns true
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_005
 * @tc.desc: Test IsUserPrivateCommandValid with 1 int32 command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_005, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_005 Test START");
    // Prepare test data: 1 command with int32 type
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = 12345;
    privateCommand.emplace("intKey", privateDataValue1);
    // Verify that 1 int32 command returns true
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_006
 * @tc.desc: Test IsUserPrivateCommandValid with command exceeding 32KB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_006, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_006 Test START");
    // Prepare test data: 1 command with size exceeding 32KB (32 * 1024 + 1 bytes)
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    std::string largeString(32 * 1024 + 1, 'a');
    PrivateDataValue privateDataValue1 = largeString;
    privateCommand.emplace("largeKey", privateDataValue1);
    // Verify that command exceeding 32KB returns false
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_007
 * @tc.desc: Test IsUserPrivateCommandValid with 5 commands at 32KB boundary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_007, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_007 Test START");
    // Prepare test data: 5 commands with total size at 32KB boundary
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    // Each string approximately (32 * 1024 - 20) / 5 = ~6551 bytes for 5 keys (key1-key5 = 20 chars total)
    std::string largeString((32 * 1024 - 20) / 5, 'a');
    PrivateDataValue privateDataValue1 = largeString;
    privateCommand.emplace("key1", privateDataValue1);
    privateCommand.emplace("key2", privateDataValue1);
    privateCommand.emplace("key3", privateDataValue1);
    privateCommand.emplace("key4", privateDataValue1);
    privateCommand.emplace("key5", privateDataValue1);
    // Verify that 5 commands at 32KB boundary returns true
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_008
 * @tc.desc: Test IsUserPrivateCommandValid with mixed types (string, bool, int32)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_008, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_008 Test START");
    // Prepare test data: 3 commands with different types (string, bool, int32)
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = std::string("testString");
    PrivateDataValue privateDataValue2 = false;
    PrivateDataValue privateDataValue3 = 67890;
    privateCommand.emplace("stringKey", privateDataValue1);
    privateCommand.emplace("boolKey", privateDataValue2);
    privateCommand.emplace("intKey", privateDataValue3);
    // Verify that mixed type commands returns true
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_009
 * @tc.desc: Test IsUserPrivateCommandValid with 5 commands exceeding 32KB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_009, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_009 Test START");
    // Prepare test data: 5 commands with total size exceeding 32KB
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    // Each string approximately (32 * 1024) / 5 + 10 = ~6555 bytes, ensuring total exceeds 32KB
    std::string largeString((32 * 1024) / 5 + 10, 'b');
    PrivateDataValue privateDataValue1 = largeString;
    privateCommand.emplace("k1", privateDataValue1);
    privateCommand.emplace("k2", privateDataValue1);
    privateCommand.emplace("k3", privateDataValue1);
    privateCommand.emplace("k4", privateDataValue1);
    privateCommand.emplace("k5", privateDataValue1);
    // Verify that 5 commands exceeding 32KB returns false
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: testIsUserPrivateCommandValid_010
 * @tc.desc: Test IsUserPrivateCommandValid with 5 commands exactly at limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelTest, testIsUserPrivateCommandValid_010, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelTest testIsUserPrivateCommandValid_010 Test START");
    // Prepare test data: 5 commands with normal size (at count limit but within size limit)
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = std::string("normalValue");
    PrivateDataValue privateDataValue2 = true;
    PrivateDataValue privateDataValue3 = 111;
    PrivateDataValue privateDataValue4 = std::string("anotherValue");
    PrivateDataValue privateDataValue5 = false;
    privateCommand.emplace("key1", privateDataValue1);
    privateCommand.emplace("key2", privateDataValue2);
    privateCommand.emplace("key3", privateDataValue3);
    privateCommand.emplace("key4", privateDataValue4);
    privateCommand.emplace("key5", privateDataValue5);
    // Verify that 5 commands at count limit returns true
    bool result = imeSystemChannel_->IsUserPrivateCommandValid(privateCommand);
    EXPECT_EQ(result, true);
}
} // namespace MiscServices
} // namespace OHOS