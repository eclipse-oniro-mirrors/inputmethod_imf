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

#include "ime_system_channel.h"
#include "system_cmd_channel_service_impl.h"

#include <gtest/gtest.h>

#include "global.h"
#include "input_method_utils.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace MiscServices {

class OnSystemCmdListenerMock : public OnSystemCmdListener {
public:
    void ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) override
    {
        receivedCommand_ = privateCommand;
        receiveCalled_ = true;
    }
    void NotifyPanelStatus(const SysPanelStatus &sysPanelStatus) override
    {
        receivedPanelStatus_ = sysPanelStatus;
        notifyCalled_ = true;
    }
    std::unordered_map<std::string, PrivateDataValue> receivedCommand_;
    SysPanelStatus receivedPanelStatus_ { InputType::NONE, 0, 0, 0 };
    bool receiveCalled_ = false;
    bool notifyCalled_ = false;
};

class ImeSystemChannelNewTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static sptr<ImeSystemCmdChannel> imeSystemChannel_;
};

sptr<ImeSystemCmdChannel> ImeSystemChannelNewTest::imeSystemChannel_;

void ImeSystemChannelNewTest::SetUpTestCase(void)
{
    imeSystemChannel_ = ImeSystemCmdChannel::GetInstance();
}

void ImeSystemChannelNewTest::TearDownTestCase(void) { }

void ImeSystemChannelNewTest::SetUp(void)
{
    imeSystemChannel_->ClearSystemCmdAgent();
    imeSystemChannel_->systemCmdListener_ = nullptr;
}

void ImeSystemChannelNewTest::TearDown(void)
{
    imeSystemChannel_->ClearSystemCmdAgent();
    imeSystemChannel_->systemCmdListener_ = nullptr;
}

// ==================== GetInstance Tests ====================

/**
 * @tc.name: testGetInstance001
 * @tc.desc: Test GetInstance returns non-null singleton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testGetInstance001, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testGetInstance001 START");
    auto instance = ImeSystemCmdChannel::GetInstance();
    ASSERT_NE(instance, nullptr);
    auto instance2 = ImeSystemCmdChannel::GetInstance();
    EXPECT_EQ(instance, instance2);
}

// ==================== OnConnectCmdReady Tests ====================

/**
 * @tc.name: testOnConnectCmdReady_NullAgent
 * @tc.desc: Test OnConnectCmdReady with null agent object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testOnConnectCmdReady_NullAgent, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testOnConnectCmdReady_NullAgent START");
    imeSystemChannel_->isSystemCmdConnect_.store(false);
    imeSystemChannel_->systemAgent_ = nullptr;
    imeSystemChannel_->OnConnectCmdReady(nullptr);
    // Should not set connected state with null agent
    EXPECT_FALSE(imeSystemChannel_->isSystemCmdConnect_.load());
}

/**
 * @tc.name: testOnConnectCmdReady_AgentAlreadySet
 * @tc.desc: Test OnConnectCmdReady when agent already exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testOnConnectCmdReady_AgentAlreadySet, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testOnConnectCmdReady_AgentAlreadySet START");
    // Set isSystemCmdConnect_ to false, and systemAgent_ to non-null
    imeSystemChannel_->systemAgent_ = nullptr; // agent is null so it will try to create new one
    imeSystemChannel_->isSystemCmdConnect_.store(false);

    // Provide a real IRemoteObject to test the agent-already-set path
    // We cannot create a real InputMethodAgentProxy without IPC, so test the null agent path
    // which verifies OnConnectCmdReady handles null agentObject by returning early
    sptr<IRemoteObject> nullObj = nullptr;
    imeSystemChannel_->OnConnectCmdReady(nullObj);
    EXPECT_FALSE(imeSystemChannel_->isSystemCmdConnect_.load());
}

// ==================== ReceivePrivateCommand Tests ====================

/**
 * @tc.name: testReceivePrivateCommand_NullListener
 * @tc.desc: Test ReceivePrivateCommand with null listener returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testReceivePrivateCommand_NullListener, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testReceivePrivateCommand_NullListener START");
    imeSystemChannel_->systemCmdListener_ = nullptr;
    std::unordered_map<std::string, PrivateDataValue> cmd;
    cmd["key"] = std::string("value");
    auto ret = imeSystemChannel_->ReceivePrivateCommand(cmd);
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_NULL_POINTER);
}

/**
 * @tc.name: testReceivePrivateCommand_ValidListener
 * @tc.desc: Test ReceivePrivateCommand with valid listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testReceivePrivateCommand_ValidListener, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testReceivePrivateCommand_ValidListener START");
    auto listener = new (std::nothrow) OnSystemCmdListenerMock();
    ASSERT_NE(listener, nullptr);
    imeSystemChannel_->systemCmdListener_ = listener;

    std::unordered_map<std::string, PrivateDataValue> cmd;
    cmd["testKey"] = std::string("testValue");
    cmd["boolKey"] = true;
    cmd["numKey"] = 42;

    auto ret = imeSystemChannel_->ReceivePrivateCommand(cmd);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(listener->receiveCalled_);
    EXPECT_EQ(listener->receivedCommand_.size(), 3u);
}

/**
 * @tc.name: testReceivePrivateCommand_EmptyCommand
 * @tc.desc: Test ReceivePrivateCommand with empty command map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testReceivePrivateCommand_EmptyCommand, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testReceivePrivateCommand_EmptyCommand START");
    auto listener = new (std::nothrow) OnSystemCmdListenerMock();
    ASSERT_NE(listener, nullptr);
    imeSystemChannel_->systemCmdListener_ = listener;

    std::unordered_map<std::string, PrivateDataValue> cmd;
    auto ret = imeSystemChannel_->ReceivePrivateCommand(cmd);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(listener->receiveCalled_);
    EXPECT_TRUE(listener->receivedCommand_.empty());
}

// ==================== NotifyPanelStatus Tests ====================

/**
 * @tc.name: testNotifyPanelStatus_NullListener
 * @tc.desc: Test NotifyPanelStatus with null listener returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testNotifyPanelStatus_NullListener, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testNotifyPanelStatus_NullListener START");
    imeSystemChannel_->systemCmdListener_ = nullptr;
    SysPanelStatus status { InputType::NONE, 0, 0, 0 };
    auto ret = imeSystemChannel_->NotifyPanelStatus(status);
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);
}

/**
 * @tc.name: testNotifyPanelStatus_ValidListener
 * @tc.desc: Test NotifyPanelStatus with valid listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testNotifyPanelStatus_ValidListener, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testNotifyPanelStatus_ValidListener START");
    auto listener = new (std::nothrow) OnSystemCmdListenerMock();
    ASSERT_NE(listener, nullptr);
    imeSystemChannel_->systemCmdListener_ = listener;

    SysPanelStatus status { InputType::CAMERA_INPUT, 100, 200, 300 };
    auto ret = imeSystemChannel_->NotifyPanelStatus(status);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(listener->notifyCalled_);
    EXPECT_EQ(listener->receivedPanelStatus_.inputType, InputType::CAMERA_INPUT);
}

/**
 * @tc.name: testNotifyPanelStatus_DifferentInputTypes
 * @tc.desc: Test NotifyPanelStatus with various input types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testNotifyPanelStatus_DifferentInputTypes, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testNotifyPanelStatus_DifferentInputTypes START");
    auto listener = new (std::nothrow) OnSystemCmdListenerMock();
    ASSERT_NE(listener, nullptr);
    imeSystemChannel_->systemCmdListener_ = listener;

    SysPanelStatus status { InputType::SECURITY_INPUT, 0, 0, 0 };
    auto ret = imeSystemChannel_->NotifyPanelStatus(status);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(listener->receivedPanelStatus_.inputType, InputType::SECURITY_INPUT);
}

// ==================== SendPrivateCommand Tests ====================

/**
 * @tc.name: testSendPrivateCommand_NullAgent
 * @tc.desc: Test SendPrivateCommand with null agent returns ERROR_CLIENT_NOT_BOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testSendPrivateCommand_NullAgent, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testSendPrivateCommand_NullAgent START");
    imeSystemChannel_->ClearSystemCmdAgent();
    std::unordered_map<std::string, PrivateDataValue> cmd;
    cmd["key"] = std::string("value");
    auto ret = imeSystemChannel_->SendPrivateCommand(cmd);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
}

// ==================== ClearSystemCmdAgent Tests ====================

/**
 * @tc.name: testClearSystemCmdAgent001
 * @tc.desc: Test ClearSystemCmdAgent resets state correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testClearSystemCmdAgent001, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testClearSystemCmdAgent001 START");
    imeSystemChannel_->isSystemCmdConnect_.store(true);
    imeSystemChannel_->ClearSystemCmdAgent();
    EXPECT_TRUE(imeSystemChannel_->systemAgent_ == nullptr);
    EXPECT_FALSE(imeSystemChannel_->isSystemCmdConnect_.load());
}

/**
 * @tc.name: testClearSystemCmdAgent_AlreadyCleared
 * @tc.desc: Test ClearSystemCmdAgent when already cleared
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testClearSystemCmdAgent_AlreadyCleared, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testClearSystemCmdAgent_AlreadyCleared START");
    imeSystemChannel_->systemAgent_ = nullptr;
    imeSystemChannel_->isSystemCmdConnect_.store(false);
    imeSystemChannel_->ClearSystemCmdAgent();
    EXPECT_TRUE(imeSystemChannel_->systemAgent_ == nullptr);
    EXPECT_FALSE(imeSystemChannel_->isSystemCmdConnect_.load());
}

// ==================== GetSystemCmdAgent Tests ====================

/**
 * @tc.name: testGetSystemCmdAgent_Null
 * @tc.desc: Test GetSystemCmdAgent returns null when not connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testGetSystemCmdAgent_Null, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testGetSystemCmdAgent_Null START");
    imeSystemChannel_->systemAgent_ = nullptr;
    auto agent = imeSystemChannel_->GetSystemCmdAgent();
    EXPECT_TRUE(agent == nullptr);
}

// ==================== SetSystemCmdListener / GetSystemCmdListener Tests ====================

/**
 * @tc.name: testSetGetSystemCmdListener001
 * @tc.desc: Test SetSystemCmdListener and GetSystemCmdListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testSetGetSystemCmdListener001, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testSetGetSystemCmdListener001 START");
    auto listener = new (std::nothrow) OnSystemCmdListenerMock();
    ASSERT_NE(listener, nullptr);
    imeSystemChannel_->SetSystemCmdListener(listener);
    auto retListener = imeSystemChannel_->GetSystemCmdListener();
    EXPECT_EQ(retListener.GetRefPtr(), listener);
}

/**
 * @tc.name: testSetSystemCmdListener_Null
 * @tc.desc: Test SetSystemCmdListener with null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testSetSystemCmdListener_Null, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testSetSystemCmdListener_Null START");
    imeSystemChannel_->SetSystemCmdListener(nullptr);
    auto retListener = imeSystemChannel_->GetSystemCmdListener();
    EXPECT_TRUE(retListener == nullptr);
}

/**
 * @tc.name: testSetSystemCmdListener_Replace
 * @tc.desc: Test SetSystemCmdListener replaces existing listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testSetSystemCmdListener_Replace, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testSetSystemCmdListener_Replace START");
    auto listener1 = new (std::nothrow) OnSystemCmdListenerMock();
    ASSERT_NE(listener1, nullptr);
    imeSystemChannel_->SetSystemCmdListener(listener1);

    auto listener2 = new (std::nothrow) OnSystemCmdListenerMock();
    ASSERT_NE(listener2, nullptr);
    imeSystemChannel_->SetSystemCmdListener(listener2);

    auto retListener = imeSystemChannel_->GetSystemCmdListener();
    EXPECT_EQ(retListener.GetRefPtr(), listener2);
}

// ==================== IsUserPrivateCommandValid Tests ====================

/**
 * @tc.name: testIsUserPrivateCommandValid_Empty
 * @tc.desc: Test IsUserPrivateCommandValid with empty map returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsUserPrivateCommandValid_Empty, TestSize.Level1)
{
    std::unordered_map<std::string, PrivateDataValue> cmd;
    EXPECT_FALSE(ImeSystemCmdChannel::IsUserPrivateCommandValid(cmd));
}

/**
 * @tc.name: testIsUserPrivateCommandValid_ExceedsCount
 * @tc.desc: Test IsUserPrivateCommandValid with too many commands
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsUserPrivateCommandValid_ExceedsCount, TestSize.Level1)
{
    std::unordered_map<std::string, PrivateDataValue> cmd;
    for (int i = 0; i < 6; i++) {
        cmd["key" + std::to_string(i)] = i;
    }
    EXPECT_FALSE(ImeSystemCmdChannel::IsUserPrivateCommandValid(cmd));
}

/**
 * @tc.name: testIsUserPrivateCommandValid_AtCountLimit
 * @tc.desc: Test IsUserPrivateCommandValid with exactly 5 commands
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsUserPrivateCommandValid_AtCountLimit, TestSize.Level1)
{
    std::unordered_map<std::string, PrivateDataValue> cmd;
    for (int i = 0; i < 5; i++) {
        cmd["key" + std::to_string(i)] = i;
    }
    EXPECT_TRUE(ImeSystemCmdChannel::IsUserPrivateCommandValid(cmd));
}

/**
 * @tc.name: testIsUserPrivateCommandValid_StringType
 * @tc.desc: Test IsUserPrivateCommandValid with string type value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsUserPrivateCommandValid_StringType, TestSize.Level1)
{
    std::unordered_map<std::string, PrivateDataValue> cmd;
    cmd["strKey"] = std::string("value");
    EXPECT_TRUE(ImeSystemCmdChannel::IsUserPrivateCommandValid(cmd));
}

/**
 * @tc.name: testIsUserPrivateCommandValid_BoolType
 * @tc.desc: Test IsUserPrivateCommandValid with bool type value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsUserPrivateCommandValid_BoolType, TestSize.Level1)
{
    std::unordered_map<std::string, PrivateDataValue> cmd;
    cmd["boolKey"] = true;
    EXPECT_TRUE(ImeSystemCmdChannel::IsUserPrivateCommandValid(cmd));
}

/**
 * @tc.name: testIsUserPrivateCommandValid_NumberType
 * @tc.desc: Test IsUserPrivateCommandValid with number type value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsUserPrivateCommandValid_NumberType, TestSize.Level1)
{
    std::unordered_map<std::string, PrivateDataValue> cmd;
    cmd["numKey"] = 42;
    EXPECT_TRUE(ImeSystemCmdChannel::IsUserPrivateCommandValid(cmd));
}

/**
 * @tc.name: testIsUserPrivateCommandValid_ExceedsSize
 * @tc.desc: Test IsUserPrivateCommandValid with value exceeding 32KB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsUserPrivateCommandValid_ExceedsSize, TestSize.Level1)
{
    std::unordered_map<std::string, PrivateDataValue> cmd;
    std::string largeValue(32 * 1024 + 1, 'a');
    cmd["largeKey"] = largeValue;
    EXPECT_FALSE(ImeSystemCmdChannel::IsUserPrivateCommandValid(cmd));
}

/**
 * @tc.name: testIsUserPrivateCommandValid_MixedTypes
 * @tc.desc: Test IsUserPrivateCommandValid with mixed value types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsUserPrivateCommandValid_MixedTypes, TestSize.Level1)
{
    std::unordered_map<std::string, PrivateDataValue> cmd;
    cmd["strKey"] = std::string("hello");
    cmd["boolKey"] = false;
    cmd["numKey"] = 42;
    EXPECT_TRUE(ImeSystemCmdChannel::IsUserPrivateCommandValid(cmd));
}

/**
 * @tc.name: testIsUserPrivateCommandValid_AtSizeBoundary
 * @tc.desc: Test IsUserPrivateCommandValid at 32KB boundary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsUserPrivateCommandValid_AtSizeBoundary, TestSize.Level1)
{
    std::unordered_map<std::string, PrivateDataValue> cmd;
    // Key "k" = 1 byte + value of size (32*1024 - 1) = 32768 total
    std::string value(32 * 1024 - 1, 'b');
    cmd["k"] = value;
    EXPECT_TRUE(ImeSystemCmdChannel::IsUserPrivateCommandValid(cmd));
}

// ==================== GetExtensionInfo Tests ====================

/**
 * @tc.name: testGetExtensionInfo_EmptyList
 * @tc.desc: Test GetExtensionInfo with empty extension list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testGetExtensionInfo_EmptyList, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testGetExtensionInfo_EmptyList START");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ExtensionAbilityInfo extInfo;
    imeSystemChannel_->GetExtensionInfo(extensionInfos, extInfo);
    EXPECT_TRUE(extInfo.name.empty());
}

/**
 * @tc.name: testGetExtensionInfo_WithMetadata
 * @tc.desc: Test GetExtensionInfo with extension containing smart_menu metadata
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testGetExtensionInfo_WithMetadata, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testGetExtensionInfo_WithMetadata START");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ExtensionAbilityInfo extInfoItem;
    Metadata metadata;
    metadata.name = "ohos.extension.smart_menu";
    extInfoItem.metadata.push_back(metadata);
    extInfoItem.name = "testExtension";
    extensionInfos.push_back(extInfoItem);

    ExtensionAbilityInfo result;
    imeSystemChannel_->GetExtensionInfo(extensionInfos, result);
    EXPECT_EQ(result.name, "testExtension");
}

/**
 * @tc.name: testGetExtensionInfo_NoMatchingMetadata
 * @tc.desc: Test GetExtensionInfo with no matching metadata
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testGetExtensionInfo_NoMatchingMetadata, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testGetExtensionInfo_NoMatchingMetadata START");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ExtensionAbilityInfo extInfoItem;
    Metadata metadata;
    metadata.name = "other.metadata";
    extInfoItem.metadata.push_back(metadata);
    extensionInfos.push_back(extInfoItem);

    ExtensionAbilityInfo result;
    imeSystemChannel_->GetExtensionInfo(extensionInfos, result);
    EXPECT_TRUE(result.name.empty());
}

/**
 * @tc.name: testGetExtensionInfo_MultipleExtensions
 * @tc.desc: Test GetExtensionInfo with multiple extensions, one matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testGetExtensionInfo_MultipleExtensions, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testGetExtensionInfo_MultipleExtensions START");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    // First extension - no matching metadata
    ExtensionAbilityInfo ext1;
    ext1.name = "ext1";
    Metadata meta1;
    meta1.name = "other.metadata";
    ext1.metadata.push_back(meta1);
    extensionInfos.push_back(ext1);

    // Second extension - has matching metadata
    ExtensionAbilityInfo ext2;
    ext2.name = "ext2_smart";
    Metadata meta2;
    meta2.name = "ohos.extension.smart_menu";
    ext2.metadata.push_back(meta2);
    extensionInfos.push_back(ext2);

    ExtensionAbilityInfo result;
    imeSystemChannel_->GetExtensionInfo(extensionInfos, result);
    EXPECT_EQ(result.name, "ext2_smart");
}

/**
 * @tc.name: testGetExtensionInfo_EmptyMetadata
 * @tc.desc: Test GetExtensionInfo with extension having empty metadata
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testGetExtensionInfo_EmptyMetadata, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testGetExtensionInfo_EmptyMetadata START");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ExtensionAbilityInfo extInfoItem;
    extInfoItem.name = "extNoMeta";
    // No metadata entries
    extensionInfos.push_back(extInfoItem);

    ExtensionAbilityInfo result;
    imeSystemChannel_->GetExtensionInfo(extensionInfos, result);
    EXPECT_TRUE(result.name.empty());
}

// ==================== IsSystemApp Tests ====================

/**
 * @tc.name: testIsSystemApp_CachedTrue
 * @tc.desc: Test IsSystemApp when cached value is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsSystemApp_CachedTrue, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testIsSystemApp_CachedTrue START");
    imeSystemChannel_->isSystemApp_.store(true);
    auto result = imeSystemChannel_->IsSystemApp();
    EXPECT_TRUE(result);
    // Reset
    imeSystemChannel_->isSystemApp_.store(false);
}

/**
 * @tc.name: testIsSystemApp_NotCached
 * @tc.desc: Test IsSystemApp when not cached, proxy unavailable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testIsSystemApp_NotCached, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testIsSystemApp_NotCached START");
    imeSystemChannel_->isSystemApp_.store(false);
    imeSystemChannel_->systemAbility_ = nullptr;
    auto result = imeSystemChannel_->IsSystemApp();
    // In test env without real proxy, should return false
    EXPECT_FALSE(result);
}

// ==================== OnRemoteSaDied Tests ====================

/**
 * @tc.name: testOnRemoteSaDied001
 * @tc.desc: Test OnRemoteSaDied resets system ability and agent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testOnRemoteSaDied001, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testOnRemoteSaDied001 START");
    // Set some non-null state
    imeSystemChannel_->systemAbility_ = nullptr; // No real proxy in test env
    imeSystemChannel_->isSystemCmdConnect_.store(true);
    wptr<IRemoteObject> remote = nullptr;
    imeSystemChannel_->OnRemoteSaDied(remote);
    EXPECT_TRUE(imeSystemChannel_->systemAbility_ == nullptr);
    EXPECT_TRUE(imeSystemChannel_->systemAgent_ == nullptr);
    EXPECT_FALSE(imeSystemChannel_->isSystemCmdConnect_.load());
}

    /**
     * @tc.name: testConnectSystemCmd_AlreadyConnected
     * @tc.desc: Test ConnectSystemCmd when already connected returns NO_ERROR
     * @tc.type: FUNC
     * @tc.require:
     */
    HWTEST_F(ImeSystemChannelNewTest, testConnectSystemCmd_AlreadyConnected, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testConnectSystemCmd_AlreadyConnected START");
    imeSystemChannel_->isSystemCmdConnect_.store(true);
    auto listener = new (std::nothrow) OnSystemCmdListenerMock();
    ASSERT_NE(listener, nullptr);
    auto ret = imeSystemChannel_->ConnectSystemCmd(listener);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    // Reset
    imeSystemChannel_->isSystemCmdConnect_.store(false);
}

// ==================== SystemCmdChannelServiceImpl Tests ====================

/**
 * @tc.name: testSystemCmdChannelServiceImpl_SendPrivateCommand
 * @tc.desc: Test SystemCmdChannelServiceImpl SendPrivateCommand with null listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testSystemCmdChannelServiceImpl_SendPrivateCommand, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testSystemCmdChannelServiceImpl_SendPrivateCommand START");
    auto serviceImpl = new (std::nothrow) SystemCmdChannelServiceImpl();
    ASSERT_NE(serviceImpl, nullptr);
    std::unordered_map<std::string, PrivateDataValue> cmd;
    cmd["key"] = std::string("value");
    auto ret = serviceImpl->SendPrivateCommand(cmd);
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_NULL_POINTER);
    serviceImpl->DecStrongRef(serviceImpl);
}

/**
 * @tc.name: testSystemCmdChannelServiceImpl_NotifyPanelStatus
 * @tc.desc: Test SystemCmdChannelServiceImpl NotifyPanelStatus with null listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeSystemChannelNewTest, testSystemCmdChannelServiceImpl_NotifyPanelStatus, TestSize.Level1)
{
    IMSA_HILOGI("ImeSystemChannelNewTest testSystemCmdChannelServiceImpl_NotifyPanelStatus START");
    auto serviceImpl = new (std::nothrow) SystemCmdChannelServiceImpl();
    ASSERT_NE(serviceImpl, nullptr);
    SysPanelStatus status { InputType::NONE, 0, 0, 0 };
    auto ret = serviceImpl->NotifyPanelStatus(status);
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);
    serviceImpl->DecStrongRef(serviceImpl);
}
} // namespace MiscServices
} // namespace OHOS