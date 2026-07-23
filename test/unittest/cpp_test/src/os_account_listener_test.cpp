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

#include "os_account_listener.h"

#include <gtest/gtest.h>

#include "global.h"
#include "inputmethod_message_handler.h"
#include "itypes_util.h"
#include "message.h"
#include "os_account_subscriber.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;
using namespace AccountSA;
}

class OsAccountListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {}
    static std::shared_ptr<OsAccountListener> listener_;
};

std::shared_ptr<OsAccountListener> OsAccountListenerTest::listener_ = nullptr;

void OsAccountListenerTest::SetUpTestCase(void)
{
    IMSA_HILOGI("OsAccountListenerTest::SetUpTestCase");
    OsAccountSubscribeInfo info(OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPED, "ImfOsAccountListener");
    listener_ = std::make_shared<OsAccountListener>(info);
}

/**
 * @tc.name: OnStateChanged_001
 * @tc.desc: Test SWITCHED state dispatches MSG_ID_USER_SWITCHED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountListenerTest, OnStateChanged_001, TestSize.Level0)
{
    IMSA_HILOGI("OsAccountListenerTest OnStateChanged_001 START");
    OsAccountStateData data;
    data.state = OsAccountState::SWITCHED;
    data.fromId = 100;
    data.toId = 101;
    data.displayId = ImfCommonConst::DEFAULT_DISPLAY_ID;
    ASSERT_NE(listener_, nullptr);
    listener_->OnStateChanged(data);
    auto *msg = MessageHandler::Instance()->GetMessage();
    ASSERT_NE(msg, nullptr);
    EXPECT_EQ(msg->msgId_, MessageID::MSG_ID_USER_SWITCHED);
    delete msg;
}

/**
 * @tc.name: OnStateChanged_002
 * @tc.desc: Test STOPPED state dispatches MSG_ID_USER_STOPPED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountListenerTest, OnStateChanged_002, TestSize.Level0)
{
    IMSA_HILOGI("OsAccountListenerTest OnStateChanged_002 START");
    OsAccountStateData data;
    data.state = OsAccountState::STOPPED;
    data.fromId = 100;
    data.toId = 100;
    data.displayId = ImfCommonConst::DEFAULT_DISPLAY_ID;
    ASSERT_NE(listener_, nullptr);
    listener_->OnStateChanged(data);
    auto *msg = MessageHandler::Instance()->GetMessage();
    ASSERT_NE(msg, nullptr);
    EXPECT_EQ(msg->msgId_, MessageID::MSG_ID_USER_STOPPED);
    delete msg;
}

/**
 * @tc.name: OnStateChanged_003
 * @tc.desc: Test REMOVED state dispatches MSG_ID_USER_REMOVED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountListenerTest, OnStateChanged_003, TestSize.Level0)
{
    IMSA_HILOGI("OsAccountListenerTest OnStateChanged_003 START");
    OsAccountStateData data;
    data.state = OsAccountState::REMOVED;
    data.fromId = 100;
    data.toId = 100;
    data.displayId = ImfCommonConst::DEFAULT_DISPLAY_ID;
    ASSERT_NE(listener_, nullptr);
    listener_->OnStateChanged(data);
    auto *msg = MessageHandler::Instance()->GetMessage();
    ASSERT_NE(msg, nullptr);
    EXPECT_EQ(msg->msgId_, MessageID::MSG_ID_USER_REMOVED);
    delete msg;
}

/**
 * @tc.name: OnStateChanged_004
 * @tc.desc: Test other state does not dispatch any message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountListenerTest, OnStateChanged_004, TestSize.Level0)
{
    IMSA_HILOGI("OsAccountListenerTest OnStateChanged_004 START");
    OsAccountStateData data;
    data.state = static_cast<OsAccountState>(-1);
    data.fromId = 100;
    data.toId = 100;
    data.displayId = ImfCommonConst::DEFAULT_DISPLAY_ID;
    ASSERT_NE(listener_, nullptr);
    listener_->OnStateChanged(data);
    // No message should be sent for unknown state; verify no crash
}
} // namespace MiscServices
} // namespace OHOS
