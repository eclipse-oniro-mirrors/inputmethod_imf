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

#include "wms_connection_monitor_manager.h"
#include "wms_connection_observer.h"

#include <gtest/gtest.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <set>

#include "global.h"
#include "tdd_util.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;
}

class WmsConnectionMonitorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {}
    void SetUp() override;
    void TearDown() override;
};

void WmsConnectionMonitorTest::SetUpTestCase(void)
{
    IMSA_HILOGI("WmsConnectionMonitorTest::SetUpTestCase");
}

void WmsConnectionMonitorTest::SetUp(void)
{
}

void WmsConnectionMonitorTest::TearDown(void)
{
    // Clean up the static connected user set between tests
    std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
    WmsConnectionObserver::connectedUserId_.clear();
}

/**
 * @tc.name: WmsConnectionMonitorManager_GetInstance_001
 * @tc.desc: Test GetInstance returns a valid singleton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionMonitorManager_GetInstance_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest GetInstance_001 START");
    auto &instance1 = WmsConnectionMonitorManager::GetInstance();
    auto &instance2 = WmsConnectionMonitorManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: WmsConnectionObserver_IsWmsConnected_001
 * @tc.desc: Test IsWmsConnected returns false when no users are connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_IsWmsConnected_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest IsWmsConnected_001 START");
    int32_t userId = 100;
    auto ret = WmsConnectionObserver::IsWmsConnected(userId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WmsConnectionObserver_IsWmsConnected_002
 * @tc.desc: Test IsWmsConnected returns true after a user is added
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_IsWmsConnected_002, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest IsWmsConnected_002 START");
    int32_t userId = 100;
    // Directly add a user to the connected set to simulate a connected state
    {
        std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
        WmsConnectionObserver::connectedUserId_.insert(userId);
    }
    auto ret = WmsConnectionObserver::IsWmsConnected(userId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: WmsConnectionObserver_IsWmsConnected_003
 * @tc.desc: Test IsWmsConnected returns false after a user is removed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_IsWmsConnected_003, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest IsWmsConnected_003 START");
    int32_t userId = 100;
    // Add then remove
    {
        std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
        WmsConnectionObserver::connectedUserId_.insert(userId);
    }
    EXPECT_TRUE(WmsConnectionObserver::IsWmsConnected(userId));
    {
        std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
        WmsConnectionObserver::connectedUserId_.erase(userId);
    }
    EXPECT_FALSE(WmsConnectionObserver::IsWmsConnected(userId));
}

/**
 * @tc.name: WmsConnectionObserver_OnConnected_001
 * @tc.desc: Test OnConnected with pid invokes handler and adds user to connected set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_OnConnected_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest OnConnected_001 START");
    std::atomic<bool> handlerCalled{ false };
    std::atomic<bool> isConnected{ false };
    std::atomic<int32_t> receivedUserId{ -1 };
    std::atomic<int32_t> receivedScreenId{ -1 };
    std::atomic<pid_t> receivedPid{ -1 };
    ChangeHandler handler = [&](bool connected, int32_t userId, int32_t screenId, pid_t pid) {
        handlerCalled.store(true);
        isConnected.store(connected);
        receivedUserId.store(userId);
        receivedScreenId.store(screenId);
        receivedPid.store(pid);
    };
    WmsConnectionObserver observer(handler);
    int32_t userId = 200;
    int32_t screenId = 0;
    pid_t pid = 12345;
    observer.OnConnected(userId, screenId, pid);
    EXPECT_TRUE(handlerCalled.load());
    EXPECT_TRUE(isConnected.load());
    EXPECT_EQ(receivedUserId.load(), userId);
    EXPECT_EQ(receivedScreenId.load(), screenId);
    EXPECT_EQ(receivedPid.load(), pid);
    EXPECT_TRUE(WmsConnectionObserver::IsWmsConnected(userId));
}

/**
 * @tc.name: WmsConnectionObserver_OnDisconnected_001
 * @tc.desc: Test OnDisconnected with pid invokes handler and removes user from connected set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_OnDisconnected_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest OnDisconnected_001 START");
    // First add a user
    int32_t userId = 300;
    {
        std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
        WmsConnectionObserver::connectedUserId_.insert(userId);
    }
    EXPECT_TRUE(WmsConnectionObserver::IsWmsConnected(userId));

    std::atomic<bool> handlerCalled{ false };
    std::atomic<bool> isConnected{ true };
    ChangeHandler handler = [&](bool connected, int32_t uid, int32_t screenId, pid_t pid) {
        handlerCalled.store(true);
        isConnected.store(connected);
    };
    WmsConnectionObserver observer(handler);
    int32_t screenId = 0;
    pid_t pid = 54321;
    observer.OnDisconnected(userId, screenId, pid);
    EXPECT_TRUE(handlerCalled.load());
    EXPECT_FALSE(isConnected.load());
    EXPECT_FALSE(WmsConnectionObserver::IsWmsConnected(userId));
}

/**
 * @tc.name: WmsConnectionObserver_OnConnected_NoHandler_001
 * @tc.desc: Test OnConnected with nullptr handler does not crash and still adds user
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_OnConnected_NoHandler_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest OnConnected_NoHandler_001 START");
    ChangeHandler handler = nullptr;
    WmsConnectionObserver observer(handler);
    int32_t userId = 400;
    int32_t screenId = 1;
    pid_t pid = 99999;
    observer.OnConnected(userId, screenId, pid);
    // Should not crash; user should still be added
    EXPECT_TRUE(WmsConnectionObserver::IsWmsConnected(userId));
}

/**
 * @tc.name: WmsConnectionObserver_OnDisconnected_NoHandler_001
 * @tc.desc: Test OnDisconnected with nullptr handler does not crash and still removes user
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_OnDisconnected_NoHandler_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest OnDisconnected_NoHandler_001 START");
    int32_t userId = 500;
    {
        std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
        WmsConnectionObserver::connectedUserId_.insert(userId);
    }
    ChangeHandler handler = nullptr;
    WmsConnectionObserver observer(handler);
    int32_t screenId = 1;
    pid_t pid = 88888;
    observer.OnDisconnected(userId, screenId, pid);
    // Should not crash; user should be removed
    EXPECT_FALSE(WmsConnectionObserver::IsWmsConnected(userId));
}

/**
 * @tc.name: WmsConnectionObserver_OnDisconnected_RemoveNonExistent_001
 * @tc.desc: Test OnDisconnected for a user not in the connected set does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_OnDisconnected_RemoveNonExistent_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest OnDisconnected_RemoveNonExistent_001 START");
    std::atomic<bool> handlerCalled{ false };
    ChangeHandler handler = [&](bool connected, int32_t uid, int32_t screenId, pid_t pid) {
        handlerCalled.store(true);
    };
    WmsConnectionObserver observer(handler);
    int32_t userId = 600;
    int32_t screenId = 0;
    pid_t pid = 77777;
    // User not in connected set, but Remove should not crash
    observer.OnDisconnected(userId, screenId, pid);
    EXPECT_TRUE(handlerCalled.load());
    EXPECT_FALSE(WmsConnectionObserver::IsWmsConnected(userId));
}

/**
 * @tc.name: WmsConnectionObserver_OnConnected_NoPid_001
 * @tc.desc: Test OnConnected without pid (empty overload) does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_OnConnected_NoPid_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest OnConnected_NoPid_001 START");
    ChangeHandler handler = nullptr;
    WmsConnectionObserver observer(handler);
    int32_t userId = 700;
    int32_t screenId = 0;
    // The overload without pid is a no-op; should not crash
    observer.OnConnected(userId, screenId);
    EXPECT_FALSE(WmsConnectionObserver::IsWmsConnected(userId));
}

/**
 * @tc.name: WmsConnectionObserver_OnDisconnected_NoPid_001
 * @tc.desc: Test OnDisconnected without pid (empty overload) does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_OnDisconnected_NoPid_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest OnDisconnected_NoPid_001 START");
    int32_t userId = 800;
    {
        std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
        WmsConnectionObserver::connectedUserId_.insert(userId);
    }
    ChangeHandler handler = nullptr;
    WmsConnectionObserver observer(handler);
    int32_t screenId = 0;
    // The overload without pid is a no-op; should not crash or remove the user
    observer.OnDisconnected(userId, screenId);
    // User should still be connected since the no-pid overload is empty
    EXPECT_TRUE(WmsConnectionObserver::IsWmsConnected(userId));
}

/**
 * @tc.name: WmsConnectionMonitorManager_RegisterWMSConnectionChangedListener_001
 * @tc.desc: Test RegisterWMSConnectionChangedListener with a valid handler
 * @tc.type: FUNC
 * @tc.require:
 */


/**
 * @tc.name: WmsConnectionObserver_MultipleUsers_001
 * @tc.desc: Test IsWmsConnected with multiple users
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WmsConnectionMonitorTest, WmsConnectionObserver_MultipleUsers_001, TestSize.Level0)
{
    IMSA_HILOGI("WmsConnectionMonitorTest MultipleUsers_001 START");
    int32_t userId1 = 100;
    int32_t userId2 = 200;
    // Neither connected initially
    EXPECT_FALSE(WmsConnectionObserver::IsWmsConnected(userId1));
    EXPECT_FALSE(WmsConnectionObserver::IsWmsConnected(userId2));
    // Add user1
    {
        std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
        WmsConnectionObserver::connectedUserId_.insert(userId1);
    }
    EXPECT_TRUE(WmsConnectionObserver::IsWmsConnected(userId1));
    EXPECT_FALSE(WmsConnectionObserver::IsWmsConnected(userId2));
    // Add user2
    {
        std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
        WmsConnectionObserver::connectedUserId_.insert(userId2);
    }
    EXPECT_TRUE(WmsConnectionObserver::IsWmsConnected(userId1));
    EXPECT_TRUE(WmsConnectionObserver::IsWmsConnected(userId2));
    // Remove user1
    {
        std::lock_guard<std::mutex> lock(WmsConnectionObserver::lock_);
        WmsConnectionObserver::connectedUserId_.erase(userId1);
    }
    EXPECT_FALSE(WmsConnectionObserver::IsWmsConnected(userId1));
    EXPECT_TRUE(WmsConnectionObserver::IsWmsConnected(userId2));
}
} // namespace MiscServices
} // namespace OHOS
