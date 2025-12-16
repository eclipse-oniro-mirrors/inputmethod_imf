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
#include <gtest/gtest.h>
#include <sys/time.h>

#define private public
#define protected public
#include "ime_event_listener_manager.h"
#include "input_client_service_impl.h"
#undef private
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "global.h"
#include "ime_event_listener.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
namespace {
} // namespace

class ImeEventListenerManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ImeEventListenerManagerTest::SetUpTestCase()
{
    IMSA_HILOGI("ImeEventListenerManagerTest::SetUpTestCase");
}

void ImeEventListenerManagerTest::TearDownTestCase()
{
    IMSA_HILOGI("ImeEventListenerManagerTest::TearDownTestCase");
}

void ImeEventListenerManagerTest::SetUp()
{
    ImeEventListenerManager::GetInstance().imeEventListeners_.clear();
    IMSA_HILOGI("ImeEventListenerManagerTest::SetUp");
}

void ImeEventListenerManagerTest::TearDown()
{
    IMSA_HILOGI("ImeEventListenerManagerTest::TearDown");
}

/**
 * @tc.name: test_UpdateListenerInfo_insert_001
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(ImeEventListenerManagerTest, test_UpdateListenerInfo_insert_001, TestSize.Level0)
{
    IMSA_HILOGI("test_UpdateListenerInfo_insert_001 TEST START");
    int32_t userId = 101;
    uint32_t eventFlag = 1;
    int64_t pid = 201;
    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    // add one
    int32_t result = ImeEventListenerManager::GetInstance().UpdateListenerInfo(userId, { eventFlag, client, pid });
    EXPECT_EQ(result, ErrorCode::NO_ERROR);
    EXPECT_EQ(ImeEventListenerManager::GetInstance().imeEventListeners_.size(), 1);
    auto it = ImeEventListenerManager::GetInstance().imeEventListeners_.find(userId);
    ASSERT_NE(it, ImeEventListenerManager::GetInstance().imeEventListeners_.end());
    ASSERT_EQ(it->second.size(), 1);
    auto listener = it->second[0];
    EXPECT_EQ(listener.eventFlag, eventFlag);
    EXPECT_EQ(listener.pid, pid);
    EXPECT_EQ(listener.client, client);
    // add two, same userId
    int64_t pid1 = 409;
    sptr<IInputClient> client1 = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    result = ImeEventListenerManager::GetInstance().UpdateListenerInfo(userId, { eventFlag, client1, pid1 });
    EXPECT_EQ(result, ErrorCode::NO_ERROR);
    EXPECT_EQ(ImeEventListenerManager::GetInstance().imeEventListeners_.size(), 1);
    it = ImeEventListenerManager::GetInstance().imeEventListeners_.find(userId);
    ASSERT_NE(it, ImeEventListenerManager::GetInstance().imeEventListeners_.end());
    ASSERT_EQ(it->second.size(), 2);
    // add three, not same userId
    int64_t pid2 = 409;
    sptr<IInputClient> client2 = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    int32_t userId2 = 10;
    result = ImeEventListenerManager::GetInstance().UpdateListenerInfo(userId2, { eventFlag, client2, pid2 });
    EXPECT_EQ(result, ErrorCode::NO_ERROR);
    EXPECT_EQ(ImeEventListenerManager::GetInstance().imeEventListeners_.size(), 2);
    it = ImeEventListenerManager::GetInstance().imeEventListeners_.find(userId2);
    ASSERT_NE(it, ImeEventListenerManager::GetInstance().imeEventListeners_.end());
    ASSERT_EQ(it->second.size(), 1);
}

/**
 * @tc.name: test_UpdateListenerInfo_update
 * @tc.desc: test KeyEvent Callback.
 * @tc.type: FUNC
 */
HWTEST_F(ImeEventListenerManagerTest, test_UpdateListenerInfo_update, TestSize.Level0)
{
    IMSA_HILOGI("test_UpdateListenerInfo_update TEST START");
    int32_t userId = 101;
    uint32_t eventFlag = 1;
    int64_t pid = 201;
    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    // add one
    int32_t result = ImeEventListenerManager::GetInstance().UpdateListenerInfo(userId, { eventFlag, client, pid });
    EXPECT_EQ(result, ErrorCode::NO_ERROR);
    EXPECT_EQ(ImeEventListenerManager::GetInstance().imeEventListeners_.size(), 1);
    auto it = ImeEventListenerManager::GetInstance().imeEventListeners_.find(userId);
    ASSERT_NE(it, ImeEventListenerManager::GetInstance().imeEventListeners_.end());
    ASSERT_EQ(it->second.size(), 1);
    auto listener = it->second[0];
    EXPECT_EQ(listener.eventFlag, eventFlag);

    uint32_t eventFlag1 = 10;
    result = ImeEventListenerManager::GetInstance().UpdateListenerInfo(userId, { eventFlag1, client, pid });
    EXPECT_EQ(result, ErrorCode::NO_ERROR);
    it = ImeEventListenerManager::GetInstance().imeEventListeners_.find(userId);
    ASSERT_NE(it, ImeEventListenerManager::GetInstance().imeEventListeners_.end());
    ASSERT_EQ(it->second.size(), 1);
    listener = it->second[0];
    EXPECT_EQ(listener.eventFlag, eventFlag1);
}

/**
 * @tc.name: test_UpdateListenerInfo_delete
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImeEventListenerManagerTest, test_UpdateListenerInfo_delete, TestSize.Level0)
{
    IMSA_HILOGI("test_UpdateListenerInfo_delete TEST START");
    int32_t userId = 101;
    uint32_t eventFlag = 1;
    int64_t pid = 201;
    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    // add one
    int32_t result = ImeEventListenerManager::GetInstance().UpdateListenerInfo(userId, { eventFlag, client, pid });
    EXPECT_EQ(result, ErrorCode::NO_ERROR);
    EXPECT_EQ(ImeEventListenerManager::GetInstance().imeEventListeners_.size(), 1);
    auto it = ImeEventListenerManager::GetInstance().imeEventListeners_.find(userId);
    ASSERT_NE(it, ImeEventListenerManager::GetInstance().imeEventListeners_.end());
    ASSERT_EQ(it->second.size(), 1);
    auto listener = it->second[0];
    EXPECT_EQ(listener.eventFlag, eventFlag);

    uint32_t eventFlag1 = 0;
    result = ImeEventListenerManager::GetInstance().UpdateListenerInfo(userId, { eventFlag1, client, pid });
    EXPECT_EQ(result, ErrorCode::NO_ERROR);
    it = ImeEventListenerManager::GetInstance().imeEventListeners_.find(userId);
    ASSERT_EQ(it, ImeEventListenerManager::GetInstance().imeEventListeners_.end());
}

/**
 * @tc.name: test_GetListenerInfo
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImeEventListenerManagerTest, test_GetListenerInfo, TestSize.Level0)
{
    IMSA_HILOGI("test_GetListenerInfo TEST START");
    // not has user 0 listener
    int32_t userId = 0;
    auto listeners = ImeEventListenerManager::GetInstance().GetListenerInfo(userId);
    EXPECT_TRUE(listeners.empty());
    // has user 0 listener
    uint32_t eventFlag = 1;
    int64_t pid = 201;
    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    std::vector<ImeEventListenerInfo> imeListeners;
    imeListeners.push_back({ eventFlag, client, pid });
    ImeEventListenerManager::GetInstance().imeEventListeners_.insert_or_assign(userId, imeListeners);
    listeners = ImeEventListenerManager::GetInstance().GetListenerInfo(userId);
    ASSERT_EQ(listeners.size(), 1);
    ASSERT_EQ(listeners[0].pid, pid);

    // has other user listener,  has user0 listener
    int32_t userId1 = 100;
    ImeEventListenerManager::GetInstance().imeEventListeners_.insert_or_assign(userId1, imeListeners);
    listeners = ImeEventListenerManager::GetInstance().GetListenerInfo(userId1);
    ASSERT_EQ(listeners.size(), 2);
    // not has other user listener,  not has user0 listener
    ImeEventListenerManager::GetInstance().imeEventListeners_.clear();
    listeners = ImeEventListenerManager::GetInstance().GetListenerInfo(userId);
    EXPECT_TRUE(listeners.empty());
}

/**
 * @tc.name: test_OnListenerDied
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImeEventListenerManagerTest, test_OnListenerDied, TestSize.Level0)
{
    IMSA_HILOGI("test_OnListenerDied TEST START");
    int32_t userId = 10;
    // remote is nullptr
    ImeEventListenerManager::GetInstance().OnListenerDied(userId, nullptr);
    // not find user info
    uint32_t eventFlag = 10;
    int64_t pid = 2010;
    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    ImeEventListenerManager::GetInstance().OnListenerDied(userId, client);

    uint32_t eventFlag1 = 1;
    int64_t pid1 = 201;
    sptr<IInputClient> client1 = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client1, nullptr);
    std::vector<ImeEventListenerInfo> imeListeners;
    auto deathRecipient = new (std::nothrow) InputDeathRecipient();
    ASSERT_NE(deathRecipient, nullptr);
    imeListeners.push_back({ eventFlag1, client1, pid1, deathRecipient });
    imeListeners.push_back({ eventFlag, client, pid });
    ImeEventListenerManager::GetInstance().imeEventListeners_.insert_or_assign(userId, imeListeners);
    // find user info, not find remote info
    sptr<IInputClient> client3 = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    ImeEventListenerManager::GetInstance().OnListenerDied(userId, client3);
    auto it = ImeEventListenerManager::GetInstance().imeEventListeners_.find(userId);
    ASSERT_NE(it, ImeEventListenerManager::GetInstance().imeEventListeners_.end());
    ASSERT_EQ(it->second.size(), 2);
    // find user info, find remote info, deathRecipient is nullptr
    ImeEventListenerManager::GetInstance().OnListenerDied(userId, client);
    it = ImeEventListenerManager::GetInstance().imeEventListeners_.find(userId);
    ASSERT_NE(it, ImeEventListenerManager::GetInstance().imeEventListeners_.end());
    ASSERT_EQ(it->second.size(), 1);
    // find user info, find remote info, has deathRecipient
    ImeEventListenerManager::GetInstance().OnListenerDied(userId, client1);
    EXPECT_TRUE(ImeEventListenerManager::GetInstance().imeEventListeners_.empty());
}

/**
 * @tc.name: test_notify
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImeEventListenerManagerTest, test_notify, TestSize.Level0)
{
    IMSA_HILOGI("test_notify TEST START");
    int32_t userId = 10;
    int32_t callingWndId = 100;
    uint64_t displayGroupId = 3;
    uint64_t defaultDisplayGroupId = ImfCommonConst::DEFAULT_DISPLAY_GROUP_ID;
    int32_t requestKeyboardReason = 2;

    // not default displayGroup
    ImeEventListenerManager::GetInstance().NotifyInputStart(
        userId, callingWndId, displayGroupId, requestKeyboardReason);
    ImeEventListenerManager::GetInstance().NotifyInputStop(userId, displayGroupId);
    // default displayGroup
    uint64_t displayGroupId1 = ImfCommonConst::DEFAULT_DISPLAY_GROUP_ID;
    ImeEventListenerManager::GetInstance().NotifyInputStart(
        userId, callingWndId, displayGroupId1, requestKeyboardReason);
    ImeEventListenerManager::GetInstance().NotifyInputStop(userId, displayGroupId1);

    std::vector<ImeEventListenerInfo> imeListeners;
    ImeEventListenerInfo info;
    imeListeners.push_back(info);
    ImeEventListenerInfo info1;
    sptr<IInputClient> client = new (std::nothrow) InputClientServiceImpl();
    ASSERT_NE(client, nullptr);
    info1.client = client;
    imeListeners.push_back(info1);
    ImeEventListenerInfo info2;
    info2.client = client;
    info2.eventFlag = EVENT_IME_CHANGE_MASK | EVENT_IME_SHOW_MASK | EVENT_IME_HIDE_MASK
                      | EVENT_INPUT_STATUS_CHANGED_MASK;
    imeListeners.push_back(info2);
    ImeEventListenerManager::GetInstance().imeEventListeners_.insert_or_assign(userId, imeListeners);
    auto ret = ImeEventListenerManager::GetInstance().NotifyInputStart(
        userId, callingWndId, defaultDisplayGroupId, requestKeyboardReason);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = ImeEventListenerManager::GetInstance().NotifyInputStop(userId, defaultDisplayGroupId);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ImeWindowInfo imeWindowInfo;
    ret =
        ImeEventListenerManager::GetInstance().NotifyPanelStatusChange(userId, InputWindowStatus::SHOW, imeWindowInfo);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret =
        ImeEventListenerManager::GetInstance().NotifyPanelStatusChange(userId, InputWindowStatus::HIDE, imeWindowInfo);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    Property property;
    SubProperty subProperty;
    ret = ImeEventListenerManager::GetInstance().NotifyImeChange(userId, property, subProperty);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}
} // namespace MiscServices
} // namespace OHOS