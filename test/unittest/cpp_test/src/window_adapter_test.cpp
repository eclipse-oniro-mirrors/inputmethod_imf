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

#define private public
#define protected public
#include "window_adapter.h"
#undef private

#include <gtest/gtest.h>

#include <functional>
#include <memory>

#include "global.h"
#include "tdd_util.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace OHOS::Rosen;
class WindowAdapterTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        WindowDisplayChangeHandler callback = [](int32_t userId, int32_t windowId, uint64_t displayId) {};
        WindowAdapter::GetInstance().RegisterWindowDisplayIdChangedListener(callback, userId_);
    }
    static void TearDownTestCase()
    {
    }
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
    static bool hasHandled_;
    static int32_t userId_;
};
bool WindowAdapterTest::hasHandled_{ false };
int32_t WindowAdapterTest::userId_{ 100 };

/**
 * @tc.name: WindowAdapter_GetFocusInfo
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WindowAdapterTest, WindowAdapter_GetFocusInfo, TestSize.Level0)
{
    IMSA_HILOGI("WindowAdapterTest::WindowAdapter_GetFocusInfo START");
    OHOS::Rosen::FocusChangeInfo focusInfo;
    WindowAdapter::GetInstance().GetFocusInfo(focusInfo, WindowAdapterTest::userId_);
    EXPECT_TRUE(focusInfo.displayId_ >= 0);
}

/**
 * @tc.name: WindowAdapter_GetDisplayId
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WindowAdapterTest, WindowAdapter_GetDisplayId, TestSize.Level0)
{
    IMSA_HILOGI("WindowAdapterTest::WindowAdapter_GetDisplayId START");
    int64_t callingPid = -1000;
    uint64_t displayId = 0;
    auto ret = WindowAdapter::GetInstance().GetDisplayId(callingPid, displayId, WindowAdapterTest::userId_);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WindowAdapter_OnDisplayGroupInfoChanged
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WindowAdapterTest, WindowAdapter_OnDisplayGroupInfoChanged, TestSize.Level0)
{
    IMSA_HILOGI("WindowAdapterTest::WindowAdapter_OnDisplayGroupInfoChanged START");
    WindowAdapter::GetInstance().displayGroupIds_.clear();
    uint64_t displayId = 100;
    uint64_t displayGroupId = 2;
    uint64_t displayId1 = 99;
    int32_t userId = TddUtil::GetCurrentUserId();
    // empty, remove
    WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId, displayGroupId, false, userId);
    auto userIter = WindowAdapter::GetInstance().displayGroupIds_.find(userId);
    EXPECT_TRUE(userIter == WindowAdapter::GetInstance().displayGroupIds_.end());
    // add
    WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId, displayGroupId, true, userId);
    userIter = WindowAdapter::GetInstance().displayGroupIds_.find(userId);
    EXPECT_TRUE(userIter != WindowAdapter::GetInstance().displayGroupIds_.end());
    auto displayGroupIds = userIter->second;
    auto iter = displayGroupIds.find(displayId);
    EXPECT_TRUE(iter != displayGroupIds.end());
    EXPECT_EQ(iter->second, displayGroupId);
    // not find displayId
    WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId1, displayGroupId, false, userId);
    userIter = WindowAdapter::GetInstance().displayGroupIds_.find(userId);
    EXPECT_TRUE(userIter != WindowAdapter::GetInstance().displayGroupIds_.end());
    displayGroupIds = userIter->second;
    iter = displayGroupIds.find(displayId);
    EXPECT_EQ(iter->second, displayGroupId);
    // remove success
    WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId, displayGroupId, false, userId);
    userIter = WindowAdapter::GetInstance().displayGroupIds_.find(userId);
    EXPECT_TRUE(userIter != WindowAdapter::GetInstance().displayGroupIds_.end());
    displayGroupIds = userIter->second;
    iter = displayGroupIds.find(displayId);
    EXPECT_TRUE(iter == displayGroupIds.end());
}
#ifdef SCENE_BOARD_ENABLE
/**
 * @tc.name: WindowAdapter_OnWindowInfoChanged
 * @tc.desc: windowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WindowAdapterTest, WindowAdapter_OnWindowInfoChanged, TestSize.Level0)
{
    IMSA_HILOGI("WindowAdapterTest::WindowAdapter_OnWindowInfoChanged START");
    auto handler = [](int32_t userId, int32_t windowId, uint64_t displayId) { hasHandled_ = true; };
    auto listener = std::make_shared<WindowAdapter::WindowDisplayChangedListenerImpl>(handler);
    // empty
    WindowInfoList winInfoList;
    listener->OnWindowInfoChanged(winInfoList);
    EXPECT_FALSE(hasHandled_);
    // displayId not found
    std::unordered_map<WindowInfoKey, WindowChangeInfoType> info;
    info[WindowInfoKey::WINDOW_RECT] = 10;
    winInfoList.push_back(info);
    listener->OnWindowInfoChanged(winInfoList);
    EXPECT_FALSE(hasHandled_);
    // windowId not found
    winInfoList.clear();
    info.clear();
    info[WindowInfoKey::DISPLAY_ID] = 10;
    winInfoList.push_back(info);
    listener->OnWindowInfoChanged(winInfoList);
    EXPECT_FALSE(hasHandled_);
    // displayId type error
    winInfoList.clear();
    info.clear();
    int32_t displayId = 1;
    uint32_t windowId = 1;
    info[WindowInfoKey::DISPLAY_ID] = displayId;
    info[WindowInfoKey::WINDOW_ID] = windowId;
    winInfoList.push_back(info);
    listener->OnWindowInfoChanged(winInfoList);
    EXPECT_FALSE(hasHandled_);
    // windowId type error
    winInfoList.clear();
    info.clear();
    uint64_t displayId1 = 10;
    int32_t windowId1 = 1;
    info[WindowInfoKey::DISPLAY_ID] = displayId1;
    info[WindowInfoKey::WINDOW_ID] = windowId1;
    winInfoList.push_back(info);
    listener->OnWindowInfoChanged(winInfoList);
    EXPECT_FALSE(hasHandled_);
    // ok
    winInfoList.clear();
    info.clear();
    uint32_t windowId2 = 1;
    info[WindowInfoKey::DISPLAY_ID] = displayId1;
    info[WindowInfoKey::WINDOW_ID] = windowId2;
    winInfoList.push_back(info);
    listener->OnWindowInfoChanged(winInfoList);
    EXPECT_TRUE(hasHandled_);
}
#endif
} // namespace MiscServices
} // namespace OHOS
