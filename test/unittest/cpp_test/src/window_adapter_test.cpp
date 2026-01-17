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

#include "global.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
class WindowAdapterTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    static void TearDownTestCase()
    {
    }
    void SetUp() override
    {
        WindowDisplayChangeHandler callback = [](OHOS::Rosen::CallingWindowInfo callingWindowInfo) {
            IMSA_HILOGD("callback result:%{public}s",
                WindowDisplayChangeListener::CallingWindowInfoToString(callingWindowInfo).c_str());
        };
        WindowAdapter::GetInstance().RegisterCallingWindowInfoChangedListener(callback);
    }
    void TearDown() override
    {
    }
};

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
    WindowAdapter::GetInstance().GetFocusInfo(focusInfo);
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
    auto ret = WindowAdapter::GetInstance().GetDisplayId(callingPid, displayId);
    EXPECT_TRUE(ret);
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
    // empty, remove
    WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId, displayGroupId, false);
    auto iter = WindowAdapter::GetInstance().displayGroupIds_.find(displayId);
    EXPECT_TRUE(iter == WindowAdapter::GetInstance().displayGroupIds_.end());
    // add
    WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId, displayGroupId, true);
    iter = WindowAdapter::GetInstance().displayGroupIds_.find(displayId);
    EXPECT_TRUE(iter != WindowAdapter::GetInstance().displayGroupIds_.end());
    EXPECT_EQ(iter->second, displayGroupId);
    // not find displayId
    WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId1, displayGroupId, false);
    iter = WindowAdapter::GetInstance().displayGroupIds_.find(displayId);
    EXPECT_TRUE(iter != WindowAdapter::GetInstance().displayGroupIds_.end());
    EXPECT_EQ(iter->second, displayGroupId);
    // remove success
    WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId, displayGroupId, false);
    iter = WindowAdapter::GetInstance().displayGroupIds_.find(displayId);
    EXPECT_TRUE(iter == WindowAdapter::GetInstance().displayGroupIds_.end());
}

/**
 * @tc.name: WindowAdapter_OnUnfocused
 * @tc.desc: windowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WindowAdapterTest, WindowAdapter_OnUnfocused, TestSize.Level0)
{
    IMSA_HILOGI("WindowAdapterTest::WindowAdapter_OnUnfocused START");
    WindowAdapter::GetInstance().focusWindowInfos_.clear();
    uint32_t windowId = 10;

    Rosen::FocusChangeInfo focusWindowInfo;
    focusWindowInfo.windowId_ = windowId;
    WindowAdapter::GetInstance().OnUnFocused(focusWindowInfo);
    EXPECT_TRUE(WindowAdapter::GetInstance().focusWindowInfos_.empty());

    WindowAdapter::GetInstance().focusWindowInfos_.push_back(focusWindowInfo);
    WindowAdapter::GetInstance().OnUnFocused(focusWindowInfo);
    EXPECT_TRUE(WindowAdapter::GetInstance().focusWindowInfos_.empty());
}
} // namespace MiscServices
} // namespace OHOS
