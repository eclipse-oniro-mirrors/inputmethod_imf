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

#define private public
#define protected public
#include "res_sched_adapter.h"
#undef private

#include <gtest/gtest.h>
#include <functional>
#include "global.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
class ResSchedAdapterTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
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
};

/**
 * @tc.name: ResSchedAdapterTest_NotifyPanelStatus
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResSchedAdapterTest, ResSchedAdapterTest_NotifyPanelStatus, TestSize.Level0)
{
    ResSchedAdapter::NotifyPanelStatus(true);
    auto pid = IPCSkeleton::GetCallingPid();
    auto it = ResSchedAdapter::lastPanelStatusMap_.find(pid);
    if (it != ResSchedAdapter::lastPanelStatusMap_.end()) {
        EXPECT_EQ(true, it->second);
    }
    ResSchedAdapter::NotifyPanelStatus(false);
    it = ResSchedAdapter::lastPanelStatusMap_.find(pid);
    if (it != ResSchedAdapter::lastPanelStatusMap_.end()) {
        EXPECT_EQ(false, it->second);
    }
}

/**
 * @tc.name: ResSchedAdapterTest_ResetPanelStatusFlag
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResSchedAdapterTest, ResSchedAdapterTest_ResetPanelStatusFlag, TestSize.Level0)
{
    auto pid = IPCSkeleton::GetCallingPid();
    ResSchedAdapter::ResetPanelStatusFlag(pid);
    auto it = ResSchedAdapter::lastPanelStatusMap_.find(pid);
    EXPECT_EQ(it, ResSchedAdapter::lastPanelStatusMap_.end());
}
} // namespace MiscServices
} // namespace OHOS
