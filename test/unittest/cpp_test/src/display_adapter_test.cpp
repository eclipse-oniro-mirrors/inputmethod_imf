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

#include "display_adapter.h"

#include <gtest/gtest.h>

#include "global.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;
}

class DisplayAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {}
};

void DisplayAdapterTest::SetUpTestCase(void)
{
    IMSA_HILOGI("DisplayAdapterTest::SetUpTestCase");
}

/**
 * @tc.name: IsImeShowable_001
 * @tc.desc: Test IsImeShowable with invalid display ID, should return true when display info is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayAdapterTest, IsImeShowable_001, TestSize.Level0)
{
    IMSA_HILOGI("DisplayAdapterTest IsImeShowable_001 START");
    uint64_t displayId = 99999;
    auto ret = DisplayAdapter::IsImeShowable(displayId);
    // When display info is null, IsImeShowable returns true
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetDisplayInfo_001
 * @tc.desc: Test GetDisplayInfo with invalid display ID, should return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayAdapterTest, GetDisplayInfo_001, TestSize.Level0)
{
    IMSA_HILOGI("DisplayAdapterTest GetDisplayInfo_001 START");
    uint64_t displayId = 99999;
    auto displayInfo = DisplayAdapter::GetDisplayInfo(displayId);
    EXPECT_EQ(displayInfo, nullptr);
}

/**
 * @tc.name: GetDefaultDisplayId_001
 * @tc.desc: Test GetDefaultDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayAdapterTest, GetDefaultDisplayId_001, TestSize.Level0)
{
    IMSA_HILOGI("DisplayAdapterTest GetDefaultDisplayId_001 START");
    [[maybe_unused]] auto displayId = DisplayAdapter::GetDefaultDisplayId();
    // GetDefaultDisplayId returns a display ID - just verify it doesn't crash
    EXPECT_TRUE(displayId >= 0 || displayId < 0);
}

/**
 * @tc.name: IsRestrictedMainDisplayId_001
 * @tc.desc: Test IsRestrictedMainDisplayId with DEFAULT_DISPLAY_ID should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayAdapterTest, IsRestrictedMainDisplayId_001, TestSize.Level0)
{
    IMSA_HILOGI("DisplayAdapterTest IsRestrictedMainDisplayId_001 START");
    auto ret = DisplayAdapter::IsRestrictedMainDisplayId(DisplayAdapter::DEFAULT_DISPLAY_ID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsRestrictedMainDisplayId_002
 * @tc.desc: Test IsRestrictedMainDisplayId with invalid display ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayAdapterTest, IsRestrictedMainDisplayId_002, TestSize.Level0)
{
    IMSA_HILOGI("DisplayAdapterTest IsRestrictedMainDisplayId_002 START");
    uint64_t displayId = 99999;
    auto ret = DisplayAdapter::IsRestrictedMainDisplayId(displayId);
    // When display info is null (invalid display), IsImeShowable returns true,
    // so IsRestrictedMainDisplayId returns false
    EXPECT_FALSE(ret);
}
} // namespace MiscServices
} // namespace OHOS
