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

#include <gtest/gtest.h>

#include "global.h"
#include "samgr_adapter.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;
}

class SaMgrAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {}
};

void SaMgrAdapterTest::SetUpTestCase(void)
{
    IMSA_HILOGI("SaMgrAdapterTest::SetUpTestCase");
}

/**
 * @tc.name: IsSaReady_001
 * @tc.desc: Test IsSaReady with invalid SA ID (-1), should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SaMgrAdapterTest, IsSaReady_001, TestSize.Level0)
{
    IMSA_HILOGI("SaMgrAdapterTest IsSaReady_001 START");
    int32_t saId = -1;
    auto ret = SaMgrAdapter::IsSaReady(saId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsSaReady_002
 * @tc.desc: Test IsSaReady with SA ID 0, should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SaMgrAdapterTest, IsSaReady_002, TestSize.Level0)
{
    IMSA_HILOGI("SaMgrAdapterTest IsSaReady_002 START");
    int32_t saId = 0;
    auto ret = SaMgrAdapter::IsSaReady(saId);
    EXPECT_TRUE(ret);
}
} // namespace MiscServices
} // namespace OHOS
