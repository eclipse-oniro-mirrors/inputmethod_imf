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
#include "command_manager.h"
#undef private
#include <gtest/gtest.h>

#include "global.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;

class CommandManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    static void TearDownTestCase()
    {
    }
    void SetUp()
    {
    }
    void TearDown()
    {
    }
};

/**
 * @tc.name: GetCmd_001
 * @tc.desc: name not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommandManagerTest, GetCmd_001, TestSize.Level0)
{
    IMSA_HILOGI("CommandManagerTest GetCmd_001 START");
    CommandManager::GetInstance().commands_.clear();
    auto cmdInfo = CommandManager::GetInstance().GetCmd("insert");
    EXPECT_EQ(cmdInfo, nullptr);
}

/**
 * @tc.name: GetCmd_002
 * @tc.desc: name find success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommandManagerTest, GetCmd_002, TestSize.Level0)
{
    IMSA_HILOGI("CommandManagerTest GetCmd_002 START");
    CommandManager::GetInstance().Init();
    auto cmdInfo = CommandManager::GetInstance().GetCmd("insert");
    EXPECT_NE(cmdInfo, nullptr);
}
} // namespace MiscServices
} // namespace OHOS
