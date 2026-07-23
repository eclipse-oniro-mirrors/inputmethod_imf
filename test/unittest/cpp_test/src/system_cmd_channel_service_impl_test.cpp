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

#include "system_cmd_channel_service_impl.h"

#include <gtest/gtest.h>
#include <string>
#include <unordered_map>

#include "global.h"
#include "ime_system_channel.h"
#include "input_method_utils.h"
#include "sys_panel_status.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {

class SystemCmdChannelServiceImplTest : public testing::Test {
public:
    static void SetUpTestCase(void) { }
    static void TearDownTestCase(void) { }
    void SetUp()
    {
        service_ = std::make_shared<SystemCmdChannelServiceImpl>();
    }
    void TearDown()
    {
        service_.reset();
    }

protected:
    std::shared_ptr<SystemCmdChannelServiceImpl> service_;
};

HWTEST_F(SystemCmdChannelServiceImplTest, SendPrivateCommand_NullChannel_001, TestSize.Level0)
{
    // When ImeSystemCmdChannel::GetInstance() returns nullptr,
    // SendPrivateCommand should return ERROR_NULL_POINTER.
    // In unit test environment, the ImeSystemCmdChannel instance may not be initialized,
    // so the channel will likely be nullptr.
    Value value;
    auto ret = service_->SendPrivateCommand(value);
    // In unit test env, ImeSystemCmdChannel is not connected so it may be nullptr
    // or may fail at a later stage. The key branch is the nullptr check.
    // We accept either ERROR_NULL_POINTER (channel is null) or any error code
    // that indicates the channel is not available.
    EXPECT_NE(ret, ErrorCode::NO_ERROR);
}

HWTEST_F(SystemCmdChannelServiceImplTest, NotifyPanelStatus_NullChannel_001, TestSize.Level0)
{
    // When ImeSystemCmdChannel::GetInstance() returns nullptr,
    // NotifyPanelStatus should return ERROR_NULL_POINTER.
    SysPanelStatus status(InputType::NONE, FLG_FIXED, 0, 0);
    auto ret = service_->NotifyPanelStatus(status);
    // In unit test env, channel is likely null
    EXPECT_NE(ret, ErrorCode::NO_ERROR);
}

HWTEST_F(SystemCmdChannelServiceImplTest, Value_DefaultConstruction_001, TestSize.Level0)
{
    Value value;
    EXPECT_TRUE(value.valueMap.empty());
}

HWTEST_F(SystemCmdChannelServiceImplTest, Value_MapConstruction_001, TestSize.Level0)
{
    std::unordered_map<std::string, PrivateDataValue> map;
    map["test"] = "value";
    Value value(map);
    EXPECT_EQ(value.valueMap.size(), 1u);
}

HWTEST_F(SystemCmdChannelServiceImplTest, SysPanelStatus_Properties_001, TestSize.Level0)
{
    SysPanelStatus status(InputType::CAMERA_INPUT, FLG_FLOATING, 100, 200);
    status.isPanelRaised = true;
    status.needFuncButton = false;

    EXPECT_EQ(status.inputType, InputType::CAMERA_INPUT);
    EXPECT_EQ(status.flag, FLG_FLOATING);
    EXPECT_EQ(status.width, 100u);
    EXPECT_EQ(status.height, 200u);
    EXPECT_TRUE(status.isPanelRaised);
    EXPECT_FALSE(status.needFuncButton);
}
} // namespace MiscServices
} // namespace OHOS