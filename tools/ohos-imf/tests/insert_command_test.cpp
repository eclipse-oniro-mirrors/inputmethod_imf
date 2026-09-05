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
#include "insert_command.h"
#undef private
#include <gtest/gtest.h>

#include "cli_utils.h"
#include "global.h"
#include "input_method_controller.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;

class InsertCommandTest : public testing::Test {
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
 * @tc.name: Execute_001
 * @tc.desc: param num is not same with 2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsertCommandTest, Execute_001, TestSize.Level0)
{
    IMSA_HILOGI("InsertCommandTest Execute_001 START");
    InsertCommand cmd;
    std::vector<std::string> argList;
    auto ret = cmd.Execute(argList);
    EXPECT_EQ(ret, CliUtils::GenerateError({ "ERR_ARG_COUNT_MISMATCH", "Invalid argument count",
                       "Only '--text <content>' is supported. Please execute 'ohos-imf insert --help' for usage" }));
}

/**
 * @tc.name: Execute_002
 * @tc.desc: "--key" is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsertCommandTest, Execute_002, TestSize.Level0)
{
    IMSA_HILOGI("InsertCommandTest Execute_002 START");
    InsertCommand cmd;
    std::vector<std::string> argList = { "abcd", "abcg" };
    auto ret = cmd.Execute(argList);
    EXPECT_EQ(ret, CliUtils::GenerateError({ "ERR_ARG_MISSING", "Missing required option '--text' or its value",
                       "Please execute 'ohos-imf insert --help' for usage" }));
}

/**
 * @tc.name: Execute_003
 * @tc.desc: value is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsertCommandTest, Execute_003, TestSize.Level0)
{
    IMSA_HILOGI("InsertCommandTest Execute_003 START");
    InsertCommand cmd;
    std::vector<std::string> argList = { "abcd", "--text" };
    auto ret = cmd.Execute(argList);
    EXPECT_EQ(ret, CliUtils::GenerateError({ "ERR_ARG_MISSING", "Missing required option '--text' or its value",
                       "Please execute 'ohos-imf insert --help' for usage" }));
}

/**
 * @tc.name: Execute_004
 * @tc.desc: out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsertCommandTest, Execute_004, TestSize.Level0)
{
    IMSA_HILOGI("InsertCommandTest Execute_004 START");
    InsertCommand cmd;
    size_t textSize = 513;
    std::string text(textSize, 'a');
    std::vector<std::string> argList = { "--text", text };
    auto ret = cmd.Execute(argList);
    std::string errMsg = "Text size is " + std::to_string(textSize) + ", exceeds the limit, it must not exceed "
                         + std::to_string(InsertCommand::MAX_INSERT_TEXT_SIZE) + " bytes";
    EXPECT_EQ(ret, CliUtils::GenerateError({ "ERR_ARG_OUT_OF_RANGE", errMsg, "Please provide valid text" }));
}

/**
 * @tc.name: Execute_005
 * @tc.desc: has no ohos.permission.CONTROL_DEVICE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsertCommandTest, Execute_005, TestSize.Level0)
{
    IMSA_HILOGI("InsertCommandTest Execute_005 START");
    InputMethodController::GetInstance()->SetTextInteractionRet(ErrorCode::ERROR_STATUS_PERMISSION_DENIED);
    InsertCommand cmd;
    std::vector<std::string> argList = { "--text", "dgg" };
    auto ret = cmd.Execute(argList);
    EXPECT_EQ(ret, CliUtils::GenerateError({ "ERR_PERMISSION_DENIED",
                       "Permission denied: missing ohos.permission.CONTROL_DEVICE permission",
                       "Please add ohos.permission.CONTROL_DEVICE in the requirePermissions field of module.json5" }));
}

/**
 * @tc.name: Execute_006
 * @tc.desc: has no edit bow bound ime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsertCommandTest, Execute_006, TestSize.Level0)
{
    IMSA_HILOGI("InsertCommandTest Execute_006 START");
    InputMethodController::GetInstance()->SetTextInteractionRet(ErrorCode::ERROR_CLIENT_NOT_BOUND);
    InsertCommand cmd;
    std::vector<std::string> argList = { "--text", "dgg" };
    auto ret = cmd.Execute(argList);
    EXPECT_EQ(ret, CliUtils::GenerateError(
                       { "ERR_EDIT_BOX_NOT_BOUND_WITH_IME_APP", "No focused edit box or not bound to the IME app",
                           "Please click the edit box in current focused window to trigger the binding operation "
                           "first and "
                           "try again" }));
}

/**
 * @tc.name: Execute_007
 * @tc.desc: success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsertCommandTest, Execute_007, TestSize.Level0)
{
    IMSA_HILOGI("InsertCommandTest Execute_007 START");
    InputMethodController::GetInstance()->SetTextInteractionRet(ErrorCode::NO_ERROR);
    InsertCommand cmd;
    std::vector<std::string> argList = { "--text", "dgg" };
    auto ret = cmd.Execute(argList);
    EXPECT_EQ(ret, CliUtils::GenerateSuccess(std::make_shared<CommonSuccessInfo>()));
}
} // namespace MiscServices
} // namespace OHOS
