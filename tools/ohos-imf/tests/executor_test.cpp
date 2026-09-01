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
#include "insert_command.h"
#define private public
#define protected public
#include "executor.h"
#undef private
#include <gtest/gtest.h>

#include "cli_utils.h"
#include "global.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;

class ExecutorTest : public testing::Test {
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
 * @tc.name: Executor_001
 * @tc.desc: Fewer than 2 arguments provided
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExecutorTest, Executor_001, TestSize.Level0)
{
    IMSA_HILOGI("ExecutorTest Executor_001 START");
    int32_t argc = 1;
    char arg0[] = "ohos-imf";
    char *argv[] = { arg0 };
    Executor executor(argc, argv);
    EXPECT_EQ(executor.cmd_, "--help");
    EXPECT_TRUE(executor.argList_.empty());
}

/**
 * @tc.name: Executor_002
 * @tc.desc: more than 2 arguments provided
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExecutorTest, Executor_002, TestSize.Level0)
{
    IMSA_HILOGI("ExecutorTest Executor_002 START");
    int32_t argc = 3;
    char arg0[] = "ohos-imf";
    char arg1[] = "insert";
    char arg2[] = "ad";
    char *argv[] = { arg0, arg1, arg2 };
    Executor executor(argc, argv);
    EXPECT_EQ(executor.cmd_, argv[1]);
    ASSERT_EQ(executor.argList_.size(), 1);
    EXPECT_EQ(executor.argList_[0], argv[2]);
}

/**
 * @tc.name: Execute_001
 * @tc.desc: Print full help
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExecutorTest, Execute_001, TestSize.Level0)
{
    IMSA_HILOGI("ExecutorTest Execute_001 START");
    int32_t argc = 1;
    char arg0[] = "ohos-imf";
    char *argv[] = { arg0 };
    Executor executor(argc, argv);
    auto info = executor.Execute();
    EXPECT_EQ(info, executor.GenerateFullHelp());

    auto argc1 = 3;
    char arg1[] = "ohos-imf";
    char arg2[] = "--help";
    char arg3[] = "dj";
    char *argv1[] = { arg1, arg2, arg3 };
    Executor executor1(argc1, argv1);
    auto info1 = executor1.Execute();
    EXPECT_EQ(info1, executor1.GenerateFullHelp());
}

/**
 * @tc.name: Execute_002
 * @tc.desc: Print version
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExecutorTest, Execute_002, TestSize.Level0)
{
    IMSA_HILOGI("ExecutorTest Execute_002 START");
    int32_t argc = 2;
    char arg1[] = "ohos-imf";
    char arg2[] = "--version";
    char *argv[] = { arg1, arg2 };
    Executor executor(argc, argv);
    auto info = executor.Execute();
    EXPECT_EQ(info, executor.ExtractVersion());
}

/**
 * @tc.name: Execute_003
 * @tc.desc: cmd not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExecutorTest, Execute_003, TestSize.Level0)
{
    IMSA_HILOGI("ExecutorTest Execute_003 START");
    int32_t argc = 3;
    char arg1[] = "ohos-imf";
    char arg2[] = "ad";
    char arg3[] = "insert";
    char *argv[] = { arg1, arg2, arg3 };
    Executor executor(argc, argv);
    auto info = executor.Execute();
    EXPECT_EQ(info, CliUtils::GenerateError({ "ERR_CMD_INVALID", "The command is unknown",
                        "Please execute 'ohos-imf --help' to see detailed usage instructions" }));
}

/**
 * @tc.name: Execute_004
 * @tc.desc: Print insert cmd help
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExecutorTest, Execute_004, TestSize.Level0)
{
    IMSA_HILOGI("ExecutorTest Execute_004 START");
    int32_t argc = 3;
    char arg1[] = "ohos-imf";
    char arg2[] = "insert";
    char arg3[] = "--help";
    char *argv[] = { arg1, arg2, arg3 };
    Executor executor(argc, argv);
    auto info = executor.Execute();
    EXPECT_EQ(info, executor.GenerateCmdHelp(std::make_shared<InsertCommand>()));
}

/**
 * @tc.name: Execute_005
 * @tc.desc: cmd find, but has no param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExecutorTest, Execute_005, TestSize.Level0)
{
    IMSA_HILOGI("ExecutorTest Execute_005 START");
    int32_t argc = 2;
    char arg1[] = "ohos-imf";
    char arg2[] = "insert";
    char *argv[] = { arg1, arg2 };
    Executor executor(argc, argv);
    auto info = executor.Execute();
    EXPECT_EQ(info, CliUtils::GenerateError({ "ERR_ARG_COUNT_MISMATCH", "Invalid argument count",
                        "Only '--text <content>' is supported. Please execute 'ohos-imf insert --help' for usage" }));
}
} // namespace MiscServices
} // namespace OHOS
