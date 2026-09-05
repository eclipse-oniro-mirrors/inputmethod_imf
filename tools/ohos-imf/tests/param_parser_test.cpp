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

#include "param_parser.h"

#include <gtest/gtest.h>

#include "global.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;

class ParamParseTest : public testing::Test {
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
 * @tc.name: GetParam_001
 * @tc.desc: key not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ParamParseTest, GetParam_001, TestSize.Level0)
{
    IMSA_HILOGI("ParamParseTest GetParam_001 START");
    std::vector<std::string> argList = { "--text", "gh" };
    auto param = ParamParse::GetParam(argList, "--delete");
    EXPECT_TRUE(param.empty());
}

/**
 * @tc.name: GetParam_002
 * @tc.desc: value is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ParamParseTest, GetParam_002, TestSize.Level0)
{
    IMSA_HILOGI("ParamParseTest GetParam_002 START");
    std::vector<std::string> argList = { "--delete", "value", "--text" };
    auto param = ParamParse::GetParam(argList, "--text");
    EXPECT_TRUE(param.empty());
}

/**
 * @tc.name: GetParam_003
 * @tc.desc: success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ParamParseTest, GetParam_003, TestSize.Level0)
{
    IMSA_HILOGI("ParamParseTest GetParam_003 START");
    std::string value = "--text";
    std::vector<std::string> argList = { "--text", value, "--delete" };
    auto param = ParamParse::GetParam(argList, "--text");
    EXPECT_EQ(param, value);

    value = "我们";
    argList = { "--delete", "--text", value };
    param = ParamParse::GetParam(argList, "--text");
    EXPECT_EQ(param, value);
}
} // namespace MiscServices
} // namespace OHOS