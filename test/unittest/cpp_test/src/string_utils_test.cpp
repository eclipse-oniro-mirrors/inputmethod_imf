/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <gtest/gtest.h>
#include <string>

#include "global.h"
#include "string_utils.h"


using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
class StringUtilsTest : public testing::Test {
public:
    void SetUp()
    {
        IMSA_HILOGI("StringUtils::SetUp");
    }
    void TearDown()
    {
        IMSA_HILOGI("StringUtils::TearDown");
    }
};

/**
 * @tc.name: testToHex_001
 * @tc.desc: IMA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_001, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a"));
    std::string result = "61";
    EXPECT_TRUE(out.compare(result) == 0);
    out = StringUtils::ToHex(std::u16string(u"a"));
    result = "0061";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_001
 * @tc.desc: IMA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_001, TestSize.Level0)
{
    std::u16string out = u"abcdefg\0𪛊";
    auto charNum = StringUtils::CountUtf16Chars(out);
    StringUtils::TruncateUtf16String(out, charNum -1);
    std::u16string checkOut = u"abcdefg\0";
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

} // namespace MiscServices
} // namespace OHOS
