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
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_001, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a"));
    std::string result = "61";
    IMSA_HILOGI("out:%{public}s,result:%{public}s", out.c_str(), result.c_str());
    EXPECT_TRUE(out.compare(result) == 0);
    out = StringUtils::ToHex(std::u16string(u"a"));
    IMSA_HILOGI("out:%{public}s,result:%{public}s", out.c_str(), result.c_str());
    result = "0061";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testToHex_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_002, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string(""));
    std::string result = "";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u""));
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testToHex_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_003, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("你好"));
    std::string result = "e4bda0e5a5bd";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"你好"));
    result = "4f60597d";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_001, TestSize.Level0)
{
    char16_t inputChar[] = u"abcdefg\0";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    IMSA_HILOGI("out:%{public}zu", inputLen);
    std::u16string out(inputChar, inputLen);
    IMSA_HILOGI("out:%{public}s", StringUtils::ToHex(out).c_str());
    auto charNum = StringUtils::CountUtf16Chars(out);
    StringUtils::TruncateUtf16String(out, charNum -1);
    std::u16string checkOut(inputChar, inputLen - 1);
    IMSA_HILOGI("out:%{public}s", StringUtils::ToHex(checkOut).c_str());
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_002, TestSize.Level0)
{
    char16_t inputChar[] = u"abcdef";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 7);
}

/**
 * @tc.name: testTruncateUtf16String_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_001, TestSize.Level0)
{
    char16_t inputChar[] = u"abcdefg";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 0);
    EXPECT_TRUE(out.empty());
}

/**
 * @tc.name: testTruncateUtf16String_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_002, TestSize.Level0)
{
    char16_t inputChar[] = u"abcdefg";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, inputLen + 1);
    EXPECT_EQ(out.length(), inputLen);
}

/**
 * @tc.name: testToHex_004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_004, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("日"));
    std::string result = "65e5";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"日"));
    result = "65e5";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_002, TestSize.Level0)
{
    std::u16string out(u"");
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 0);
}

/**
 * @tc.name: testTruncateUtf16String_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_003, TestSize.Level0)
{
    std::u16string out(u"");
    StringUtils::TruncateUtf16String(out, 0);
    EXPECT_TRUE(out.empty());
}

/**
 * @tc.name: testTruncateUtf16String_004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_004, TestSize.Level0)
{
    std::u16string out(u"abcdefg");
    StringUtils::TruncateUtf16String(out, 10);
    EXPECT_EQ(out.length(), 7);
}

/**
 * @tc.name: testToHex_005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_005, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a日b"));
    std::string result = "6165e562";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a日b"));
    result = "006165e50062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testToHex_006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_006, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("\n"));
    std::string result = "0a";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"\n"));
    result = "000a";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_003, TestSize.Level0)
{
    char16_t inputChar[] = u"abc\n";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 4);
}

/**
 * @tc.name: testTruncateUtf16String_005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_005, TestSize.Level0)
{
    char16_t inputChar[] = u"abc\n";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 3);
    std::u16string checkOut(inputChar, 3);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_007
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_007, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("abcdefghijklmnopqrstuvwxyz"));
    std::string result = "6162636465666768696a6b6c6d6e6f707172737475767778797a";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"abcdefghijklmnopqrstuvwxyz"));
    result = "006100620063006400650066006700680069006a006b006c006d006e006f0070007100720073007400750076007700780079007";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_004, TestSize.Level0)
{
    char16_t inputChar[] = u"abcdefghijklmnopqrstuvwxyz";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 26);
}

/**
 * @tc.name: testToHex_008
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_008, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string(" "));
    std::string result = "20";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u" "));
    result = "0020";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_005, TestSize.Level0)
{
    char16_t inputChar[] = u"abc ";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 4);
}

/**
 * @tc.name: testTruncateUtf16String_006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_006, TestSize.Level0)
{
    char16_t inputChar[] = u"abc ";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 3);
    std::u16string checkOut(inputChar, 3);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_009
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_009, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("123"));
    std::string result = "313233";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"123"));
    result = "003100320033";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_006, TestSize.Level0)
{
    char16_t inputChar[] = u"123";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testToHex_010
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_010, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a1b2c3"));
    std::string result = "613162326333";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a1b2c3"));
    result = "006100310062003200630033";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_007
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_007, TestSize.Level0)
{
    char16_t inputChar[] = u"a1b2c3";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 6);
}

/**
 * @tc.name: testTruncateUtf16String_007
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_007, TestSize.Level0)
{
    char16_t inputChar[] = u"a1b2c3";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 4);
    std::u16string checkOut(inputChar, 4);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_011
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_011, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("!@#"));
    std::string result = "214023";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"!@#"));
    result = "002100400023";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_008
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_008, TestSize.Level0)
{
    char16_t inputChar[] = u"!@#";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testToHex_012
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_012, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string(""));
    std::string result = "";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u""));
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testToHex_012
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_012, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string(""));
    std::string result = "";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u""));
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testTruncateUtf16String_008
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_008, TestSize.Level0)
{
    std::u16string out(u"");
    StringUtils::TruncateUtf16String(out, 0);
    EXPECT_TRUE(out.empty());
}

/**
 * @tc.name: testToHex_013
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_013, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()"));
    std::string result = "6162636465666768696a6b6c6d6e6f707172737475767778797a3132333435363738393021402324255e262a282";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()"));
    result = "006100620063006400650066006700680069006a006b006c006d006e006f0070007100720073007400
        750076007700780079007a003100320033003400350036003700380039003000210040002300240025005e0026002a00280029";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_010
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_010, TestSize.Level0)
{
    char16_t inputChar[] = u"abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 30);
}

/**
 * @tc.name: testToHex_014
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_014, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a b c"));
    std::string result = "6120622063";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a b c"));
    result = "00610020006200200063";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_011
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_011, TestSize.Level0)
{
    char16_t inputChar[] = u"a b c";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 5);
}

/**
 * @tc.name: testTruncateUtf16String_009
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_009, TestSize.Level0)
{
    char16_t inputChar[] = u"a b c";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 2);
    std::u16string checkOut(inputChar, 2);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_015
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_015, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("!@#$%^&*()"));
    std::string result = "21402324255e262a2829";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"!@#$%^&*()"));
    result = "00210040002300240025005e0026002a00280029";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_012
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_012, TestSize.Level0)
{
    char16_t inputChar[] = u"!@#$%^&*()";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 10);
}

/**
 * @tc.name: testToHex_016
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_016, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\nb\nc"));
    std::string result = "610a620a63";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\nb\nc"));
    result = "0061000a0062000a0063";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_013
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_013, TestSize.Level0)
{
    char16_t inputChar[] = u"a\nb\nc";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 5);
}

/**
 * @tc.name: testTruncateUtf16String_010
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_010, TestSize.Level0)
{
    char16_t inputChar[] = u"a\nb\nc";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 3);
    std::u16string checkOut(inputChar, 3);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_017
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_017, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\tb\tc"));
    std::string result = "6109620963";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\tb\tc"));
    result = "00610009006200090063";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_014
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_014, TestSize.Level0)
{
    char16_t inputChar[] = u"a\tb\tc";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 5);
}

/**
 * @tc.name: testToHex_018
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_018, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("你好世界"));
    std::string result = "e4bda0e5a5bd";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"你好世界"));
    result = "4f60597d";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_015
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_015, TestSize.Level0)
{
    char16_t inputChar[] = u"你好世界";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 4);
}

/**
 * @tc.name: testTruncateUtf16String_011
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_011, TestSize.Level0)
{
    char16_t inputChar[] = u"你好世界";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 2);
    std::u16string checkOut(inputChar, 2);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_019
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_019, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a1你好@世界"));
    std::string result = "6131e4bda0e5a5bd";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a1你好@世界"));
    result = "006100314f60597d";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_016
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_016, TestSize.Level0)
{
    char16_t inputChar[] = u"a1你好@世界";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 6);
}

/**
 * @tc.name: testToHex_020
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_020, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\nb"));
    std::string result = "610a62";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\nb"));
    result = "0061000a0062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_017
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_017, TestSize.Level0)
{
    char16_t inputChar[] = u"a\nb";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testTruncateUtf16String_012
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_012, TestSize.Level0)
{
    char16_t inputChar[] = u"a\nb";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 1);
    std::u16string checkOut(inputChar, 1);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_021
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_021, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\tb"));
    std::string result = "610962";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\tb"));
    result = "006100090062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_018
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_018, TestSize.Level0)
{
    char16_t inputChar[] = u"a\tb";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testToHex_022
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_022, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\\b"));
    std::string result = "615c62";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\\b"));
    result = "0061005c0062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_019
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_019, TestSize.Level0)
{
    char16_t inputChar[] = u"a\\b";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testTruncateUtf16String_013
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_013, TestSize.Level0)
{
    char16_t inputChar[] = u"a\\b";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 2);
    std::u16string checkOut(inputChar, 2);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_023
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_023, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("ab"));
    std::string result = "61f09f889262";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"ab"));
    result = "0061835dc020062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_020
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_020, TestSize.Level0)
{
    char16_t inputChar[] = u"ab";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 4);
}

/**
 * @tc.name: testToHex_026
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_026, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\nb"));
    std::string result = "610a62";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\nb"));
    result = "0061000a0062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_023
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_023, TestSize.Level0)
{
    char16_t inputChar[] = u"a\nb";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testTruncateUtf16String_015
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_015, TestSize.Level0)
{
    char16_t inputChar[] = u"a\nb";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 2);
    std::u16string checkOut(inputChar, 2);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_027
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_027, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\tb"));
    std::string result = "610962";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\tb"));
    result = "006100090062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_024
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_024, TestSize.Level0)
{
    char16_t inputChar[] = u"a\tb";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testToHex_030
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_030, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\\b"));
    std::string result = "615c62";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\\b"));
    result = "0061005c0062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_027
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_027, TestSize.Level0)
{
    char16_t inputChar[] = u"a\\b";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testTruncateUtf16String_017
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_017, TestSize.Level0)
{
    char16_t inputChar[] = u"a\\b";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 2);
    std::u16string checkOut(inputChar, 2);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_031
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_031, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("\"a\""));
    std::string result = "226122";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"\"a\""));
    result = "002200610022";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_028
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_028, TestSize.Level0)
{
    char16_t inputChar[] = u"\"a\"";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testToHex_036
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_036, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a \nb"));
    std::string result = "61200a62";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a \nb"));
    result = "00610020000a0062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_033
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_033, TestSize.Level0)
{
    char16_t inputChar[] = u"a \nb";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 4);
}

/**
 * @tc.name: testTruncateUtf16String_019
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_019, TestSize.Level0)
{
    char16_t inputChar[] = u"a \nb";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 3);
    std::u16string checkOut(inputChar, 3);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_037
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_037, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\t\nb"));
    std::string result = "61090a62";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\t\nb"));
    result = "00610009000a0062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_034
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_034, TestSize.Level0)
{
    char16_t inputChar[] = u"a\t\nb";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 4);
}

/**
 * @tc.name: testToHex_042
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_042, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a你好b"));
    std::string result = "61e4bda0e5a5bd62";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a你好b"));
    result = "00614f60597d0062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_039
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_039, TestSize.Level0)
{
    char16_t inputChar[] = u"a你好b";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 5);
}

/**
 * @tc.name: testTruncateUtf16String_021
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_021, TestSize.Level0)
{
    char16_t inputChar[] = u"a你好b";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 4);
    std::u16string checkOut(inputChar, 4);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_043
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_043, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("!@#你好"));
    std::string result = "214023e4bda0e5a5bd";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"!@#你好"));
    result = "0021004000234f60597d";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_040
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_040, TestSize.Level0)
{
    char16_t inputChar[] = u"!@#你好";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 5);
}

/**
 * @tc.name: testToHex_046
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_046, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string(""));
    std::string result = "";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u""));
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_043
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_043, TestSize.Level0)
{
    std::u16string out(u"");
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 0);
}

/**
 * @tc.name: testTruncateUtf16String_023
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_023, TestSize.Level0)
{
    std::u16string out(u"");
    StringUtils::TruncateUtf16String(out, 0);
    EXPECT_TRUE(out.empty());
}

/**
 * @tc.name: testToHex_047
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_047, TestSize.Level0)
{
    std::string longStr(1000, 'a');
    std::string out = StringUtils::ToHex(longStr);
    std::string result(2000, '0');
    for (int i = 0; i < 1000; ++i) {
        result[i * 2] = '6';
        result[i * 2 + 1] = '1';
    }
    EXPECT_TRUE(out.compare(result) == 0);
    
    std::u16string longU16Str(1000, u'a');
    out = StringUtils::ToHex(longU16Str);
    result = "";
    for (int i = 0; i < 1000; ++i) {
        result += "0061";
    }
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_044
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_044, TestSize.Level0)
{
    std::u16string longStr(1000, u'a');
    auto charNum = StringUtils::CountUtf16Chars(longStr);
    EXPECT_EQ(charNum, 1000);
}

/**
 * @tc.name: testToHex_052
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_052, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\x80b"));
    std::string result = "618062";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\x80b"));
    result = "006100800062";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_049
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_049, TestSize.Level0)
{
    char16_t inputChar[] = u"a\x80b";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 3);
}

/**
 * @tc.name: testTruncateUtf16String_025
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testTruncateUtf16String_025, TestSize.Level0)
{
    char16_t inputChar[] = u"a\x80b";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    StringUtils::TruncateUtf16String(out, 2);
    std::u16string checkOut(inputChar, 2);
    EXPECT_TRUE(out.compare(checkOut) == 0);
}

/**
 * @tc.name: testToHex_053
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testToHex_053, TestSize.Level0)
{
    std::string out = StringUtils::ToHex(std::string("a\x80b你好"));
    std::string result = "618062e4bda0e5a5bd";
    EXPECT_TRUE(out.compare(result) == 0);
    
    out = StringUtils::ToHex(std::u16string(u"a\x80b你好"));
    result = "0061008000624f60597d";
    EXPECT_TRUE(out.compare(result) == 0);
}

/**
 * @tc.name: testCountUtf16Chars_050
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StringUtilsTest, testCountUtf16Chars_050, TestSize.Level0)
{
    char16_t inputChar[] = u"a\x80b你好";
    size_t inputLen = sizeof(inputChar) / sizeof(char16_t);
    std::u16string out(inputChar, inputLen);
    auto charNum = StringUtils::CountUtf16Chars(out);
    EXPECT_EQ(charNum, 5);
}
} // namespace MiscServices
} // namespace OHOS
