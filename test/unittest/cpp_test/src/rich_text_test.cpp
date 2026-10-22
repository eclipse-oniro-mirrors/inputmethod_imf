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

#include "input_method_controller.h"
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include "input_data_channel_service_impl.h"
#include "tdd_util.h"
#include "text_listener.h"
#include "variant_util.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
class RichTextTest : public testing::Test {
public:
    static sptr<InputMethodController> imc_;
    static sptr<OnTextChangedListener> textListener_;
    static void SetUpTestCase(void)
    {
        IMSA_HILOGI("RichTextTest::SetUpTestCase");
        TextListener::ResetParam();
        textListener_ = new TextListener();
        imc_ = InputMethodController::GetInstance();
    }
    static void TearDownTestCase(void)
    {
        IMSA_HILOGI("RichTextTest::TearDownTestCase");
        imc_->Close();
        TextListener::ResetParam();
    }
    void SetUp()
    {
        IMSA_HILOGI("RichTextTest::SetUp");
        TextListener::ResetParam();
    }
    void TearDown()
    {
        IMSA_HILOGI("RichTextTest::TearDown");
        TextListener::ResetParam();
    }
    static void GetIMCAttached()
    {
        imc_->SetTextListener(textListener_);
        imc_->clientInfo_.state = ClientState::ACTIVE;
        imc_->isBound_.store(true);
        imc_->isEditable_.store(true);
    }
    static void GetIMCDetached()
    {
        imc_->SetTextListener(nullptr);
        imc_->isBound_.store(false);
        imc_->isEditable_.store(false);
    }
};
sptr<InputMethodController> RichTextTest::imc_;
sptr<OnTextChangedListener> RichTextTest::textListener_;

/**
 * @tc.name: testRichTextDataEmpty01
 * @tc.desc: Test RichTextData IsEmpty.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testRichTextDataEmpty01, TestSize.Level1)
{
    RichTextData data;
    EXPECT_TRUE(data.IsEmpty());
    RichTextSpan span;
    span.type = SpanType::TEXT;
    span.range.start = 0;
    span.range.end = 5;
    span.content = "hello";
    data.spans.push_back(span);
    EXPECT_FALSE(data.IsEmpty());
}

/**
 * @tc.name: testRichTextSerialization01
 * @tc.desc: Test RichTextDataInner serialization and deserialization.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testRichTextSerialization01, TestSize.Level1)
{
    RichTextData data;
    RichTextSpan span1;
    span1.type = SpanType::TEXT;
    span1.range.start = 0;
    span1.range.end = 5;
    span1.content = "hello";
    data.spans.push_back(span1);

    RichTextSpan span2;
    span2.type = SpanType::IMAGE;
    span2.range.start = 5;
    span2.range.end = 6;
    span2.content = "image_tag";
    data.spans.push_back(span2);

    RichTextDataInner inner;
    inner.richTextData = data;

    Parcel parcel;
    bool ret = inner.Marshalling(parcel);
    EXPECT_TRUE(ret);

    auto *readInner = RichTextDataInner::Unmarshalling(parcel);
    ASSERT_NE(readInner, nullptr);
    EXPECT_EQ(readInner->richTextData.spans.size(), 2u);
    EXPECT_EQ(readInner->richTextData.spans[0].type, SpanType::TEXT);
    EXPECT_EQ(readInner->richTextData.spans[0].range.start, 0);
    EXPECT_EQ(readInner->richTextData.spans[0].range.end, 5);
    EXPECT_EQ(readInner->richTextData.spans[0].content, "hello");
    EXPECT_EQ(readInner->richTextData.spans[1].type, SpanType::IMAGE);
    EXPECT_EQ(readInner->richTextData.spans[1].range.start, 5);
    EXPECT_EQ(readInner->richTextData.spans[1].range.end, 6);
    EXPECT_EQ(readInner->richTextData.spans[1].content, "image_tag");
    delete readInner;
}

/**
 * @tc.name: testRichTextSerialization02
 * @tc.desc: Test RichTextDataInner serialization with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testRichTextSerialization02, TestSize.Level1)
{
    RichTextData data;
    RichTextDataInner inner;
    inner.richTextData = data;

    Parcel parcel;
    bool ret = inner.Marshalling(parcel);
    EXPECT_TRUE(ret);

    auto *readInner = RichTextDataInner::Unmarshalling(parcel);
    ASSERT_NE(readInner, nullptr);
    EXPECT_EQ(readInner->richTextData.spans.size(), 0u);
    EXPECT_TRUE(readInner->richTextData.IsEmpty());
    delete readInner;
}

/**
 * @tc.name: testRichTextSerialization03
 * @tc.desc: Test RichTextDataInner serialization with all span types.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testRichTextSerialization03, TestSize.Level1)
{
    RichTextData data;
    RichTextSpan span1;
    span1.type = SpanType::TEXT;
    span1.range.start = 0;
    span1.range.end = 3;
    span1.content = "abc";
    data.spans.push_back(span1);

    RichTextSpan span2;
    span2.type = SpanType::IMAGE;
    span2.range.start = 3;
    span2.range.end = 4;
    span2.content = "img";
    data.spans.push_back(span2);

    RichTextSpan span3;
    span3.type = SpanType::SYMBOL;
    span3.range.start = 4;
    span3.range.end = 5;
    span3.content = "sym";
    data.spans.push_back(span3);

    RichTextSpan span4;
    span4.type = SpanType::CUSTOM;
    span4.range.start = 5;
    span4.range.end = 6;
    span4.content = "custom";
    data.spans.push_back(span4);

    RichTextDataInner inner;
    inner.richTextData = data;

    Parcel parcel;
    bool ret = inner.Marshalling(parcel);
    EXPECT_TRUE(ret);

    auto *readInner = RichTextDataInner::Unmarshalling(parcel);
    ASSERT_NE(readInner, nullptr);
    EXPECT_EQ(readInner->richTextData.spans.size(), 4u);
    EXPECT_EQ(readInner->richTextData.spans[0].type, SpanType::TEXT);
    EXPECT_EQ(readInner->richTextData.spans[1].type, SpanType::IMAGE);
    EXPECT_EQ(readInner->richTextData.spans[2].type, SpanType::SYMBOL);
    EXPECT_EQ(readInner->richTextData.spans[3].type, SpanType::CUSTOM);
    delete readInner;
}

/**
 * @tc.name: testResponseDataRichText01
 * @tc.desc: Test ResponseData with RichTextData variant type.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testResponseDataRichText01, TestSize.Level1)
{
    RichTextData data;
    RichTextSpan span;
    span.type = SpanType::TEXT;
    span.range.start = 0;
    span.range.end = 5;
    span.content = "hello";
    data.spans.push_back(span);

    ResponseData responseData = data;
    EXPECT_EQ(responseData.index(), 3);

    RichTextData extracted;
    bool got = VariantUtil::GetValue(responseData, extracted);
    EXPECT_TRUE(got);
    EXPECT_EQ(extracted.spans.size(), 1u);
    EXPECT_EQ(extracted.spans[0].content, "hello");
}

/**
 * @tc.name: testGetLeftRichNotEditable01
 * @tc.desc: Test GetLeftRich when not editable.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetLeftRichNotEditable01, TestSize.Level1)
{
    GetIMCDetached();
    RichTextData richText;
    int32_t ret = imc_->GetLeftRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_TRUE(richText.IsEmpty());
}

/**
 * @tc.name: testGetRightRichNotEditable01
 * @tc.desc: Test GetRightRich when not editable.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetRightRichNotEditable01, TestSize.Level1)
{
    GetIMCDetached();
    RichTextData richText;
    int32_t ret = imc_->GetRightRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    EXPECT_TRUE(richText.IsEmpty());
}

/**
 * @tc.name: testGetLeftRichImageSpan01
 * @tc.desc: AC-1.1 Test GetLeftRich returns IMAGE span with correct type/content/range.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetLeftRichImageSpan01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;
    RichTextData richText;
    int32_t ret = imc_->GetLeftRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(richText.spans.size(), 2u);
    bool foundImage = false;
    for (const auto &span : richText.spans) {
        if (span.type == SpanType::IMAGE) {
            foundImage = true;
            EXPECT_EQ(span.content, "img_tag_left");
            EXPECT_GE(span.range.start, 0);
            EXPECT_GT(span.range.end, span.range.start);
        }
    }
    EXPECT_TRUE(foundImage);
}

/**
 * @tc.name: testGetLeftRichMixedSpans01
 * @tc.desc: AC-1.2 Test GetLeftRich returns mixed TEXT+IMAGE spans with non-overlapping ranges.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetLeftRichMixedSpans01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;
    RichTextData richText;
    int32_t ret = imc_->GetLeftRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(richText.spans.size(), 2u);
    EXPECT_EQ(richText.spans[0].type, SpanType::TEXT);
    EXPECT_EQ(richText.spans[1].type, SpanType::IMAGE);
    for (size_t i = 1; i < richText.spans.size(); i++) {
        EXPECT_LE(richText.spans[i - 1].range.end, richText.spans[i].range.start);
    }
}

/**
 * @tc.name: testGetLeftRichGetString01
 * @tc.desc: AC-1.3 Test getString logic: TEXT contributes content, IMAGE contributes space.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetLeftRichGetString01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;
    RichTextData richText;
    int32_t ret = imc_->GetLeftRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    std::string plainText;
    for (const auto &span : richText.spans) {
        if (span.type == SpanType::TEXT) {
            plainText += span.content;
        } else {
            plainText += " ";
        }
    }
    EXPECT_EQ(plainText, std::string(TextListener::TEXT_BEFORE_CURSOR) + " ");
}

/**
 * @tc.name: testGetLeftRichPlainTextFallback01
 * @tc.desc: AC-1.4 Test GetLeftRich plain text fallback when isRichText=false.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetLeftRichPlainTextFallback01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = false;
    RichTextData richText;
    int32_t ret = imc_->GetLeftRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(richText.spans.size(), 1u);
    EXPECT_EQ(richText.spans[0].type, SpanType::TEXT);
    bool hasImage = false;
    for (const auto &span : richText.spans) {
        if (span.type == SpanType::IMAGE) {
            hasImage = true;
        }
    }
    EXPECT_FALSE(hasImage);
}

/**
 * @tc.name: testGetRightRichImageSpan01
 * @tc.desc: AC-2.1 Test GetRightRich returns IMAGE span with correct type/content/range.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetRightRichImageSpan01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;
    RichTextData richText;
    int32_t ret = imc_->GetRightRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(richText.spans.size(), 2u);
    bool foundImage = false;
    for (const auto &span : richText.spans) {
        if (span.type == SpanType::IMAGE) {
            foundImage = true;
            EXPECT_EQ(span.content, "img_tag_right");
            EXPECT_GE(span.range.start, 0);
            EXPECT_GT(span.range.end, span.range.start);
        }
    }
    EXPECT_TRUE(foundImage);
}

/**
 * @tc.name: testGetRightRichMixedSpans01
 * @tc.desc: AC-2.2 Test GetRightRich returns mixed IMAGE+TEXT spans with non-overlapping ranges.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetRightRichMixedSpans01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;
    RichTextData richText;
    int32_t ret = imc_->GetRightRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(richText.spans.size(), 2u);
    EXPECT_EQ(richText.spans[0].type, SpanType::IMAGE);
    EXPECT_EQ(richText.spans[1].type, SpanType::TEXT);
    for (size_t i = 1; i < richText.spans.size(); i++) {
        EXPECT_LE(richText.spans[i - 1].range.end, richText.spans[i].range.start);
    }
}

/**
 * @tc.name: testGetRightRichGetString01
 * @tc.desc: AC-2.3 Test getString logic for right side: IMAGE contributes space, TEXT contributes content.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetRightRichGetString01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;
    RichTextData richText;
    int32_t ret = imc_->GetRightRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    std::string plainText;
    for (const auto &span : richText.spans) {
        if (span.type == SpanType::TEXT) {
            plainText += span.content;
        } else {
            plainText += " ";
        }
    }
    EXPECT_EQ(plainText, std::string(" ") + std::string(TextListener::TEXT_AFTER_CURSOR));
}

/**
 * @tc.name: testGetRightRichPlainTextFallback01
 * @tc.desc: AC-2.4 Test GetRightRich plain text fallback when isRichText=false.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetRightRichPlainTextFallback01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = false;
    RichTextData richText;
    int32_t ret = imc_->GetRightRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(richText.spans.size(), 1u);
    EXPECT_EQ(richText.spans[0].type, SpanType::TEXT);
    bool hasImage = false;
    for (const auto &span : richText.spans) {
        if (span.type == SpanType::IMAGE) {
            hasImage = true;
        }
    }
    EXPECT_FALSE(hasImage);
}

/**
 * @tc.name: testGetLeftRichAsyncConsistency01
 * @tc.desc: AC-1.5 Test GetLeftRich with V2 listener returns same data as direct listener call.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetLeftRichAsyncConsistency01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;
    RichTextData syncRichText;
    int32_t ret = imc_->GetLeftRich(10, syncRichText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    auto listener = imc_->GetTextListener();
    ASSERT_NE(listener, nullptr);
    RichTextData listenerRichText = listener->GetLeftRichTextOfCursor(10);
    EXPECT_EQ(syncRichText.spans.size(), listenerRichText.spans.size());
    for (size_t i = 0; i < syncRichText.spans.size(); i++) {
        EXPECT_EQ(syncRichText.spans[i].type, listenerRichText.spans[i].type);
        EXPECT_EQ(syncRichText.spans[i].content, listenerRichText.spans[i].content);
        EXPECT_EQ(syncRichText.spans[i].range.start, listenerRichText.spans[i].range.start);
        EXPECT_EQ(syncRichText.spans[i].range.end, listenerRichText.spans[i].range.end);
    }
}

/**
 * @tc.name: testGetRightRichAsyncConsistency01
 * @tc.desc: AC-2.5 Test GetRightRich with V2 listener returns same data as direct listener call.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetRightRichAsyncConsistency01, TestSize.Level1)
{
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;
    RichTextData syncRichText;
    int32_t ret = imc_->GetRightRich(10, syncRichText);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    auto listener = imc_->GetTextListener();
    ASSERT_NE(listener, nullptr);
    RichTextData listenerRichText = listener->GetRightRichTextOfCursor(10);
    EXPECT_EQ(syncRichText.spans.size(), listenerRichText.spans.size());
    for (size_t i = 0; i < syncRichText.spans.size(); i++) {
        EXPECT_EQ(syncRichText.spans[i].type, listenerRichText.spans[i].type);
        EXPECT_EQ(syncRichText.spans[i].content, listenerRichText.spans[i].content);
        EXPECT_EQ(syncRichText.spans[i].range.start, listenerRichText.spans[i].range.start);
        EXPECT_EQ(syncRichText.spans[i].range.end, listenerRichText.spans[i].range.end);
    }
}

// ===== IPC size limit tests for RichTextData::GetIpcSize / IsSizeValid =====

// Build a span whose IPC footprint is exactly footprintBytes.
// Per-span IPC size = SPAN_HEADER_SIZE + content.size().
static RichTextSpan BuildSpanWithFootprint(size_t footprintBytes)
{
    RichTextSpan span;
    span.type = SpanType::TEXT;
    span.range.start = 0;
    span.range.end = 1;
    if (footprintBytes >= SPAN_HEADER_SIZE) {
        span.content = std::string(footprintBytes - SPAN_HEADER_SIZE, 'x');
    }
    return span;
}

/**
 * @tc.name: testGetIpcSizeEmpty01
 * @tc.desc: Test GetIpcSize returns 0 when spans is empty.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetIpcSizeEmpty01, TestSize.Level1)
{
    RichTextData data;
    EXPECT_EQ(data.spans.size(), 0u);
    EXPECT_EQ(data.GetIpcSize(), 0u);
}

/**
 * @tc.name: testGetIpcSizeSingleSpan01
 * @tc.desc: Test GetIpcSize returns SPAN_HEADER_SIZE + content.size() for a single span.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetIpcSizeSingleSpan01, TestSize.Level1)
{
    RichTextData data;
    const std::string content = "hello";
    RichTextSpan span;
    span.type = SpanType::TEXT;
    span.range.start = 0;
    span.range.end = static_cast<int32_t>(content.size());
    span.content = content;
    data.spans.push_back(span);
    // Per-span IPC size = sizeof(uint32_t) type + sizeof(int32_t) range.start + sizeof(int32_t) range.end + content
    const size_t expected = sizeof(uint32_t) + sizeof(int32_t) + sizeof(int32_t) + content.size();
    EXPECT_EQ(data.GetIpcSize(), expected);
}

/**
 * @tc.name: testGetIpcSizeMultipleSpans01
 * @tc.desc: Test GetIpcSize accumulates size across multiple spans.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetIpcSizeMultipleSpans01, TestSize.Level1)
{
    RichTextData data;
    const std::string c1 = "abc";
    const std::string c2 = "de";
    RichTextSpan span1;
    span1.type = SpanType::TEXT;
    span1.range.start = 0;
    span1.range.end = 3;
    span1.content = c1;
    RichTextSpan span2;
    span2.type = SpanType::IMAGE;
    span2.range.start = 3;
    span2.range.end = 4;
    span2.content = c2;
    data.spans.push_back(span1);
    data.spans.push_back(span2);
    const size_t expected = (SPAN_HEADER_SIZE + c1.size()) + (SPAN_HEADER_SIZE + c2.size());
    EXPECT_EQ(data.GetIpcSize(), expected);
}

/**
 * @tc.name: testGetIpcSizeAtLimit01
 * @tc.desc: Test GetIpcSize equals MAX_RICH_TEXT_SIZE at the 128KB boundary (4096 spans x 32 bytes each).
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetIpcSizeAtLimit01, TestSize.Level1)
{
    RichTextData data;
    const size_t perSpanFootprint = 32; // SPAN_HEADER_SIZE (header) + 20 (content)
    const size_t spanCount = MAX_RICH_TEXT_SIZE / perSpanFootprint; // 131072 / 32 = 4096
    EXPECT_EQ(spanCount * perSpanFootprint, MAX_RICH_TEXT_SIZE);
    for (size_t i = 0; i < spanCount; i++) {
        data.spans.push_back(BuildSpanWithFootprint(perSpanFootprint));
    }
    EXPECT_EQ(data.spans.size(), spanCount);
    EXPECT_EQ(data.GetIpcSize(), MAX_RICH_TEXT_SIZE);
}

/**
 * @tc.name: testIsSizeValidEmpty01
 * @tc.desc: Test IsSizeValid returns true for empty rich text data.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testIsSizeValidEmpty01, TestSize.Level1)
{
    RichTextData data;
    EXPECT_EQ(data.GetIpcSize(), 0u);
    EXPECT_TRUE(data.IsSizeValid());
}

/**
 * @tc.name: testIsSizeValidAtLimit01
 * @tc.desc: Test IsSizeValid returns true when size equals MAX_RICH_TEXT_SIZE (128KB boundary).
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testIsSizeValidAtLimit01, TestSize.Level1)
{
    RichTextData data;
    const size_t perSpanFootprint = 32;
    const size_t spanCount = MAX_RICH_TEXT_SIZE / perSpanFootprint;
    for (size_t i = 0; i < spanCount; i++) {
        data.spans.push_back(BuildSpanWithFootprint(perSpanFootprint));
    }
    EXPECT_EQ(data.GetIpcSize(), MAX_RICH_TEXT_SIZE);
    EXPECT_TRUE(data.IsSizeValid());
}

/**
 * @tc.name: testIsSizeValidOverLimit01
 * @tc.desc: Test IsSizeValid returns false when size exceeds MAX_RICH_TEXT_SIZE by one byte.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testIsSizeValidOverLimit01, TestSize.Level1)
{
    RichTextData data;
    // One span at the limit, plus one extra byte to exceed it.
    data.spans.push_back(BuildSpanWithFootprint(MAX_RICH_TEXT_SIZE));
    EXPECT_EQ(data.GetIpcSize(), MAX_RICH_TEXT_SIZE);
    EXPECT_TRUE(data.IsSizeValid());
    // Add one more span (SPAN_HEADER_SIZE bytes minimum) to push size over the limit.
    data.spans.push_back(BuildSpanWithFootprint(SPAN_HEADER_SIZE));
    EXPECT_GT(data.GetIpcSize(), MAX_RICH_TEXT_SIZE);
    EXPECT_FALSE(data.IsSizeValid());
}

/**
 * @tc.name: testMaxRichTextSizeConstant01
 * @tc.desc: Test MAX_RICH_TEXT_SIZE constant equals 128 * 1024 (131072).
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testMaxRichTextSizeConstant01, TestSize.Level1)
{
    EXPECT_EQ(MAX_RICH_TEXT_SIZE, 128u * 1024u);
    EXPECT_EQ(MAX_RICH_TEXT_SIZE, 131072u);
}

// Test listener that returns oversized RichTextData to trigger the IPC size-limit path.
class OversizedTextListener : public TextListener {
public:
    RichTextData GetLeftRichTextOfCursor(int32_t number) override
    {
        RichTextData data;
        // Build a single span whose IPC footprint exceeds MAX_RICH_TEXT_SIZE by 1 byte.
        data.spans.push_back(BuildSpanWithFootprint(MAX_RICH_TEXT_SIZE + 1));
        return data;
    }

    RichTextData GetRightRichTextOfCursor(int32_t number) override
    {
        RichTextData data;
        data.spans.push_back(BuildSpanWithFootprint(MAX_RICH_TEXT_SIZE + 1));
        return data;
    }
};

/**
 * @tc.name: testGetLeftRichOversize01
 * @tc.desc: Test GetLeftRich returns ERROR_IMA_DATA_CHANNEL_ABNORMAL and clears spans when size exceeds limit.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetLeftRichOversize01, TestSize.Level1)
{
    sptr<OversizedTextListener> oversizedListener = new OversizedTextListener();
    imc_->SetTextListener(oversizedListener);
    imc_->clientInfo_.state = ClientState::ACTIVE;
    imc_->isBound_.store(true);
    imc_->isEditable_.store(true);
    imc_->textConfig_.inputAttribute.isRichText = true;

    RichTextData richText;
    int32_t ret = imc_->GetLeftRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(richText.spans.empty());

    // Cleanup: restore default listener state.
    imc_->SetTextListener(textListener_);
}

/**
 * @tc.name: testGetRightRichOversize01
 * @tc.desc: Test GetRightRich returns ERROR_IMA_DATA_CHANNEL_ABNORMAL and clears spans when size exceeds limit.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testGetRightRichOversize01, TestSize.Level1)
{
    sptr<OversizedTextListener> oversizedListener = new OversizedTextListener();
    imc_->SetTextListener(oversizedListener);
    imc_->clientInfo_.state = ClientState::ACTIVE;
    imc_->isBound_.store(true);
    imc_->isEditable_.store(true);
    imc_->textConfig_.inputAttribute.isRichText = true;

    RichTextData richText;
    int32_t ret = imc_->GetRightRich(10, richText);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
    EXPECT_TRUE(richText.spans.empty());

    // Cleanup: restore default listener state.
    imc_->SetTextListener(textListener_);
}

// ===== InputDataChannelServiceImpl::GetRichBeforeCursor / GetRichAfterCursor tests =====

/**
 * @tc.name: testDataChannelServiceImplGetRichBefore01
 * @tc.desc: Test InputDataChannelServiceImpl::GetRichBeforeCursor normal branch (instance != nullptr).
 *           When agent is nullptr, ResponseDataChannel returns ERROR_IME_NOT_STARTED internally,
 *           but GetRichBeforeCursor returns the GetLeftRich result.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testDataChannelServiceImplGetRichBefore01, TestSize.Level1)
{
    // Prepare IMC attached state so GetLeftRich succeeds.
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;

    sptr<InputDataChannelServiceImpl> serviceImpl = new InputDataChannelServiceImpl();
    ASSERT_NE(serviceImpl, nullptr);
    uint64_t msgId = 1001;
    // agent is nullptr: ResponseDataChannel will return ERROR_IME_NOT_STARTED but the function
    // still returns the GetLeftRich result (NO_ERROR) because ret is captured before ResponseDataChannel.
    ErrCode ret = serviceImpl->GetRichBeforeCursor(10, msgId, nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    // Detached state: GetLeftRich returns ERROR_CLIENT_NOT_EDITABLE.
    GetIMCDetached();
    ret = serviceImpl->GetRichBeforeCursor(10, msgId, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
}

/**
 * @tc.name: testDataChannelServiceImplGetRichAfter01
 * @tc.desc: Test InputDataChannelServiceImpl::GetRichAfterCursor normal branch (instance != nullptr).
 *           When agent is nullptr, ResponseDataChannel returns ERROR_IME_NOT_STARTED internally,
 *           but GetRichAfterCursor returns the GetRightRich result.
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testDataChannelServiceImplGetRichAfter01, TestSize.Level1)
{
    // Prepare IMC attached state so GetRightRich succeeds.
    GetIMCAttached();
    imc_->textConfig_.inputAttribute.isRichText = true;

    sptr<InputDataChannelServiceImpl> serviceImpl = new InputDataChannelServiceImpl();
    ASSERT_NE(serviceImpl, nullptr);
    uint64_t msgId = 1002;
    ErrCode ret = serviceImpl->GetRichAfterCursor(10, msgId, nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    // Detached state: GetRightRich returns ERROR_CLIENT_NOT_EDITABLE.
    GetIMCDetached();
    ret = serviceImpl->GetRichAfterCursor(10, msgId, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
}

/**
 * @tc.name: testDataChannelServiceImplGetRichBeforeOversize01
 * @tc.desc: Test InputDataChannelServiceImpl::GetRichBeforeCursor returns ERROR_IMA_DATA_CHANNEL_ABNORMAL
 *           when listener returns oversized RichTextData (IsSizeValid == false).
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testDataChannelServiceImplGetRichBeforeOversize01, TestSize.Level1)
{
    sptr<OversizedTextListener> oversizedListener = new OversizedTextListener();
    imc_->SetTextListener(oversizedListener);
    imc_->clientInfo_.state = ClientState::ACTIVE;
    imc_->isBound_.store(true);
    imc_->isEditable_.store(true);
    imc_->textConfig_.inputAttribute.isRichText = true;

    sptr<InputDataChannelServiceImpl> serviceImpl = new InputDataChannelServiceImpl();
    ASSERT_NE(serviceImpl, nullptr);
    uint64_t msgId = 1003;
    ErrCode ret = serviceImpl->GetRichBeforeCursor(10, msgId, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);

    // Cleanup: restore default listener state.
    imc_->SetTextListener(textListener_);
}

/**
 * @tc.name: testDataChannelServiceImplGetRichAfterOversize01
 * @tc.desc: Test InputDataChannelServiceImpl::GetRichAfterCursor returns ERROR_IMA_DATA_CHANNEL_ABNORMAL
 *           when listener returns oversized RichTextData (IsSizeValid == false).
 * @tc.type: FUNC
 */
HWTEST_F(RichTextTest, testDataChannelServiceImplGetRichAfterOversize01, TestSize.Level1)
{
    sptr<OversizedTextListener> oversizedListener = new OversizedTextListener();
    imc_->SetTextListener(oversizedListener);
    imc_->clientInfo_.state = ClientState::ACTIVE;
    imc_->isBound_.store(true);
    imc_->isEditable_.store(true);
    imc_->textConfig_.inputAttribute.isRichText = true;

    sptr<InputDataChannelServiceImpl> serviceImpl = new InputDataChannelServiceImpl();
    ASSERT_NE(serviceImpl, nullptr);
    uint64_t msgId = 1004;
    ErrCode ret = serviceImpl->GetRichAfterCursor(10, msgId, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);

    // Cleanup: restore default listener state.
    imc_->SetTextListener(textListener_);
}
} // namespace MiscServices
} // namespace OHOS
