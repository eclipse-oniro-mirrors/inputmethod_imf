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
#include "inputmethod_controller_capi_test.h"

#include "global.h"
#include "native_inputmethod_types.h"
#include "native_object_registry.h"
#include "string_ex.h"

using namespace testing::ext;

namespace OHOS {
namespace MiscServices {
/**
 * @tc.name: TestCursorInfo_001
 * @tc.desc: create and destroy TestCursorInfo success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TestCursorInfo_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::TestCursorInfo_001 START");
    double expLeft = 1.1;
    double expTop = 2.2;
    double expWidth = 3.3;
    double expHeight = 4.4;
    auto cursorInfo = OH_CursorInfo_Create(expLeft, expTop, expWidth, expHeight);
    ASSERT_NE(nullptr, cursorInfo);

    double actLeft = 0;
    double actTop = 0;
    double actWidth = 0;
    double actHeight = 0;
    EXPECT_EQ(IME_ERR_OK, OH_CursorInfo_GetRect(cursorInfo, &actLeft, &actTop, &actWidth, &actHeight));
    EXPECT_EQ(expLeft, actLeft);
    EXPECT_EQ(expTop, actTop);
    EXPECT_EQ(expWidth, actWidth);
    EXPECT_EQ(expHeight, actHeight);

    // test set rect
    expLeft = 1;
    expTop = 2;
    expWidth = 3;
    expHeight = 4;
    EXPECT_EQ(IME_ERR_OK, OH_CursorInfo_SetRect(cursorInfo, expLeft, expTop, expWidth, expHeight));
    EXPECT_EQ(IME_ERR_OK, OH_CursorInfo_GetRect(cursorInfo, &actLeft, &actTop, &actWidth, &actHeight));
    EXPECT_EQ(expLeft, actLeft);
    EXPECT_EQ(expTop, actTop);
    EXPECT_EQ(expWidth, actWidth);
    EXPECT_EQ(expHeight, actHeight);

    OH_CursorInfo_Destroy(cursorInfo);
}

static void TestCursorInfoOfTextConfig(InputMethod_TextConfig *config)
{
    InputMethod_CursorInfo *cursorInfo = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetCursorInfo(config, &cursorInfo));
    // test set and get cursorInfo rect
    double expLeft = 1.1;
    double expTop = 2.2;
    double expWidth = 3.3;
    double expHeight = 4.4;
    EXPECT_EQ(IME_ERR_OK, OH_CursorInfo_SetRect(cursorInfo, expLeft, expTop, expWidth, expHeight));
    double actLeft = 0.0;
    double actTop = 0.0;
    double actWidth = 0.0;
    double actHeight = 0.0;
    EXPECT_EQ(IME_ERR_OK, OH_CursorInfo_GetRect(cursorInfo, &actLeft, &actTop, &actWidth, &actHeight));
    EXPECT_EQ(expLeft, actLeft);
    EXPECT_EQ(expTop, actTop);
    EXPECT_EQ(expWidth, actWidth);
    EXPECT_EQ(expHeight, actHeight);
}

/**
 * @tc.name: TestTextConfig_001
 * @tc.desc: create and destroy TestTextConfig success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TestTextConfig_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::TestTextConfig_001 START");
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);

    // test set and get inputType
    InputMethod_TextInputType expInputType = IME_TEXT_INPUT_TYPE_NUMBER_DECIMAL;
    InputMethod_TextInputType actInputType = IME_TEXT_INPUT_TYPE_NONE;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetInputType(config, expInputType));
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetInputType(config, &actInputType));
    EXPECT_EQ(expInputType, actInputType);

    // test set and get enterKeyType
    InputMethod_EnterKeyType expEnterKeyType = IME_ENTER_KEY_SEARCH;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetEnterKeyType(config, expEnterKeyType));
    InputMethod_EnterKeyType actEnterKeyType = IME_ENTER_KEY_UNSPECIFIED;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetEnterKeyType(config, &actEnterKeyType));
    EXPECT_EQ(expEnterKeyType, actEnterKeyType);

    // test set and get isPreviewTextSupported
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetPreviewTextSupport(config, true));
    bool isPreviewTextSupported = false;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_IsPreviewTextSupported(config, &isPreviewTextSupported));
    EXPECT_TRUE(isPreviewTextSupported);

    // test set and get consumeKeyEvents
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetConsumeKeyEvents(config, true));
    bool consumeKeyEvents = false;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetConsumeKeyEvents(config, &consumeKeyEvents));
    EXPECT_TRUE(consumeKeyEvents);

    // test set and get selection
    int32_t expStart = 1;
    int32_t expEnd = 2;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetSelection(config, expStart, expEnd));
    int32_t actStart = 0;
    int32_t actEnd = 0;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetSelection(config, &actStart, &actEnd));
    EXPECT_EQ(expStart, actStart);
    EXPECT_EQ(expEnd, actEnd);

    // test set and get windowId
    int32_t expWindowId = 1;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetWindowId(config, expWindowId));
    int32_t actWindowId = 0;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetWindowId(config, &actWindowId));
    EXPECT_EQ(expWindowId, actWindowId);

    TestCursorInfoOfTextConfig(config);

    InputMethod_TextAvoidInfo *textAvoidInfo = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetTextAvoidInfo(config, &textAvoidInfo));

    // test set and get text avoid info member
    double expPositionY = 10.0;
    double expHeight = 20.0;
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_SetPositionY(textAvoidInfo, expPositionY));
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_SetHeight(textAvoidInfo, expHeight));
    double actPositionY = 0.0;
    double actHeight = 0.0;
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_GetPositionY(textAvoidInfo, &actPositionY));
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_GetHeight(textAvoidInfo, &actHeight));
    EXPECT_EQ(expPositionY, actPositionY);
    EXPECT_EQ(expHeight, actHeight);

    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: TestTextConfig_002
 * @tc.desc: create and destroy TestTextConfig success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TestTextConfig_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::TestTextConfig_002 START");
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);

    // test set and get inputType
    InputMethod_TextInputType expInputType = IME_TEXT_INPUT_TYPE_ONE_TIME_CODE;
    InputMethod_TextInputType actInputType = IME_TEXT_INPUT_TYPE_NONE;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetInputType(config, expInputType));
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetInputType(config, &actInputType));
    EXPECT_EQ(expInputType, actInputType);
    OH_TextConfig_Destroy(config);
}

static void CheckInvalidTextConfig(InputMethod_TextConfig *config)
{
    InputMethod_TextInputType inputType = IME_TEXT_INPUT_TYPE_NONE;
    InputMethod_EnterKeyType enterKey = IME_ENTER_KEY_UNSPECIFIED;
    InputMethod_CursorInfo *cursor = nullptr;
    InputMethod_TextAvoidInfo *avoid = nullptr;
    bool enabled = false;
    int32_t start = -1;
    int32_t end = -1;
    int32_t windowId = -1;
    constexpr size_t textBufferSize = 2;
    constexpr int32_t selectionEnd = 2;
    char16_t text[textBufferSize] = { u'x', u'\0' };
    size_t length = textBufferSize;
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_SetInputType(config, inputType));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_SetEnterKeyType(config, enterKey));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_SetPreviewTextSupport(config, true));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_SetSelection(config, 1, selectionEnd));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_SetWindowId(config, 1));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_SetPlaceholder(config, text, 1));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_SetAbilityName(config, text, 1));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_SetConsumeKeyEvents(config, true));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetInputType(config, &inputType));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetEnterKeyType(config, &enterKey));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_IsPreviewTextSupported(config, &enabled));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetCursorInfo(config, &cursor));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetTextAvoidInfo(config, &avoid));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetSelection(config, &start, &end));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetWindowId(config, &windowId));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetPlaceholder(config, text, &length));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetAbilityName(config, text, &length));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetConsumeKeyEvents(config, &enabled));
    EXPECT_EQ(nullptr, cursor);
    EXPECT_EQ(nullptr, avoid);
    EXPECT_EQ(-1, start);
    EXPECT_EQ(-1, end);
    EXPECT_EQ(-1, windowId);
    EXPECT_FALSE(enabled);
    EXPECT_EQ(u'x', text[0]);
    EXPECT_EQ(textBufferSize, length);
}

/**
 * @tc.name: TextConfig_RejectUnregisteredHandle
 * @tc.desc: Non-null storage not created by the C API is rejected by every accessor.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TextConfig_RejectUnregisteredHandle, TestSize.Level0)
{
    InputMethod_TextConfig config {};
    CheckInvalidTextConfig(&config);
    EXPECT_EQ(0, config.windowId);
    EXPECT_FALSE(config.consumeKeyEvents);
}

/**
 * @tc.name: TextConfig_RejectRetiredHandle
 * @tc.desc: A storage lease cannot make a destroyed handle valid again.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TextConfig_RejectRetiredHandle, TestSize.Level0)
{
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);
    auto lease = NativeObjectRegistry<InputMethod_TextConfig>::GetInstance().Get(config);
    ASSERT_NE(nullptr, lease);
    OH_TextConfig_Destroy(config);
    CheckInvalidTextConfig(config);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: TextConfig_BorrowedChildrenFollowParentLifetime
 * @tc.desc: Destroying a borrowed child is rejected; retiring the parent invalidates both views.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TextConfig_BorrowedChildrenFollowParentLifetime, TestSize.Level0)
{
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);
    auto lease = NativeObjectRegistry<InputMethod_TextConfig>::GetInstance().Get(config);
    InputMethod_CursorInfo *cursor = nullptr;
    InputMethod_TextAvoidInfo *avoid = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetCursorInfo(config, &cursor));
    EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetTextAvoidInfo(config, &avoid));
    ASSERT_NE(nullptr, cursor);
    ASSERT_NE(nullptr, avoid);
    OH_CursorInfo_Destroy(cursor);
    OH_TextAvoidInfo_Destroy(avoid);
    EXPECT_EQ(IME_ERR_OK, OH_CursorInfo_SetRect(cursor, 1, 2, 3, 4));
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_SetPositionY(avoid, 5));
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_SetHeight(avoid, 6));
    OH_TextConfig_Destroy(config);
    double value = -1;
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_CursorInfo_GetRect(cursor, &value, &value, &value, &value));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_CursorInfo_SetRect(cursor, 0, 0, 0, 0));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextAvoidInfo_GetPositionY(avoid, &value));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextAvoidInfo_GetHeight(avoid, &value));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextAvoidInfo_SetPositionY(avoid, 0));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextAvoidInfo_SetHeight(avoid, 0));
    EXPECT_EQ(-1, value);
}

/**
 * @tc.name: OH_CursorInfo_SetRect_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_CursorInfo_SetRect_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_CursorInfo_SetRect_001 START");
    double left = 0;
    double top = 0;
    double width = 0;
    double height = 0;
    auto ret = OH_CursorInfo_SetRect(nullptr, left, top, width, height);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_CursorInfo_GetRect_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_CursorInfo_GetRect_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_CursorInfo_GetRect_001 START");
    double left = 0;
    double top = 0;
    double width = 0;
    double height = 0;
    auto ret = OH_CursorInfo_GetRect(nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    auto info = OH_CursorInfo_Create(left, top, width, height);
    ret = OH_CursorInfo_GetRect(info, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_CursorInfo_GetRect(info, &left, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_CursorInfo_GetRect(info, &left, &top, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_CursorInfo_GetRect(info, &left, &top, &width, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_CursorInfo_Destroy(info);
}

/**
 * @tc.name: OH_TextConfig_SetInputType_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetInputType_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetInputType_001 START");
    InputMethod_TextInputType inputType = IME_TEXT_INPUT_TYPE_TEXT;
    auto ret = OH_TextConfig_SetInputType(nullptr, inputType);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_TextConfig_SetEnterKeyType_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetEnterKeyType_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetEnterKeyType_001 START");
    InputMethod_EnterKeyType enterKeyType = IME_ENTER_KEY_UNSPECIFIED;
    auto ret = OH_TextConfig_SetEnterKeyType(nullptr, enterKeyType);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_TextConfig_SetPreviewTextSupport_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetPreviewTextSupport_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetPreviewTextSupport_001 START");
    bool supported = false;
    auto ret = OH_TextConfig_SetPreviewTextSupport(nullptr, supported);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_TextConfig_SetConsumeKeyEvents_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetConsumeKeyEvents_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetConsumeKeyEvents_001 START");
    bool supported = false;
    auto ret = OH_TextConfig_SetConsumeKeyEvents(nullptr, supported);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_TextConfig_SetSelection_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetSelection_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetSelection_001 START");
    int32_t start = 0;
    int32_t end = 0;
    auto ret = OH_TextConfig_SetSelection(nullptr, start, end);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_TextConfig_SetWindowId_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetWindowId_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetWindowId_001 START");
    int32_t windowId = 0;
    auto ret = OH_TextConfig_SetWindowId(nullptr, windowId);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_TextConfig_GetInputType_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_GetInputType_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_GetInputType_001 START");
    auto ret = OH_TextConfig_GetInputType(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextConfig *config = OH_TextConfig_Create();
    ASSERT_NE(config, nullptr);
    ret = OH_TextConfig_GetInputType(config, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_GetEnterKeyType_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_GetEnterKeyType_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_GetEnterKeyType_001 START");
    auto ret = OH_TextConfig_GetEnterKeyType(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextConfig *config = OH_TextConfig_Create();
    ASSERT_NE(config, nullptr);
    ret = OH_TextConfig_GetEnterKeyType(config, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_IsPreviewTextSupported_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_IsPreviewTextSupported_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_IsPreviewTextSupported_001 START");
    auto ret = OH_TextConfig_IsPreviewTextSupported(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextConfig *config = OH_TextConfig_Create();
    ASSERT_NE(config, nullptr);
    ret = OH_TextConfig_IsPreviewTextSupported(config, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_GetConsumeKeyEvents_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_GetConsumeKeyEvents_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_GetConsumeKeyEvents_001 START");
    auto ret = OH_TextConfig_GetConsumeKeyEvents(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextConfig *config = OH_TextConfig_Create();
    ASSERT_NE(config, nullptr);
    ret = OH_TextConfig_GetConsumeKeyEvents(config, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_GetCursorInfo_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_GetCursorInfo_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_GetCursorInfo_001 START");
    auto ret = OH_TextConfig_GetCursorInfo(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextConfig *config = OH_TextConfig_Create();
    ASSERT_NE(config, nullptr);
    ret = OH_TextConfig_GetCursorInfo(config, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_GetTextAvoidInfo_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_GetTextAvoidInfo_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_GetTextAvoidInfo_001 START");
    auto ret = OH_TextConfig_GetTextAvoidInfo(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextConfig *config = OH_TextConfig_Create();
    ASSERT_NE(config, nullptr);
    ret = OH_TextConfig_GetTextAvoidInfo(config, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_GetSelection_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_GetSelection_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_GetSelection_001 START");
    auto ret = OH_TextConfig_GetSelection(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextConfig *config = OH_TextConfig_Create();
    ASSERT_NE(config, nullptr);
    ret = OH_TextConfig_GetSelection(config, nullptr, nullptr);
    EXPECT_EQ(IME_ERR_NULL_POINTER, ret);
    int32_t start = 0;
    ret = OH_TextConfig_GetSelection(config, &start, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_GetWindowId_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_GetWindowId_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_GetWindowId_001 START");
    auto ret = OH_TextConfig_GetWindowId(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextConfig *config = OH_TextConfig_Create();
    ASSERT_NE(config, nullptr);
    ret = OH_TextConfig_GetWindowId(config, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_SetPlaceholder_001
 * @tc.desc: Input parameters are valid
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetPlaceholder_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetPlaceholder_001 START");
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);
    std::u16string input = u"test";
    auto ret = OH_TextConfig_SetPlaceholder(config, input.data(), input.size());
    EXPECT_EQ(ret, IME_ERR_OK);
    ret = OH_TextConfig_GetPlaceholder(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_TextConfig_GetPlaceholder(config, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    size_t outLen = 513;
    char16_t pOut[513] = {};
    ret = OH_TextConfig_GetPlaceholder(config, pOut, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    outLen = 1;
    ret = OH_TextConfig_GetPlaceholder(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_PARAMCHECK);
    EXPECT_EQ(outLen - 1, input.size());
    outLen = 513;
    ret = OH_TextConfig_GetPlaceholder(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    EXPECT_EQ(outLen - 1, input.size());
    outLen = input.size();
    ret = OH_TextConfig_GetPlaceholder(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_PARAMCHECK);
    std::u16string out(pOut, outLen);
    EXPECT_GT(out.size(), input.size());
    outLen = 4;
    ret = OH_TextConfig_GetPlaceholder(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_PARAMCHECK);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_SetPlaceholder_002
 * @tc.desc: Invalid test input parameter
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetPlaceholder_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetPlaceholder_002 START");
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);
    std::u16string input = u"test";
    auto ret = OH_TextConfig_SetPlaceholder(config, input.data(), input.size());
    EXPECT_EQ(ret, IME_ERR_OK);
    ret = OH_TextConfig_SetPlaceholder(config, nullptr, 0);
    EXPECT_EQ(ret, IME_ERR_OK);
    size_t outLen = 512;
    char16_t pOut[512] = {};
    ret = OH_TextConfig_GetPlaceholder(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    EXPECT_EQ(outLen, 1);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_SetPlaceholder_003
 * @tc.desc: Invalid test input parameter
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetPlaceholder_003, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetPlaceholder_003 START");
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);
    auto ret = OH_TextConfig_SetPlaceholder(config, nullptr, 257);
    EXPECT_EQ(ret, IME_ERR_OK);
    ret = OH_TextConfig_SetPlaceholder(config, nullptr, 1);
    EXPECT_EQ(ret, IME_ERR_OK);
    ret = OH_TextConfig_SetPlaceholder(nullptr, nullptr, 1);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    std::u16string input = u"";
    for (int i = 0; i < MAX_PLACEHOLDER_SIZE; ++i) {
        input.append(u"𪛊");
    }
    IMSA_HILOGI("inputLen:%{public}zu,input:%{public}s", input.size(), Str16ToStr8(input).c_str());
    ret = OH_TextConfig_SetPlaceholder(config, input.data(), input.size());
    EXPECT_EQ(ret, IME_ERR_OK);
    std::u16string out(MAX_PLACEHOLDER_INPUT_SIZE, u'\0');
    size_t outLen = out.size();
    ret = OH_TextConfig_GetPlaceholder(config, out.data(), &outLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    EXPECT_EQ(out.size(), outLen);
    EXPECT_EQ(out[out.size() - 1], 0);
    out.pop_back();
    EXPECT_EQ(out.compare(input), 0);
    input.append(u"a");
    IMSA_HILOGI("inputLen:%{public}zu,input:%{public}s", input.size(), Str16ToStr8(input).c_str());
    ret = OH_TextConfig_SetPlaceholder(config, input.data(), input.size());
    EXPECT_EQ(ret, IME_ERR_OK);
    std::u16string out2(MAX_PLACEHOLDER_INPUT_SIZE, u'\0');
    outLen = out2.size();
    ret = OH_TextConfig_GetPlaceholder(config, out2.data(), &outLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    EXPECT_EQ(out2[out2.size() - 1], 0);
    input[input.size() - 1] = u'\0';
    EXPECT_EQ(out2.compare(input), 0);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_SetAbilityName_001
 * @tc.desc: Input parameters are valid
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetAbilityName_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetAbilityName_001 START");
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);
    std::u16string input = u"test";
    auto ret = OH_TextConfig_SetAbilityName(config, input.data(), input.size());
    EXPECT_EQ(ret, IME_ERR_OK);
    ret = OH_TextConfig_GetAbilityName(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_TextConfig_GetAbilityName(config, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    size_t outLen = 66;
    char16_t pOut[66] = {};
    ret = OH_TextConfig_GetAbilityName(config, pOut, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    outLen = 1;
    ret = OH_TextConfig_GetAbilityName(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_PARAMCHECK);
    EXPECT_EQ(outLen, 5);
    outLen = 65;
    ret = OH_TextConfig_GetAbilityName(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    EXPECT_EQ(outLen, 5);
    outLen = 5;
    ret = OH_TextConfig_GetAbilityName(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    std::u16string out(pOut, outLen);
    IMSA_HILOGI("outLen:%{public}zu,out:%{public}s,outSize:%{public}zu", outLen, Str16ToStr8(out).c_str(), out.size());
    EXPECT_GT(out.size(), input.size());
    outLen = input.size();
    ret = OH_TextConfig_GetAbilityName(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_PARAMCHECK);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_SetAbilityName_002
 * @tc.desc: Invalid test input parameter
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetAbilityName_002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetAbilityName_002 START");
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);
    std::u16string input = u"test";
    auto ret = OH_TextConfig_SetAbilityName(config, input.data(), input.size());
    EXPECT_EQ(ret, IME_ERR_OK);
    ret = OH_TextConfig_SetAbilityName(config, nullptr, 0);
    EXPECT_EQ(ret, IME_ERR_OK);
    char16_t *pOut = nullptr;
    size_t outLen = 0;
    ret = OH_TextConfig_GetAbilityName(config, pOut, &outLen);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    EXPECT_EQ(outLen, 1);
    EXPECT_EQ(pOut, nullptr);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_SetAbilityName_003
 * @tc.desc: Invalid test input parameter
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetAbilityName_003, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetAbilityName_003 START");
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);
    auto ret = OH_TextConfig_SetAbilityName(config, nullptr, 128);
    EXPECT_EQ(ret, IME_ERR_OK);
    ret = OH_TextConfig_SetAbilityName(config, nullptr, 1);
    EXPECT_EQ(ret, IME_ERR_OK);
    char16_t input[] = u"0";
    ret = OH_TextConfig_SetAbilityName(config, input, 0);
    EXPECT_EQ(ret, IME_ERR_OK);
    ret = OH_TextConfig_SetAbilityName(config, input, 1);
    EXPECT_EQ(ret, IME_ERR_OK);
    ret = OH_TextConfig_SetAbilityName(nullptr, nullptr, 1);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextConfig_Destroy(config);
}

/**
 * @tc.name: OH_TextConfig_SetAbilityName_004
 * @tc.desc: Invalid test input parameter
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextConfig_SetAbilityName_004, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextConfig_SetAbilityName_004 START");
    auto config = OH_TextConfig_Create();
    ASSERT_NE(nullptr, config);
    std::u16string input = u"";
    for (int i = 0; i < MAX_ABILITY_NAME_SIZE; ++i) {
        input.append(u"𪛊");
    }
    IMSA_HILOGI("inputLen:%{public}zu,input:%{public}s", input.size(), Str16ToStr8(input).c_str());
    auto ret = OH_TextConfig_SetAbilityName(config, input.data(), input.size());
    EXPECT_EQ(ret, IME_ERR_OK);
    std::u16string out(MAX_ABILITY_NAME_INPUT_SIZE, u'\0');
    size_t outLen = out.size();
    ret = OH_TextConfig_GetAbilityName(config, out.data(), &outLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    IMSA_HILOGI("outLen:%{public}zu,input:%{public}s,outSize:%{public}zu,inputSize:%{public}zu", outLen,
        Str16ToStr8(input).c_str(), out.size(), input.size());
    EXPECT_GT(out.size(), input.size());
    EXPECT_EQ(out[out.size() - 1], 0);
    out.pop_back();
    EXPECT_EQ(out.compare(input), 0);
    input.append(u"a");
    IMSA_HILOGI("inputLen:%{public}zu,input:%{public}s", input.size(), Str16ToStr8(input).c_str());
    ret = OH_TextConfig_SetAbilityName(config, input.data(), input.size());
    EXPECT_EQ(ret, IME_ERR_OK);
    std::u16string out2(MAX_ABILITY_NAME_INPUT_SIZE, u'\0');
    outLen = out2.size();
    ret = OH_TextConfig_GetAbilityName(config, out2.data(), &outLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    EXPECT_EQ(out2[out2.size() - 1], 0);
    input[input.size() - 1] = u'\0';
    EXPECT_EQ(out2.compare(input), 0);
    char16_t charInput[65] = u"123456789\0123456789\0012345678901\023456789";
    size_t charInputLen = 32;
    IMSA_HILOGI("inputLen:%{public}zu,input:%{public}s", charInputLen, Str16ToStr8(input).c_str());
    ret = OH_TextConfig_SetAbilityName(config, charInput, charInputLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    char16_t outChar[66] = {};
    outLen = 33;
    ret = OH_TextConfig_GetAbilityName(config, outChar, &outLen);
    EXPECT_EQ(ret, IME_ERR_OK);
    out = std::u16string(outChar, outLen);
    auto utf8Out = Str16ToStr8(outChar);
    IMSA_HILOGI("outLen:%{public}zu,out:%{public}s, utf8len:%{public}zu", outLen, utf8Out.c_str(), utf8Out.size());
    OH_TextConfig_Destroy(config);
}
} // namespace MiscServices
} // namespace OHOS
