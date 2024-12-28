/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "js_input_method_engine_setting.h"
#include "js_input_method.h"
#include "js_util.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "async_call.h"

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace testing;
class JsInputMethodEngineSettingTest : public testing::Test { };
namespace OHOS::MiscServices {
class MockTaskQueue : public TaskQueue {
public:
    MOCK_METHOD(void, Push, (const Task& task), (override));
    MOCK_METHOD(void, Pop, (), (override));
    MOCK_METHOD(bool, empty, (), (const, override));
    MOCK_METHOD(Task, front, (), (const, override));
};

class MockInputMethodController : public InputMethodController {
public:
    MOCK_METHOD3(SwitchInputMethod, int32_t(SwitchTrigger trigger, const std::string& packageName, const std::string& id));
    MOCK_METHOD1(GetCurrentInputMethod, std::shared_ptr<Property>());
    MOCK_METHOD1(GetCurrentInputMethodSubtype, std::shared_ptr<SubProperty>());
    MOCK_METHOD2(GetDefaultInputMethod, int32_t(std::shared_ptr<Property>& property));
    MOCK_METHOD1(GetInputMethodConfig, int32_t(OHOS::AppExecFwk::ElementName& inputMethodConfig));
};

/**
 * @tc.name: GetJsConstProperty_001
 * @tc.desc: GetJsConstProperty_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsConstProperty_001, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsConstProperty(env, 123);
    int32_t value;
    napi_get_value_int32(env, result, &value);
    EXPECT_EQ(value, 123);
}

/**
 * @tc.name: GetJsConstProperty_002
 * @tc.desc: GetJsConstProperty_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsConstProperty_002, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetIntJsConstProperty(env, -456);
    int32_t value;
    napi_get_value_int32(env, result, &value);
    EXPECT_EQ(value, -456);
}

/**
 * @tc.name: GetJsConstProperty_003
 * @tc.desc: GetJsConstProperty_003
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsConstProperty_003, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsConstProperty(env, 123);
    int32_t value;
    napi_get_value_int32(env, result, &value);
    EXPECT_EQ(value, 456);
}

/**
 * @tc.name: GetJsConstProperty_004
 * @tc.desc: GetJsConstProperty_004
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsConstProperty_004, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetIntJsConstProperty(env, -456);
    int32_t value;
    napi_get_value_int32(env, result, &value);
    EXPECT_EQ(value, -123);
}

/**
 * @tc.name: GetJsPanelTypeProperty_001
 * @tc.desc: GetJsPanelTypeProperty_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsPanelTypeProperty_001, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsPanelTypeProperty(env);
    napi_value typeSoftKeyboard;
    napi_get_named_property(env, result, "SOFT_KEYBOARD", &typeSoftKeyboard);
    int32_t value;
    napi_get_value_int32(env, typeSoftKeyboard, &value);
    EXPECT_EQ(value, static_cast<int32_t>(PanelType::SOFT_KEYBOARD));

    napi_value typeStatusBar;
    napi_get_named_property(env, result, "STATUS_BAR", &typeStatusBar);
    napi_get_value_int32(env, typeStatusBar, &value);
    EXPECT_EQ(value, static_cast<int32_t>(PanelType::STATUS_BAR));
}

/**
 * @tc.name: GetJsPanelFlagProperty_001
 * @tc.desc: GetJsPanelFlagProperty_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsPanelFlagProperty_001, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsPanelFlagProperty(env);
    napi_value flagFixed;
    napi_get_named_property(env, result, "FLG_FIXED", &flagFixed);
    int32_t value;
    napi_get_value_int32(env, flagFixed, &value);
    EXPECT_EQ(value, static_cast<int32_t>(PanelFlag::FLG_FIXED));

    napi_value flagFloating;
    napi_get_named_property(env, result, "FLG_FLOATING", &flagFloating);
    napi_get_value_int32(env, flagFloating, &value);
    EXPECT_EQ(value, static_cast<int32_t>(PanelFlag::FLG_FLOATING));
}

/**
 * @tc.name: GetJsDirectionProperty_001
 * @tc.desc: GetJsDirectionProperty_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsDirectionProperty_001, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsDirectionProperty(env);
    napi_value cursorUp;
    napi_get_named_property(env, result, "CURSOR_UP", &cursorUp);
    int32_t value;
    napi_get_value_int32(env, cursorUp, &value);
    EXPECT_EQ(value, static_cast<int32_t>(Direction::UP));

    napi_value cursorDown;
    napi_get_named_property(env, result, "CURSOR_DOWN", &cursorDown);
    napi_get_value_int32(env, cursorDown, &value);
    EXPECT_EQ(value, static_cast<int32_t>(Direction::DOWN));

    napi_value cursorLeft;
    napi_get_named_property(env, result, "CURSOR_LEFT", &cursorLeft);
    napi_get_value_int32(env, cursorLeft, &value);
    EXPECT_EQ(value, static_cast<int32_t>(Direction::LEFT));

    napi_value cursorRight;
    napi_get_named_property(env, result, "CURSOR_RIGHT", &cursorRight);
    napi_get_value_int32(env, cursorRight, &value);
    EXPECT_EQ(value, static_cast<int32_t>(Direction::RIGHT));
}

/**
 * @tc.name: GetJsExtendActionProperty_001
 * @tc.desc: GetJsExtendActionProperty_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsExtendActionProperty_001, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsExtendActionProperty(env);
    napi_value actionSelectAll;
    napi_get_named_property(env, result, "SELECT_ALL", &actionSelectAll);
    int32_t value;
    napi_get_value_int32(env, actionSelectAll, &value);
    EXPECT_EQ(value, static_cast<int32_t>(ExtendAction::SELECT_ALL));

    napi_value actionCut;
    napi_get_named_property(env, result, "CUT", &actionCut);
    napi_get_value_int32(env, actionCut, &value);
    EXPECT_EQ(value, static_cast<int32_t>(ExtendAction::CUT));

    napi_value actionCopy;
    napi_get_named_property(env, result, "COPY", &actionCopy);
    napi_get_value_int32(env, actionCopy, &value);
    EXPECT_EQ(value, static_cast<int32_t>(ExtendAction::COPY));

    napi_value actionPaste;
    napi_get_named_property(env, result, "PASTE", &actionPaste);
    napi_get_value_int32(env, actionPaste, &value);
    EXPECT_EQ(value, static_cast<int32_t>(ExtendAction::PASTE));
}

/**
 * @tc.name: GetJsSecurityModeProperty_001
 * @tc.desc: GetJsSecurityModeProperty_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsSecurityModeProperty_001, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsSecurityModeProperty(env);
    napi_value basic;
    napi_get_named_property(env, result, "BASIC", &basic);
    int32_t value;
    napi_get_value_int32(env, basic, &value);
    EXPECT_EQ(value, static_cast<int32_t>(SecurityMode::BASIC));

    napi_value full;
    napi_get_named_property(env, result, "FULL", &full);
    napi_get_value_int32(env, full, &value);
    EXPECT_EQ(value, static_cast<int32_t>(SecurityMode::FULL));
}

/**
 * @tc.name: GetInputMethodProperty_001
 * @tc.desc: GetInputMethodProperty_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetInputMethodProperty_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    napi_value argv = nullptr;
    napi_create_object(mockEnv.env, &argv);
    napi_status status = JsInputMethod::GetInputMethodProperty(mockEnv.env, argv, ctxt);
    EXPECT_EQ(status, napi_ok);
    EXPECT_EQ(ctxt->packageName, "testPackageName");
    EXPECT_EQ(ctxt->methodId, "testMethodId");
}

/**
 * @tc.name: GetInputMethodProperty_InvalidType_001
 * @tc.desc: GetInputMethodProperty_InvalidType_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetInputMethodProperty_InvalidType_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    napi_value argv = nullptr;
    napi_create_string_utf8(mockEnv.env, "notAnObject", NAPI_AUTO_LENGTH, &argv);
    napi_status status = JsInputMethod::GetInputMethodProperty(mockEnv.env, argv, ctxt);
    EXPECT_EQ(status, napi_generic_failure);
}

/**
 * @tc.name: GetInputMethodSubProperty_ValidObject_001
 * @tc.desc: GetInputMethodSubProperty_ValidObject_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetInputMethodSubProperty_ValidObject_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    napi_value argv = nullptr;
    napi_create_object(mockEnv.env, &argv);
    napi_status status = JsInputMethod::GetInputMethodSubProperty(mockEnv.env, argv, ctxt);
    EXPECT_EQ(status, napi_ok);
    EXPECT_EQ(ctxt->name, "testName");
    EXPECT_EQ(ctxt->id, "testId");
}

/**
 * @tc.name: GetInputMethodSubProperty_InvalidType_001
 * @tc.desc: GetInputMethodSubProperty_InvalidType_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetInputMethodSubProperty_InvalidType_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    napi_value argv = nullptr;
    napi_create_string_utf8(mockEnv.env, "notAnObject", NAPI_AUTO_LENGTH, &argv);
    napi_status status = JsInputMethod::GetInputMethodSubProperty(mockEnv.env, argv, ctxt);
    EXPECT_EQ(status, napi_generic_failure);
}

/**
 * @tc.name: GetJsInputMethodProperty_001
 * @tc.desc: GetJsInputMethodProperty_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsInputMethodProperty_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    Property property = {"testName", "testId", "testIcon", 1, "testLabel", 2};
    napi_value result = JsInputMethod::GetJsInputMethodProperty(mockEnv.env, property);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJsInputMethodSubProperty_001
 * @tc.desc: GetJsInputMethodSubProperty_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsInputMethodSubProperty_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    SubProperty subProperty = 
        {"testId", "testLabel", 1, "testName", "testMode", "testLocale", "testLanguage", "testIcon", 2};
    napi_value result = JsInputMethod::GetJsInputMethodSubProperty(mockEnv.env, subProperty);
    EXPECT_NE(result, nullptr);
}


/**
 * @tc.name: GetJsInputConfigElement_001
 * @tc.desc: GetJsInputConfigElement_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsInputConfigElement_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    OHOS::AppExecFwk::ElementName elementName("testBundleName", "testModuleName", "testAbilityName");
    napi_value result = JsInputMethod::GetJsInputConfigElement(mockEnv.env, elementName);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJSInputMethodSubProperties_ValidSubProperties_001
 * @tc.desc: GetJSInputMethodSubProperties_ValidSubProperties_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJSInputMethodSubProperties_ValidSubProperties_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    std::vector<SubProperty> subProperties = {
        {"testId1", "testLabel1", 1, "testName1", "testMode1", "testLocale1", "testLanguage1", "testIcon1", 2},
        {"testId2", "testLabel2", 2, "testName2", "testMode2", "testLocale2", "testLanguage2", "testIcon2", 3}
    };
    napi_value result = JsInputMethod::GetJSInputMethodSubProperties(mockEnv.env, subProperties);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJSInputMethodSubProperties_EmptySubProperties_001
 * @tc.desc: GetJSInputMethodSubProperties_EmptySubProperties_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJSInputMethodSubProperties_EmptySubProperties_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    std::vector<SubProperty> subProperties = {};
    napi_value result = JsInputMethod::GetJSInputMethodSubProperties(mockEnv.env, subProperties);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJSInputMethodProperties_ValidProperties_001
 * @tc.desc: GetJSInputMethodProperties_ValidProperties_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJSInputMethodProperties_ValidProperties_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    std::vector<Property> properties = {
        {"testName1", "testId1", "testIcon1", 1, "testLabel1", 2},
        {"testName2", "testId2", "testIcon2", 2, "testLabel2", 3}
    };
    napi_value result = JsInputMethod::GetJSInputMethodProperties(mockEnv.env, properties);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJSInputMethodProperties_EmptyProperties_001
 * @tc.desc: GetJSInputMethodProperties_EmptyProperties_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJSInputMethodProperties_EmptyProperties_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    std::vector<Property> properties = {};
    napi_value result = JsInputMethod::GetJSInputMethodProperties(mockEnv.env, properties);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SwitchInputMethod_ValidObject_001
 * @tc.desc: SwitchInputMethod_ValidObject_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SwitchInputMethod_ValidObject_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    EXPECT_CALL(mockController, SwitchInputMethod(SwitchTrigger::CURRENT_IME, "testPackageName", "testMethodId"))
        .WillOnce(Return(ErrorCode::NO_ERROR));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::SwitchInputMethod(mockEnv.env, info);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SwitchInputMethod_ValidString_001
 * @tc.desc: SwitchInputMethod_ValidString_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SwitchInputMethod_ValidString_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    EXPECT_CALL(mockController, SwitchInputMethod(SwitchTrigger::SYSTEM_APP, "testPackageName", "testMethodId"))
        .WillOnce(Return(ErrorCode::NO_ERROR));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::SwitchInputMethod(mockEnv.env, info);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetCurrentInputMethod_Valid_001
 * @tc.desc: GetCurrentInputMethod_Valid_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetCurrentInputMethod_Valid_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    Property property = {"testName", "testId", "testIcon", 1, "testLabel", 2};
    EXPECT_CALL(mockController, GetCurrentInputMethod())
        .WillOnce(Return(std::make_shared<Property>(property)));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::GetCurrentInputMethod(mockEnv.env, info);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetCurrentInputMethod_Nullptr_001
 * @tc.desc: GetCurrentInputMethod_Nullptr_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetCurrentInputMethod_Nullptr_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    EXPECT_CALL(mockController, GetCurrentInputMethod())
        .WillOnce(Return(nullptr));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::GetCurrentInputMethod(mockEnv.env, info);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GetCurrentInputMethodSubtype_Valid_001
 * @tc.desc: GetCurrentInputMethodSubtype_Valid_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetCurrentInputMethodSubtype_Valid_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    SubProperty subProperty = 
        {"testId", "testLabel", 1, "testName", "testMode", "testLocale", "testLanguage", "testIcon", 2};
    EXPECT_CALL(mockController, GetCurrentInputMethodSubtype())
        .WillOnce(Return(std::make_shared<SubProperty>(subProperty)));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::GetCurrentInputMethodSubtype(mockEnv.env, info);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetCurrentInputMethodSubtype_Nullptr_001
 * @tc.desc: GetCurrentInputMethodSubtype_Nullptr_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetCurrentInputMethodSubtype_Nullptr_001, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    EXPECT_CALL(mockController, GetCurrentInputMethodSubtype())
        .WillOnce(Return(nullptr));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::GetCurrentInputMethodSubtype(mockEnv.env, info);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Call_WithNullContext_ReturnsNull_001
 * @tc.desc: Call_WithNullContext_ReturnsNull_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Call_WithNullContext_ReturnsNull_001, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Call(mockEnv.env, [](AsyncCall::Context* ctx) {}, "testResource");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Call_WithNullContextCtx_ReturnsNull_001
 * @tc.desc: Call_WithNullContextCtx_ReturnsNull_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Call_WithNullContextCtx_ReturnsNull_001, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Call(mockEnv.env, [](AsyncCall::Context* ctx) {}, "testResource");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Call_WithValidContext_ReturnsPromise_001
 * @tc.desc: Call_WithValidContext_ReturnsPromise_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Call_WithValidContext_ReturnsPromise_001, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Call(mockEnv.env, [](AsyncCall::Context* ctx) {}, "testResource");
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: Post_WithNullContext_ReturnsNull_001
 * @tc.desc: Post_WithNullContext_ReturnsNull_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Post_WithNullContext_ReturnsNull_001, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Post(mockEnv.env, [](AsyncCall::Context* ctx) {}, nullptr, "testFunc");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Post_WithNullContextCtx_ReturnsNull_001
 * @tc.desc: Post_WithNullContextCtx_ReturnsNull_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Post_WithNullContextCtx_ReturnsNull_001, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Post(mockEnv.env, [](AsyncCall::Context* ctx) {}, std::make_shared<TaskQueue>(), "testFunc");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Post_WithNullQueue_ReturnsNull_001
 * @tc.desc: Post_WithNullQueue_ReturnsNull_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Post_WithNullQueue_ReturnsNull_001, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Post(mockEnv.env, [](AsyncCall::Context* ctx) {}, nullptr, "testFunc");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Post_WithValidContext_ReturnsPromise_001
 * @tc.desc: Post_WithValidContext_ReturnsPromise_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Post_WithValidContext_ReturnsPromise_001, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Post(mockEnv.env, [](AsyncCall::Context* ctx) {}, std::make_shared<TaskQueue>(), "testFunc");
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SyncCall_WithNullContext_ReturnsNull_001
 * @tc.desc: SyncCall_WithNullContext_ReturnsNull_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SyncCall_WithNullContext_ReturnsNull_001, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.SyncCall(mockEnv.env, [](AsyncCall::Context* ctx) {});
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: SyncCall_WithNullContextCtx_ReturnsNull_001
 * @tc.desc: SyncCall_WithNullContextCtx_ReturnsNull_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SyncCall_WithNullContextCtx_ReturnsNull_001, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.SyncCall(mockEnv.env, [](AsyncCall::Context* ctx) {});
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: SyncCall_WithValidContext_ReturnsPromise_001
 * @tc.desc: SyncCall_WithValidContext_ReturnsPromise_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SyncCall_WithValidContext_ReturnsPromise_001, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.SyncCall(mockEnv.env, [](AsyncCall::Context* ctx) {});
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: OnExecute_WithNullContext_DoesNothing_001
 * @tc.desc: OnExecute_WithNullContext_DoesNothing_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecute_WithNullContext_DoesNothing_001, TestSize.Level0)
{
    AsyncCall::OnExecute(mockEnv.env, nullptr);
}

/**
 * @tc.name: OnExecute_WithNullContextCtx_DoesNothing_001
 * @tc.desc: OnExecute_WithNullContextCtx_DoesNothing_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecute_WithNullContextCtx_DoesNothing_001, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall::OnExecute(mockEnv.env, context.get());
}

/**
 * @tc.name: OnExecute_WithValidContext_CallsExec_001
 * @tc.desc: OnExecute_WithValidContext_CallsExec_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecute_WithValidContext_CallsExec_001, TestSize.Level0)
{
    bool execCalled = false;
    context->ctx->exec_ = [&execCalled]() { execCalled = true; };
    AsyncCall::OnExecute(mockEnv.env, context.get());
    EXPECT_TRUE(execCalled);
}

/**
 * @tc.name: OnExecuteSeq_WithNullContext_DoesNothing_001
 * @tc.desc: OnExecuteSeq_WithNullContext_DoesNothing_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecuteSeq_WithNullContext_DoesNothing_001, TestSize.Level0)
{
    AsyncCall::OnExecuteSeq(mockEnv.env, nullptr);
}

/**
 * @tc.name: OnExecuteSeq_WithNullContextCtx_DoesNothing_001
 * @tc.desc: OnExecuteSeq_WithNullContextCtx_DoesNothing_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecuteSeq_WithNullContextCtx_DoesNothing_001, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall::OnExecuteSeq(mockEnv.env, context.get());
}

/**
 * @tc.name: OnExecuteSeq_WithNullQueue_DoesNothing_001
 * @tc.desc: OnExecuteSeq_WithNullQueue_DoesNothing_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecuteSeq_WithNullQueue_DoesNothing_001, TestSize.Level0)
{
    context->queue = nullptr;
    AsyncCall::OnExecuteSeq(mockEnv.env, context.get());
}

/**
 * @tc.name: OnExecuteSeq_WithValidContext_CallsExecAndPopsTask_001
 * @tc.desc: OnExecuteSeq_WithValidContext_CallsExecAndPopsTask_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecuteSeq_WithValidContext_CallsExecAndPopsTask_001, TestSize.Level0)
{
    bool execCalled = false;
    context->ctx->exec_ = [&execCalled]() { execCalled = true; };
    context->queue = std::make_shared<MockTaskQueue>();
    EXPECT_CALL(*context->queue, empty()).WillOnce(Return(false)).WillOnce(Return(true));
    EXPECT_CALL(*context->queue, front()).WillOnce(Return(Task{mockEnv.env, context->work, "testFunc"}));
    EXPECT_CALL(*context->queue, Pop()).Times(1);
    AsyncCall::OnExecuteSeq(mockEnv.env, context.get());
    EXPECT_TRUE(execCalled);
}

/**
 * @tc.name: OnComplete_WithNullContext_DoesNothing_001
 * @tc.desc: OnComplete_WithNullContext_DoesNothing_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_WithNullContext_DoesNothing_001, TestSize.Level0)
{
    AsyncCall::OnComplete(mockEnv.env, napi_ok, nullptr);
}

/**
 * @tc.name: OnComplete_WithNullContextCtx_DoesNothing_001
 * @tc.desc: OnComplete_WithNullContextCtx_DoesNothing_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_WithNullContextCtx_DoesNothing_001, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall::OnComplete(mockEnv.env, napi_ok, context.get());
}

/**
 * @tc.name: OnComplete_001
 * @tc.desc: OnComplete_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_001, TestSize.Level0)
{
    context->ctx->exec_ = [](napi_env env, napi_value* output) {
        *output = nullptr;
        return napi_ok;
    };
    AsyncCall::OnComplete(mockEnv.env, napi_ok, context.get());
}

/**
 * @tc.name: OnComplete_WithValidContextAndError_RejectsPromise_001
 * @tc.desc: OnComplete_WithValidContextAndError_RejectsPromise_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_WithValidContextAndError_RejectsPromise_001, TestSize.Level0)
{
    context->ctx->exec_ = [](napi_env env, napi_value* output) {
        *output = nullptr;
        return napi_generic_failure;
    };
    AsyncCall::OnComplete(mockEnv.env, napi_ok, context.get());
}

/**
 * @tc.name: OnComplete_WithValidContextAndCallback_CallsCallback_001
 * @tc.desc: OnComplete_WithValidContextAndCallback_CallsCallback_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_WithValidContextAndCallback_CallsCallback_001, TestSize.Level0)
{
    context->callback = reinterpret_cast<napi_ref>(new std::map<std::string, napi_value>());
    context->ctx->exec_ = [](napi_env env, napi_value* output) {
        *output = nullptr;
        return napi_ok;
    };
    AsyncCall::OnComplete(mockEnv.env, napi_ok, context.get());
}

/**
 * @tc.name: DeleteContext_WithNullEnv_DoesNothing_001
 * @tc.desc: DeleteContext_WithNullEnv_DoesNothing_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, DeleteContext_WithNullEnv_DoesNothing_001, TestSize.Level0)
{
    AsyncCall::DeleteContext(nullptr, context.get());
}

/**
 * @tc.name: DeleteContext_WithValidEnv_DeletesContext_001
 * @tc.desc: DeleteContext_WithValidEnv_DeletesContext_001
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, DeleteContext_WithValidEnv_DeletesContext_001, TestSize.Level0)
{
    AsyncCall::DeleteContext(mockEnv.env, context.get());
}

/**
 * @tc.name: GetJsPanelTypeProperty_002
 * @tc.desc: GetJsPanelTypeProperty_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsPanelTypeProperty_002, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsPanelTypeProperty(env);
    napi_value typeSoftKeyboard;
    napi_get_named_property(env, result, "SOFT_KEYBOARD", &typeSoftKeyboard);
    int32_t value;
    napi_get_value_int32(env, typeSoftKeyboard, &value);
    EXPECT_EQ(value, static_cast<int32_t>(PanelType::SOFT_KEYBOARD));

    napi_value typeStatusBar;
    napi_get_named_property(env, result, "STATUS_BAR", &typeStatusBar);
    napi_get_value_int32(env, typeStatusBar, &value);
    EXPECT_EQ(value, static_cast<int32_t>(PanelType::STATUS_BAR));
}

/**
 * @tc.name: GetJsPanelFlagProperty_002
 * @tc.desc: GetJsPanelFlagProperty_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsPanelFlagProperty_002, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsPanelFlagProperty(env);
    napi_value flagFixed;
    napi_get_named_property(env, result, "FLG_FIXED", &flagFixed);
    int32_t value;
    napi_get_value_int32(env, flagFixed, &value);
    EXPECT_EQ(value, static_cast<int32_t>(PanelFlag::FLG_FIXED));

    napi_value flagFloating;
    napi_get_named_property(env, result, "FLG_FLOATING", &flagFloating);
    napi_get_value_int32(env, flagFloating, &value);
    EXPECT_EQ(value, static_cast<int32_t>(PanelFlag::FLG_FLOATING));
}

/**
 * @tc.name: GetJsDirectionProperty_002
 * @tc.desc: GetJsDirectionProperty_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsDirectionProperty_002, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsDirectionProperty(env);
    napi_value cursorUp;
    napi_get_named_property(env, result, "CURSOR_UP", &cursorUp);
    int32_t value;
    napi_get_value_int32(env, cursorUp, &value);
    EXPECT_EQ(value, static_cast<int32_t>(Direction::UP));

    napi_value cursorDown;
    napi_get_named_property(env, result, "CURSOR_DOWN", &cursorDown);
    napi_get_value_int32(env, cursorDown, &value);
    EXPECT_EQ(value, static_cast<int32_t>(Direction::DOWN));

    napi_value cursorLeft;
    napi_get_named_property(env, result, "CURSOR_LEFT", &cursorLeft);
    napi_get_value_int32(env, cursorLeft, &value);
    EXPECT_EQ(value, static_cast<int32_t>(Direction::LEFT));

    napi_value cursorRight;
    napi_get_named_property(env, result, "CURSOR_RIGHT", &cursorRight);
    napi_get_value_int32(env, cursorRight, &value);
    EXPECT_EQ(value, static_cast<int32_t>(Direction::RIGHT));
}

/**
 * @tc.name: GetJsExtendActionProperty_002
 * @tc.desc: GetJsExtendActionProperty_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsExtendActionProperty_002, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsExtendActionProperty(env);
    napi_value actionSelectAll;
    napi_get_named_property(env, result, "SELECT_ALL", &actionSelectAll);
    int32_t value;
    napi_get_value_int32(env, actionSelectAll, &value);
    EXPECT_EQ(value, static_cast<int32_t>(ExtendAction::SELECT_ALL));

    napi_value actionCut;
    napi_get_named_property(env, result, "CUT", &actionCut);
    napi_get_value_int32(env, actionCut, &value);
    EXPECT_EQ(value, static_cast<int32_t>(ExtendAction::CUT));

    napi_value actionCopy;
    napi_get_named_property(env, result, "COPY", &actionCopy);
    napi_get_value_int32(env, actionCopy, &value);
    EXPECT_EQ(value, static_cast<int32_t>(ExtendAction::COPY));

    napi_value actionPaste;
    napi_get_named_property(env, result, "PASTE", &actionPaste);
    napi_get_value_int32(env, actionPaste, &value);
    EXPECT_EQ(value, static_cast<int32_t>(ExtendAction::PASTE));
}

/**
 * @tc.name: GetJsSecurityModeProperty_002
 * @tc.desc: GetJsSecurityModeProperty_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsSecurityModeProperty_002, TestSize.Level0)
{
    napi_env env = nullptr;
    napi_value result = JsInputMethodEngineSetting::GetJsSecurityModeProperty(env);
    napi_value basic;
    napi_get_named_property(env, result, "BASIC", &basic);
    int32_t value;
    napi_get_value_int32(env, basic, &value);
    EXPECT_EQ(value, static_cast<int32_t>(SecurityMode::BASIC));

    napi_value full;
    napi_get_named_property(env, result, "FULL", &full);
    napi_get_value_int32(env, full, &value);
    EXPECT_EQ(value, static_cast<int32_t>(SecurityMode::FULL));
}

/**
 * @tc.name: GetInputMethodProperty_002
 * @tc.desc: GetInputMethodProperty_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetInputMethodProperty_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    napi_value argv = nullptr;
    napi_create_object(mockEnv.env, &argv);
    napi_status status = JsInputMethod::GetInputMethodProperty(mockEnv.env, argv, ctxt);
    EXPECT_EQ(status, napi_ok);
    EXPECT_EQ(ctxt->packageName, "packageName");
    EXPECT_EQ(ctxt->methodId, "methodId");
}

/**
 * @tc.name: GetInputMethodProperty_InvalidType_002
 * @tc.desc: GetInputMethodProperty_InvalidType_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetInputMethodProperty_InvalidType_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    napi_value argv = nullptr;
    napi_create_string_utf8(mockEnv.env, "object", NAPI_AUTO_LENGTH, &argv);
    napi_status status = JsInputMethod::GetInputMethodProperty(mockEnv.env, argv, ctxt);
    EXPECT_EQ(status, napi_generic_failure);
}

/**
 * @tc.name: GetInputMethodSubProperty_ValidObject_002
 * @tc.desc: GetInputMethodSubProperty_ValidObject_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetInputMethodSubProperty_ValidObject_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    napi_value argv = nullptr;
    napi_create_object(mockEnv.env, &argv);
    napi_status status = JsInputMethod::GetInputMethodSubProperty(mockEnv.env, argv, ctxt);
    EXPECT_EQ(status, napi_ok);
    EXPECT_EQ(ctxt->id, "testId");
    EXPECT_EQ(ctxt->name, "testName");
}

/**
 * @tc.name: GetInputMethodSubProperty_InvalidType_002
 * @tc.desc: GetInputMethodSubProperty_InvalidType_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetInputMethodSubProperty_InvalidType_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    auto ctxt = std::make_shared<SwitchInputMethodContext>();
    napi_value argv = nullptr;
    napi_create_string_utf8(mockEnv.env, "object", NAPI_AUTO_LENGTH, &argv);
    napi_status status = JsInputMethod::GetInputMethodSubProperty(mockEnv.env, argv, ctxt);
    EXPECT_EQ(status, napi_generic_failure);
}

/**
 * @tc.name: GetJsInputMethodProperty_002
 * @tc.desc: GetJsInputMethodProperty_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsInputMethodProperty_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    Property property = {"name", "id", "icon", 1, "label", 2};
    napi_value result = JsInputMethod::GetJsInputMethodProperty(mockEnv.env, property);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJsInputMethodSubProperty_002
 * @tc.desc: GetJsInputMethodSubProperty_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsInputMethodSubProperty_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    SubProperty subProperty = {"id", "label", 1, "name", "mode", "locale", "language", "icon", 2};
    napi_value result = JsInputMethod::GetJsInputMethodSubProperty(mockEnv.env, subProperty);
    EXPECT_NE(result, nullptr);
}


/**
 * @tc.name: GetJsInputConfigElement_002
 * @tc.desc: GetJsInputConfigElement_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJsInputConfigElement_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    OHOS::AppExecFwk::ElementName elementName("bundleName", "moduleName", "abilityName");
    napi_value result = JsInputMethod::GetJsInputConfigElement(mockEnv.env, elementName);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJSInputMethodSubProperties_ValidSubProperties_002
 * @tc.desc: GetJSInputMethodSubProperties_ValidSubProperties_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJSInputMethodSubProperties_ValidSubProperties_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    std::vector<SubProperty> subProperties = {
        {"id", "label", 1, "name", "mode", "locale", "language", "icon", 2},
        {"id1", "label1", 2, "name1", "mode1", "locale1", "language1", "icon1", 3}
    };
    napi_value result = JsInputMethod::GetJSInputMethodSubProperties(mockEnv.env, subProperties);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJSInputMethodSubProperties_EmptySubProperties_002
 * @tc.desc: GetJSInputMethodSubProperties_EmptySubProperties_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJSInputMethodSubProperties_EmptySubProperties_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    std::vector<SubProperty> subProperties = {"id", "label", 1, "name", "mode", "locale", "language", "icon", 2};
    napi_value result = JsInputMethod::GetJSInputMethodSubProperties(mockEnv.env, subProperties);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJSInputMethodProperties_ValidProperties_002
 * @tc.desc: GetJSInputMethodProperties_ValidProperties_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJSInputMethodProperties_ValidProperties_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    std::vector<Property> properties = {
        {"name1", "id1", "icon1", 1, "label1", 2},
        {"name1", "id1", "icon1", 2, "label1", 3}
    };
    napi_value result = JsInputMethod::GetJSInputMethodProperties(mockEnv.env, properties);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetJSInputMethodProperties_EmptyProperties_002
 * @tc.desc: GetJSInputMethodProperties_EmptyProperties_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetJSInputMethodProperties_EmptyProperties_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    std::vector<Property> properties = {"name1", "id1", "icon1", 2, "label1", 3};
    napi_value result = JsInputMethod::GetJSInputMethodProperties(mockEnv.env, properties);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SwitchInputMethod_ValidObject_002
 * @tc.desc: SwitchInputMethod_ValidObject_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SwitchInputMethod_ValidObject_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    EXPECT_CALL(mockController, SwitchInputMethod(SwitchTrigger::CURRENT_IME, "packageName", "methodId"))
        .WillOnce(Return(ErrorCode::NO_ERROR));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::SwitchInputMethod(mockEnv.env, info);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SwitchInputMethod_ValidString_002
 * @tc.desc: SwitchInputMethod_ValidString_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SwitchInputMethod_ValidString_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    EXPECT_CALL(mockController, SwitchInputMethod(SwitchTrigger::SYSTEM_APP, "packageName", "methodId"))
        .WillOnce(Return(ErrorCode::NO_ERROR));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::SwitchInputMethod(mockEnv.env, info);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetCurrentInputMethod_Valid_002
 * @tc.desc: GetCurrentInputMethod_Valid_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetCurrentInputMethod_Valid_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    Property property = {"testName", "testId", "icon", 1, "testLabel", 2};
    EXPECT_CALL(mockController, GetCurrentInputMethod())
        .WillOnce(Return(std::make_shared<Property>(property)));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::GetCurrentInputMethod(mockEnv.env, info);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetCurrentInputMethod_Nullptr_002
 * @tc.desc: GetCurrentInputMethod_Nullptr_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetCurrentInputMethod_Nullptr_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    EXPECT_CALL(mockController, GetCurrentInputMethod())
        .WillOnce(Return(nullptr));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::GetCurrentInputMethod(mockEnv.env, info);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GetCurrentInputMethodSubtype_Valid_002
 * @tc.desc: GetCurrentInputMethodSubtype_Valid_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetCurrentInputMethodSubtype_Valid_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    SubProperty subProperty = 
        {"testId", "testLabel", 1, "testName", "testMode", "locale", "testLanguage", "testIcon", 2};
    EXPECT_CALL(mockController, GetCurrentInputMethodSubtype())
        .WillOnce(Return(std::make_shared<SubProperty>(subProperty)));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::GetCurrentInputMethodSubtype(mockEnv.env, info);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetCurrentInputMethodSubtype_Nullptr_002
 * @tc.desc: GetCurrentInputMethodSubtype_Nullptr_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, GetCurrentInputMethodSubtype_Nullptr_002, TestSize.Level0)
{
    MockNapiEnv mockEnv;
    MockInputMethodController mockController;
    EXPECT_CALL(mockController, GetCurrentInputMethodSubtype())
        .WillOnce(Return(nullptr));
    napi_callback_info info = nullptr;
    napi_value result = JsInputMethod::GetCurrentInputMethodSubtype(mockEnv.env, info);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Call_WithNullContext_ReturnsNull_002
 * @tc.desc: Call_WithNullContext_ReturnsNull_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Call_WithNullContext_ReturnsNull_002, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Call(mockEnv.env, [](AsyncCall::Context* ctx) {}, "resource");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Call_WithNullContextCtx_ReturnsNull_002
 * @tc.desc: Call_WithNullContextCtx_ReturnsNull_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Call_WithNullContextCtx_ReturnsNull_002, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Call(mockEnv.env, [](AsyncCall::Context* ctx) {}, "resource");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Call_WithValidContext_ReturnsPromise_002
 * @tc.desc: Call_WithValidContext_ReturnsPromise_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Call_WithValidContext_ReturnsPromise_002, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Call(mockEnv.env, [](AsyncCall::Context* ctx) {}, "resource");
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: Post_WithNullContext_ReturnsNull_002
 * @tc.desc: Post_WithNullContext_ReturnsNull_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Post_WithNullContext_ReturnsNull_002, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Post(mockEnv.env, [](AsyncCall::Context* ctx) {}, nullptr, "func");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Post_WithNullContextCtx_ReturnsNull_002
 * @tc.desc: Post_WithNullContextCtx_ReturnsNull_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Post_WithNullContextCtx_ReturnsNull_002, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Post(mockEnv.env, [](AsyncCall::Context* ctx) {}, std::make_shared<TaskQueue>(), "func");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Post_WithNullQueue_ReturnsNull_002
 * @tc.desc: Post_WithNullQueue_ReturnsNull_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Post_WithNullQueue_ReturnsNull_002, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Post(mockEnv.env, [](AsyncCall::Context* ctx) {}, nullptr, "func");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Post_WithValidContext_ReturnsPromise_002
 * @tc.desc: Post_WithValidContext_ReturnsPromise_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, Post_WithValidContext_ReturnsPromise_002, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.Post(mockEnv.env, [](AsyncCall::Context* ctx) {}, std::make_shared<TaskQueue>(), "func");
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SyncCall_WithNullContext_ReturnsNull_002
 * @tc.desc: SyncCall_WithNullContext_ReturnsNull_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SyncCall_WithNullContext_ReturnsNull_002, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.SyncCall(mockEnv.env, [](AsyncCall::Context* ctx) {});
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: SyncCall_WithNullContextCtx_ReturnsNull_002
 * @tc.desc: SyncCall_WithNullContextCtx_ReturnsNull_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SyncCall_WithNullContextCtx_ReturnsNull_002, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.SyncCall(mockEnv.env, [](AsyncCall::Context* ctx) {});
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: SyncCall_WithValidContext_ReturnsPromise_002
 * @tc.desc: SyncCall_WithValidContext_ReturnsPromise_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, SyncCall_WithValidContext_ReturnsPromise_002, TestSize.Level0)
{
    AsyncCall asyncCall(mockEnv.env, nullptr, context, 0);
    napi_value result = asyncCall.SyncCall(mockEnv.env, [](AsyncCall::Context* ctx) {});
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: OnExecute_WithNullContext_DoesNothing_002
 * @tc.desc: OnExecute_WithNullContext_DoesNothing_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecute_WithNullContext_DoesNothing_002, TestSize.Level0)
{
    AsyncCall::OnExecute(mockEnv.env, nullptr);
}

/**
 * @tc.name: OnExecute_WithNullContextCtx_DoesNothing_002
 * @tc.desc: OnExecute_WithNullContextCtx_DoesNothing_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecute_WithNullContextCtx_DoesNothing_002, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall::OnExecute(mockEnv.env, context.get());
}

/**
 * @tc.name: OnExecute_WithValidContext_CallsExec_002
 * @tc.desc: OnExecute_WithValidContext_CallsExec_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecute_WithValidContext_CallsExec_002, TestSize.Level0)
{
    bool execCalled = false;
    context->ctx->exec_ = [&execCalled]() { execCalled = true; };
    AsyncCall::OnExecute(mockEnv.env, context.get());
    EXPECT_TRUE(execCalled);
}

/**
 * @tc.name: OnExecuteSeq_WithNullContext_DoesNothing_002
 * @tc.desc: OnExecuteSeq_WithNullContext_DoesNothing_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecuteSeq_WithNullContext_DoesNothing_002, TestSize.Level0)
{
    AsyncCall::OnExecuteSeq(mockEnv.env, nullptr);
}

/**
 * @tc.name: OnExecuteSeq_WithNullContextCtx_DoesNothing_002
 * @tc.desc: OnExecuteSeq_WithNullContextCtx_DoesNothing_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecuteSeq_WithNullContextCtx_DoesNothing_002, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall::OnExecuteSeq(mockEnv.env, context.get());
}

/**
 * @tc.name: OnExecuteSeq_WithNullQueue_DoesNothing_002
 * @tc.desc: OnExecuteSeq_WithNullQueue_DoesNothing_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecuteSeq_WithNullQueue_DoesNothing_002, TestSize.Level0)
{
    context->queue = nullptr;
    AsyncCall::OnExecuteSeq(mockEnv.env, context.get());
}

/**
 * @tc.name: OnExecuteSeq_WithValidContext_CallsExecAndPopsTask_002
 * @tc.desc: OnExecuteSeq_WithValidContext_CallsExecAndPopsTask_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnExecuteSeq_WithValidContext_CallsExecAndPopsTask_002, TestSize.Level0)
{
    bool execCalled = false;
    context->ctx->exec_ = [&execCalled]() { execCalled = true; };
    context->queue = std::make_shared<MockTaskQueue>();
    EXPECT_CALL(*context->queue, empty()).WillOnce(Return(false)).WillOnce(Return(true));
    EXPECT_CALL(*context->queue, front()).WillOnce(Return(Task{mockEnv.env, context->work, "func"}));
    EXPECT_CALL(*context->queue, Pop()).Times(1);
    AsyncCall::OnExecuteSeq(mockEnv.env, context.get());
    EXPECT_TRUE(execCalled);
}

/**
 * @tc.name: OnComplete_WithNullContext_DoesNothing_002
 * @tc.desc: OnComplete_WithNullContext_DoesNothing_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_WithNullContext_DoesNothing_002, TestSize.Level0)
{
    AsyncCall::OnComplete(mockEnv.env, napi_ok, nullptr);
}

/**
 * @tc.name: OnComplete_WithNullContextCtx_DoesNothing_002
 * @tc.desc: OnComplete_WithNullContextCtx_DoesNothing_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_WithNullContextCtx_DoesNothing_002, TestSize.Level0)
{
    context->ctx = nullptr;
    AsyncCall::OnComplete(mockEnv.env, napi_ok, context.get());
}

/**
 * @tc.name: OnComplete_002
 * @tc.desc: OnComplete_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_002, TestSize.Level0)
{
    context->ctx->exec_ = [](napi_env env, napi_value* output) {
        if (env == nullptr) {
            return napi_generic_failure;
        }
        *output = nullptr;
        return napi_ok;
    };
    AsyncCall::OnComplete(mockEnv.env, napi_ok, context.get());
}

/**
 * @tc.name: OnComplete_WithValidContextAndError_RejectsPromise_002
 * @tc.desc: OnComplete_WithValidContextAndError_RejectsPromise_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_WithValidContextAndError_RejectsPromise_002, TestSize.Level0)
{
    context->ctx->exec_ = [](napi_env env, napi_value* output) {
        if (env == nullptr) {
            return napi_generic_failure;
        }
        *output = nullptr;
        return napi_generic_failure;
    };
    AsyncCall::OnComplete(mockEnv.env, napi_ok, context.get());
}

/**
 * @tc.name: OnComplete_WithValidContextAndCallback_CallsCallback_002
 * @tc.desc: OnComplete_WithValidContextAndCallback_CallsCallback_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, OnComplete_WithValidContextAndCallback_CallsCallback_002, TestSize.Level0)
{
    context->callback = reinterpret_cast<napi_ref>(new std::map<std::string, napi_value>());
    context->ctx->exec_ = [](napi_env env, napi_value* output) {
        if (env == nullptr) {
            return napi_generic_failure;
        }
        *output = nullptr;
        return napi_ok;
    };
    AsyncCall::OnComplete(mockEnv.env, napi_ok, context.get());
}

/**
 * @tc.name: DeleteContext_WithNullEnv_DoesNothing_002
 * @tc.desc: DeleteContext_WithNullEnv_DoesNothing_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, DeleteContext_WithNullEnv_DoesNothing_002, TestSize.Level0)
{
    AsyncCall::DeleteContext(nullptr, context.get());
}

/**
 * @tc.name: DeleteContext_WithValidEnv_DeletesContext_002
 * @tc.desc: DeleteContext_WithValidEnv_DeletesContext_002
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: 
 */
HWTEST_F(JsInputMethodEngineSettingTest, DeleteContext_WithValidEnv_DeletesContext_002, TestSize.Level0)
{
    AsyncCall::DeleteContext(mockEnv.env, context.get());
}
} // namespace OHOS::MiscServices