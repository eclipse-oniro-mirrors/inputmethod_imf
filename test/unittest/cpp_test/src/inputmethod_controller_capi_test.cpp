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
#include "inputmethod_controller_capi_test.h"
#include <thread>

#include "global.h"
#include "input_method_controller.h"
#include "input_method_queries.h"
#include "mock_input_method_system_ability_proxy.h"
#include "mock_iremote_object.h"
#include "native_inputmethod_types.h"
#include "native_message_handler_callback.h"
#include "native_object_registry.h"
#include "native_session_guard.h"
#include "text_editor_proxy_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace testing;

// PreviewTextStyle C API declarations (defined in inputmethod_preview_text_style_capi.h,
// declared here as extern "C" to link against the C implementations in
// inputmethod_preview_text_style_capi.cpp without pulling in the public header's
// opaque typedef, since native_inputmethod_types.h already provides the concrete struct)
extern "C" {
OH_InputMethod_PreviewTextStyle *OH_InputMethod_PreviewTextStyle_Create(void);
void OH_InputMethod_PreviewTextStyle_Destroy(OH_InputMethod_PreviewTextStyle *style);
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_SetUnderlineStyle(
    OH_InputMethod_PreviewTextStyle *style, OH_InputMethod_UnderlineStyle underlineStyle);
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(
    OH_InputMethod_PreviewTextStyle *style, OH_InputMethod_UnderlineStyle *underlineStyle);
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_SetUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, uint32_t underlineColor);
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_GetUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, uint32_t *underlineColor);
InputMethod_ErrorCode OH_InputMethod_PreviewTextStyle_HasUnderlineColor(
    OH_InputMethod_PreviewTextStyle *style, bool *hasUnderlineColor);
}

namespace OHOS {
namespace MiscServices {
void InputMethodControllerCapiTest::SetUpTestSuite()
{
    systemAbilityProxyMock_ = new (std::nothrow) NiceMock<MockInputMethodSystemAbilityProxy>();
    ASSERT_NE(systemAbilityProxyMock_, nullptr);
    MockInputMethodSystemAbilityProxy::SetImsaProxyForTest(
        InputMethodController::GetInstance(), systemAbilityProxyMock_);

    textEditorProxy_ = OH_TextEditorProxy_Create();
    ASSERT_NE(nullptr, textEditorProxy_);
    ConstructTextEditorProxy(textEditorProxy_);

    attachOptions_ = OH_AttachOptions_Create(true);
    ASSERT_NE(nullptr, attachOptions_);

    ON_CALL(*systemAbilityProxyMock_, StartInput(_, _, _))
        .WillByDefault(Invoke(
            [](const InputClientInfoInner &info, vector<sptr<IRemoteObject>> &agents, vector<BindImeInfo> &imeInfos) {
                sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) NiceMock<MockIRemoteObject>();
                EXPECT_NE(iremoteObject, nullptr);
                agents.emplace_back(iremoteObject);
                BindImeInfo imeinfo;
                imeInfos.push_back(imeinfo);
                return ErrorCode::NO_ERROR;
            }));
}

void InputMethodControllerCapiTest::TearDownTestSuite()
{
    MockInputMethodSystemAbilityProxy::SetImsaProxyForTest(InputMethodController::GetInstance(), nullptr);
    if (textEditorProxy_ != nullptr) {
        OH_TextEditorProxy_Destroy(textEditorProxy_);
        textEditorProxy_ = nullptr;
    }

    if (attachOptions_ != nullptr) {
        OH_AttachOptions_Destroy(attachOptions_);
        attachOptions_ = nullptr;
    }

    systemAbilityProxyMock_ = nullptr;
}

InputMethod_TextEditorProxy *InputMethodControllerCapiTest::textEditorProxy_ = nullptr;
InputMethod_AttachOptions *InputMethodControllerCapiTest::attachOptions_ = nullptr;
sptr<MockInputMethodSystemAbilityProxy> InputMethodControllerCapiTest::systemAbilityProxyMock_ = nullptr;
/**
 * @tc.name: CurrentInputMethod_StatusAndLegacyContract
 * @tc.desc: The status query preserves service errors while the legacy getter still returns its result object.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, CurrentInputMethod_StatusAndLegacyContract, TestSize.Level0)
{
    auto controller = InputMethodController::GetInstance();
    Property serviceProperty;
    serviceProperty.name = "test.ime";
    constexpr int32_t userId = 101;
    // Explicit counts check the contract without gMock's implicit expectation sequence.
    for (auto status :
        { ErrorCode::NO_ERROR, ErrorCode::ERROR_STATUS_PERMISSION_DENIED, ErrorCode::ERROR_SERVICE_START_FAILED }) {
        auto calls = std::make_shared<uint32_t>(0);
        ON_CALL(*systemAbilityProxyMock_, GetCurrentInputMethod(_, _))
            .WillByDefault(Invoke([calls, serviceProperty, status, userId](int32_t actualUserId, Property &output) {
                ++*calls;
                EXPECT_EQ(userId, actualUserId);
                output = serviceProperty;
                return status;
            }));
        Property property;
        EXPECT_EQ(status, InputMethodQueries::GetCurrent(*controller, property, userId));
        EXPECT_EQ(serviceProperty.name, property.name);
        auto legacy = controller->GetCurrentInputMethod(userId);
        EXPECT_NE(nullptr, legacy);
        if (legacy != nullptr) {
            EXPECT_EQ(serviceProperty.name, legacy->name);
        }
        EXPECT_EQ(2u, *calls);
    }
}

/**
 * @tc.name: CurrentSubtype_StatusAndLegacyContract
 * @tc.desc: Subtype status queries preserve service failures without changing the legacy result contract.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, CurrentSubtype_StatusAndLegacyContract, TestSize.Level0)
{
    auto controller = InputMethodController::GetInstance();
    SubProperty serviceProperty;
    serviceProperty.id = "test.subtype";
    constexpr int32_t userId = 101;
    for (auto status :
        { ErrorCode::NO_ERROR, ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND, ErrorCode::ERROR_SERVICE_START_FAILED }) {
        auto calls = std::make_shared<uint32_t>(0);
        ON_CALL(*systemAbilityProxyMock_, GetCurrentInputMethodSubtype(_, _))
            .WillByDefault(Invoke([calls, serviceProperty, status, userId](SubProperty &output, int32_t actualUserId) {
                ++*calls;
                EXPECT_EQ(userId, actualUserId);
                output = serviceProperty;
                return status;
            }));
        SubProperty property;
        EXPECT_EQ(status, InputMethodQueries::GetCurrentSubtype(*controller, property, userId));
        EXPECT_EQ(serviceProperty.id, property.id);
        auto legacy = controller->GetCurrentInputMethodSubtype(userId);
        EXPECT_NE(nullptr, legacy);
        if (legacy != nullptr) {
            EXPECT_EQ(serviceProperty.id, legacy->id);
        }
        EXPECT_EQ(2u, *calls);
    }
}

/**
 * @tc.name: DefaultInputMethod_PreserveFailureAndOutput
 * @tc.desc: Failed default-IME queries propagate the service status and do not replace the caller's output.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, DefaultInputMethod_PreserveFailureAndOutput, TestSize.Level0)
{
    auto controller = InputMethodController::GetInstance();
    auto original = std::make_shared<Property>();
    original->name = "original";
    auto property = original;
    auto calls = std::make_shared<uint32_t>(0);
    ON_CALL(*systemAbilityProxyMock_, GetDefaultInputMethod(_, _, _))
        .WillByDefault(Invoke([calls](Property &, bool isBrief, int32_t userId) {
            ++*calls;
            EXPECT_FALSE(isBrief);
            EXPECT_EQ(101, userId);
            return ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND;
        }));
    EXPECT_EQ(ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND, controller->GetDefaultInputMethod(property, 101));
    EXPECT_EQ(original, property);
    EXPECT_EQ("original", property->name);
    EXPECT_EQ(1u, *calls);
}

/**
 * @tc.name: NativeRegistry_ViewLifetimeAndPruning
 * @tc.desc: Expired views are pruned and cannot be registered or resurrected.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NativeRegistry_ViewLifetimeAndPruning, TestSize.Level0)
{
    auto &registry = NativeObjectRegistry<InputMethod_CursorInfo>::GetInstance();
    auto cursor = std::make_shared<InputMethod_CursorInfo>();
    auto lifetime = std::make_shared<uint8_t>(0);
    EXPECT_EQ(nullptr, registry.Register(nullptr));
    EXPECT_TRUE(registry.GetLifetime(cursor.get()).expired());
    EXPECT_EQ(nullptr, registry.Get(cursor.get()));
    EXPECT_FALSE(registry.RegisterView(cursor, {}));
    EXPECT_TRUE(registry.RegisterView(cursor, lifetime));
    EXPECT_EQ(cursor, registry.Get(cursor.get()));
    EXPECT_FALSE(registry.Destroy(cursor.get()));
    lifetime.reset();
    EXPECT_EQ(nullptr, registry.Get(cursor.get()));
    auto next = std::make_shared<InputMethod_CursorInfo>();
    auto nextLifetime = std::make_shared<uint8_t>(0);
    EXPECT_TRUE(registry.RegisterView(next, nextLifetime));
    EXPECT_TRUE(registry.GetLifetime(cursor.get()).expired());
    EXPECT_EQ(next, registry.Get(next.get()));
    registry.UnregisterBorrowed(next.get());
    EXPECT_EQ(nullptr, registry.Get(next.get()));
    registry.UnregisterBorrowed(next.get());
}

/**
 * @tc.name: NativeRegistry_OwnedLeaseSurvivesRetirement
 * @tc.desc: Retirement invalidates the handle immediately but releases storage after the last lease.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NativeRegistry_OwnedLeaseSurvivesRetirement, TestSize.Level0)
{
    auto raw = OH_AttachOptions_Create(true);
    ASSERT_NE(nullptr, raw);
    auto &registry = NativeObjectRegistry<InputMethod_AttachOptions>::GetInstance();
    auto lease = registry.Get(raw);
    ASSERT_NE(nullptr, lease);
    std::weak_ptr<InputMethod_AttachOptions> storage = lease;
    auto lifetime = registry.GetLifetime(raw);
    registry.UnregisterBorrowed(raw);
    EXPECT_EQ(lease, registry.Get(raw));
    EXPECT_TRUE(registry.Destroy(raw));
    EXPECT_TRUE(lifetime.expired());
    EXPECT_EQ(nullptr, registry.Get(raw));
    EXPECT_FALSE(registry.Destroy(raw));
    EXPECT_FALSE(storage.expired());
    EXPECT_TRUE(lease->showKeyboard);
    lease.reset();
    EXPECT_TRUE(storage.expired());
}

/**
 * @tc.name: NativeObjectScope_CloseAndMove
 * @tc.desc: Borrowed scope closure is idempotent and moved-from destruction preserves the new owner.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NativeObjectScope_CloseAndMove, TestSize.Level0)
{
    auto &registry = NativeObjectRegistry<InputMethod_TextConfig>::GetInstance();
    std::shared_ptr<InputMethod_TextConfig> lease;
    std::weak_ptr<InputMethod_TextConfig> storage;
    {
        NativeObjectScope<InputMethod_TextConfig> scope;
        ASSERT_NE(nullptr, scope.Get());
        NativeObjectScope<InputMethod_TextConfig> moved(std::move(scope));
        EXPECT_EQ(nullptr, scope.Get());
        lease = registry.Get(moved.Get());
        ASSERT_NE(nullptr, lease);
        storage = lease;
        EXPECT_FALSE(registry.Destroy(moved.Get()));
        EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetWindowId(moved.Get(), 123));
        moved.Close();
        moved.Close();
        EXPECT_EQ(nullptr, registry.Get(moved.Get()));
    }
    EXPECT_FALSE(storage.expired());
    EXPECT_EQ(123, lease->windowId);
    lease.reset();
    EXPECT_TRUE(storage.expired());
}

void GetTextConfigFunc(InputMethod_TextEditorProxy *proxy, InputMethod_TextConfig *config) { }
void InsertTextFunc(InputMethod_TextEditorProxy *proxy, const char16_t *text, size_t length) { }
void DeleteForwardFunc(InputMethod_TextEditorProxy *proxy, int32_t length) { }
void DeleteBackwardFunc(InputMethod_TextEditorProxy *proxy, int32_t length) { }
void SendKeyboardStatusFunc(InputMethod_TextEditorProxy *proxy, InputMethod_KeyboardStatus status) { }
void SendEnterKeyFunc(InputMethod_TextEditorProxy *proxy, InputMethod_EnterKeyType type) { }
void MoveCursorFunc(InputMethod_TextEditorProxy *proxy, InputMethod_Direction direction) { }
void HandleSetSelectionFunc(InputMethod_TextEditorProxy *proxy, int32_t start, int32_t end) { }
void HandleExtendActionFunc(InputMethod_TextEditorProxy *proxy, InputMethod_ExtendAction action) { }
void GetleftTextOfCursorFunc(InputMethod_TextEditorProxy *proxy, int32_t number, char16_t text[], size_t *length) { }
void GetRightTextOfCursorFunc(InputMethod_TextEditorProxy *proxy, int32_t number, char16_t text[], size_t *length) { }
int32_t GetTextIndexAtCursorFunc(InputMethod_TextEditorProxy *proxy)
{
    return 0;
}
int32_t ReceivePrivateCommandFunc(
    InputMethod_TextEditorProxy *proxy, InputMethod_PrivateCommand *privateCommand[], size_t size)
{
    return 0;
}
int32_t SetPreviewTextFunc(
    InputMethod_TextEditorProxy *proxy, const char16_t *text, size_t length, int32_t start, int32_t end)
{
    return 0;
}
int32_t SetPreviewTextWithStyleFunc(InputMethod_TextEditorProxy *proxy,
    const char16_t *text, uint32_t length, int32_t start, int32_t end,
    const OH_InputMethod_PreviewTextStyle *style)
{
    return IME_ERR_OK;
}
void FinishTextPreviewFunc(InputMethod_TextEditorProxy *proxy) { }
void InputMethodControllerCapiTest::ConstructTextEditorProxy(InputMethod_TextEditorProxy *textEditorProxy)
{
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetTextConfigFunc(textEditorProxy, GetTextConfigFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetInsertTextFunc(textEditorProxy, InsertTextFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetDeleteForwardFunc(textEditorProxy, DeleteForwardFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetDeleteBackwardFunc(textEditorProxy, DeleteBackwardFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetSendKeyboardStatusFunc(textEditorProxy, SendKeyboardStatusFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetSendEnterKeyFunc(textEditorProxy, SendEnterKeyFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetMoveCursorFunc(textEditorProxy, MoveCursorFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetHandleSetSelectionFunc(textEditorProxy, HandleSetSelectionFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetHandleExtendActionFunc(textEditorProxy, HandleExtendActionFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetLeftTextOfCursorFunc(textEditorProxy, GetleftTextOfCursorFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetRightTextOfCursorFunc(textEditorProxy, GetRightTextOfCursorFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetTextIndexAtCursorFunc(textEditorProxy, GetTextIndexAtCursorFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetReceivePrivateCommandFunc(textEditorProxy, ReceivePrivateCommandFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetSetPreviewTextFunc(textEditorProxy, SetPreviewTextFunc));
    EXPECT_EQ(IME_ERR_OK,
        OH_InputMethod_TextEditorProxy_SetSetPreviewTextWithStyleFunc(textEditorProxy, SetPreviewTextWithStyleFunc));
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetFinishTextPreviewFunc(textEditorProxy, FinishTextPreviewFunc));
}

static void TestGetTextEditorProxyMember(InputMethod_TextEditorProxy *textEditorProxy)
{
    OH_TextEditorProxy_GetTextConfigFunc getTextCOnfigFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetGetTextConfigFunc(textEditorProxy, &getTextCOnfigFunc));
    EXPECT_EQ(GetTextConfigFunc, getTextCOnfigFunc);

    OH_TextEditorProxy_InsertTextFunc insertTextFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetInsertTextFunc(textEditorProxy, &insertTextFunc));
    EXPECT_EQ(InsertTextFunc, insertTextFunc);

    OH_TextEditorProxy_DeleteForwardFunc deleteForwardFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetDeleteForwardFunc(textEditorProxy, &deleteForwardFunc));
    EXPECT_EQ(DeleteForwardFunc, deleteForwardFunc);

    OH_TextEditorProxy_DeleteBackwardFunc deleteBackwardFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetDeleteBackwardFunc(textEditorProxy, &deleteBackwardFunc));
    EXPECT_EQ(DeleteBackwardFunc, deleteBackwardFunc);

    OH_TextEditorProxy_SendKeyboardStatusFunc sendKeyboardStatusFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetSendKeyboardStatusFunc(textEditorProxy, &sendKeyboardStatusFunc));
    EXPECT_EQ(SendKeyboardStatusFunc, sendKeyboardStatusFunc);

    OH_TextEditorProxy_SendEnterKeyFunc sendEnterKeyFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetSendEnterKeyFunc(textEditorProxy, &sendEnterKeyFunc));
    EXPECT_EQ(SendEnterKeyFunc, sendEnterKeyFunc);

    OH_TextEditorProxy_MoveCursorFunc moveCursorFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetMoveCursorFunc(textEditorProxy, &moveCursorFunc));
    EXPECT_EQ(MoveCursorFunc, moveCursorFunc);

    OH_TextEditorProxy_HandleSetSelectionFunc handleSetSelectionFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetHandleSetSelectionFunc(textEditorProxy, &handleSetSelectionFunc));
    EXPECT_EQ(HandleSetSelectionFunc, handleSetSelectionFunc);

    OH_TextEditorProxy_HandleExtendActionFunc handleExtendActionFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetHandleExtendActionFunc(textEditorProxy, &handleExtendActionFunc));
    EXPECT_EQ(HandleExtendActionFunc, handleExtendActionFunc);

    OH_TextEditorProxy_GetLeftTextOfCursorFunc getLeftTextOfCursorFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetGetLeftTextOfCursorFunc(textEditorProxy, &getLeftTextOfCursorFunc));
    EXPECT_EQ(GetleftTextOfCursorFunc, getLeftTextOfCursorFunc);

    OH_TextEditorProxy_GetRightTextOfCursorFunc getRightTextOfCursorFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetGetRightTextOfCursorFunc(textEditorProxy, &getRightTextOfCursorFunc));
    EXPECT_EQ(GetRightTextOfCursorFunc, getRightTextOfCursorFunc);

    OH_TextEditorProxy_GetTextIndexAtCursorFunc getTextIndexAtCursorFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetGetTextIndexAtCursorFunc(textEditorProxy, &getTextIndexAtCursorFunc));
    EXPECT_EQ(GetTextIndexAtCursorFunc, getTextIndexAtCursorFunc);

    OH_TextEditorProxy_ReceivePrivateCommandFunc receivePrivateCommandFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetReceivePrivateCommandFunc(textEditorProxy, &receivePrivateCommandFunc));
    EXPECT_EQ(ReceivePrivateCommandFunc, receivePrivateCommandFunc);

    OH_TextEditorProxy_SetPreviewTextFunc setPreviewTextFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetSetPreviewTextFunc(textEditorProxy, &setPreviewTextFunc));
    EXPECT_EQ(SetPreviewTextFunc, setPreviewTextFunc);

    OH_TextEditorProxy_FinishTextPreviewFunc finishTextPreviewFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_GetFinishTextPreviewFunc(textEditorProxy, &finishTextPreviewFunc));
    EXPECT_EQ(FinishTextPreviewFunc, finishTextPreviewFunc);
}

static void TestGetPreviewTextWithStyleMember(InputMethod_TextEditorProxy *textEditorProxy)
{
    OH_InputMethod_TextEditorProxy_SetPreviewTextWithStyleFunc setPreviewTextWithStyleFunc = nullptr;
    EXPECT_EQ(IME_ERR_OK,
        OH_InputMethod_TextEditorProxy_GetSetPreviewTextWithStyleFunc(textEditorProxy, &setPreviewTextWithStyleFunc));
    EXPECT_EQ(SetPreviewTextWithStyleFunc, setPreviewTextWithStyleFunc);
}

/**
 * @tc.name: TextEditorProxy_001
 * @tc.desc: create and destroy TextEditorProxy success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TextEditorProxy_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::TextEditorProxy_001 START");
    auto textEditorProxy = OH_TextEditorProxy_Create();
    ASSERT_NE(nullptr, textEditorProxy);
    ConstructTextEditorProxy(textEditorProxy);
    TestGetTextEditorProxyMember(textEditorProxy);
    TestGetPreviewTextWithStyleMember(textEditorProxy);
    OH_TextEditorProxy_Destroy(textEditorProxy);
}

/**
 * @tc.name: SetPreviewTextWithStyleFunc_NullProxy_001
 * @tc.desc: SetSetPreviewTextWithStyleFunc with null proxy returns IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, SetPreviewTextWithStyleFunc_NullProxy_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::SetPreviewTextWithStyleFunc_NullProxy_001 START");
    auto ret = OH_InputMethod_TextEditorProxy_SetSetPreviewTextWithStyleFunc(nullptr, SetPreviewTextWithStyleFunc);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: SetPreviewTextWithStyleFunc_NullFunc_001
 * @tc.desc: SetSetPreviewTextWithStyleFunc with null func returns IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, SetPreviewTextWithStyleFunc_NullFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::SetPreviewTextWithStyleFunc_NullFunc_001 START");
    auto textEditorProxy = OH_TextEditorProxy_Create();
    ASSERT_NE(nullptr, textEditorProxy);
    auto ret = OH_InputMethod_TextEditorProxy_SetSetPreviewTextWithStyleFunc(textEditorProxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(textEditorProxy);
}

/**
 * @tc.name: GetSetPreviewTextWithStyleFunc_NullProxy_001
 * @tc.desc: GetSetPreviewTextWithStyleFunc with null proxy returns IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, GetSetPreviewTextWithStyleFunc_NullProxy_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::GetSetPreviewTextWithStyleFunc_NullProxy_001 START");
    OH_InputMethod_TextEditorProxy_SetPreviewTextWithStyleFunc func = nullptr;
    auto ret = OH_InputMethod_TextEditorProxy_GetSetPreviewTextWithStyleFunc(nullptr, &func);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: GetSetPreviewTextWithStyleFunc_NullOut_001
 * @tc.desc: GetSetPreviewTextWithStyleFunc with null out param returns IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, GetSetPreviewTextWithStyleFunc_NullOut_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::GetSetPreviewTextWithStyleFunc_NullOut_001 START");
    auto textEditorProxy = OH_TextEditorProxy_Create();
    ASSERT_NE(nullptr, textEditorProxy);
    auto ret = OH_InputMethod_TextEditorProxy_GetSetPreviewTextWithStyleFunc(textEditorProxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(textEditorProxy);
}

/**
 * @tc.name: AttachOptions_001
 * @tc.desc: create and destroy AttachOptions success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, AttachOptions_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::AttachOptions_001 START");
    auto options = OH_AttachOptions_Create(true);
    ASSERT_NE(nullptr, options);

    bool showKeyboard = false;
    EXPECT_EQ(IME_ERR_OK, OH_AttachOptions_IsShowKeyboard(options, &showKeyboard));
    EXPECT_TRUE(showKeyboard);
    OH_AttachOptions_Destroy(options);
}

/**
 * @tc.name: CreateAndDestroyAttachOptionsWithRequestKeyboardReason_success
 * @tc.desc: create and destroy AttachOptions success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, CreateAndDestroyAttachOptionsWithRequestKeyboardReason_success, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::CreateAndDestroyAttachOptionsWithRequestKeyboardReason_success START");
    auto options = OH_AttachOptions_CreateWithRequestKeyboardReason(
        true, InputMethod_RequestKeyboardReason::IME_REQUEST_REASON_NONE);
    ASSERT_NE(nullptr, options);

    int32_t requestKeyboardReason = -1;
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_AttachOptions_GetRequestKeyboardReason(options, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_AttachOptions_GetRequestKeyboardReason(nullptr, &requestKeyboardReason));

    EXPECT_EQ(IME_ERR_OK, OH_AttachOptions_GetRequestKeyboardReason(options, &requestKeyboardReason));
    EXPECT_EQ(requestKeyboardReason, InputMethod_RequestKeyboardReason::IME_REQUEST_REASON_NONE);
    OH_AttachOptions_Destroy(options);
}

/**
 * @tc.name: GetRequestKeyboardReasonWithNull_fail
 * @tc.desc: get request keyboard reason with null fail
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, GetRequestKeyboardReasonWithNull_fail, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::GetRequestKeyboardReasonWithNull_fail START");
    auto options = OH_AttachOptions_CreateWithRequestKeyboardReason(
        true, InputMethod_RequestKeyboardReason::IME_REQUEST_REASON_NONE);
    ASSERT_NE(nullptr, options);

    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_AttachOptions_GetRequestKeyboardReason(options, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_AttachOptions_GetRequestKeyboardReason(nullptr, nullptr));
    OH_AttachOptions_Destroy(options);
}

/**
 * @tc.name: TextAvoidInfo_001
 * @tc.desc: create and destroy TextAvoidInfo success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TextAvoidInfo_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::TextAvoidInfo_001 START");
    double expPositionY = 1.1;
    double expHeight = 1.2;
    auto avoidInfo = OH_TextAvoidInfo_Create(expPositionY, expHeight);
    ASSERT_NE(nullptr, avoidInfo);

    double actPositionY = 0.0;
    double actHeight = 0.0;
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_GetPositionY(avoidInfo, &actPositionY));
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_GetHeight(avoidInfo, &actHeight));
    EXPECT_EQ(expPositionY, actPositionY);
    EXPECT_EQ(expHeight, actHeight);

    // test set positionY and height
    expPositionY = 2.1;
    expHeight = 2.2;
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_SetPositionY(avoidInfo, expPositionY));
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_SetHeight(avoidInfo, expHeight));
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_GetPositionY(avoidInfo, &actPositionY));
    EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_GetHeight(avoidInfo, &actHeight));
    EXPECT_EQ(expPositionY, actPositionY);
    EXPECT_EQ(expHeight, actHeight);

    OH_TextAvoidInfo_Destroy(avoidInfo);
}

/**
 * @tc.name: PrivateCommand_001
 * @tc.desc: create and destroy PrivateCommand success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PrivateCommand_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PrivateCommand_001 START");
    std::string key = "key";
    auto privateCommand = OH_PrivateCommand_Create(const_cast<char *>(key.c_str()), key.length());
    ASSERT_NE(nullptr, privateCommand);

    // test set bool value
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_SetBoolValue(privateCommand, true));
    bool actBoolValue = false;
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_GetBoolValue(privateCommand, &actBoolValue));
    EXPECT_TRUE(actBoolValue);

    // test set int value
    int32_t expIntValue = 1;
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_SetIntValue(privateCommand, expIntValue));
    int32_t actIntValue = 0;
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_GetIntValue(privateCommand, &actIntValue));
    EXPECT_EQ(expIntValue, actIntValue);

    // test set string value
    std::string expStrValue = "string";
    EXPECT_EQ(IME_ERR_OK,
        OH_PrivateCommand_SetStrValue(privateCommand, const_cast<char *>(expStrValue.c_str()), expStrValue.length()));
    const char *actStrValue = nullptr;
    size_t actStrValueLength = 0;
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_GetStrValue(privateCommand, &actStrValue, &actStrValueLength));
    EXPECT_EQ(expStrValue, std::string(actStrValue, actStrValueLength));

    // test get value type
    InputMethod_CommandValueType valueType = IME_COMMAND_VALUE_TYPE_NONE;
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_GetValueType(privateCommand, &valueType));
    EXPECT_EQ(IME_COMMAND_VALUE_TYPE_STRING, valueType);

    // test get and set key
    const char *actStrKey = nullptr;
    size_t actStrKeyLength = 0;
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_GetKey(privateCommand, &actStrKey, &actStrKeyLength));
    EXPECT_EQ(key, std::string(actStrKey, actStrKeyLength));
    std::string newKey = "newKey";
    EXPECT_EQ(
        IME_ERR_OK, OH_PrivateCommand_SetKey(privateCommand, const_cast<char *>(newKey.c_str()), newKey.length()));
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_GetKey(privateCommand, &actStrKey, &actStrKeyLength));
    EXPECT_EQ(newKey, std::string(actStrKey, actStrKeyLength));
    OH_PrivateCommand_Destroy(privateCommand);
}
/**
 * @tc.name: OH_TextEditorProxy_SetGetTextConfigFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetGetTextConfigFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetGetTextConfigFunc_001 START");
    auto ret = OH_TextEditorProxy_SetGetTextConfigFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetGetTextConfigFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetInsertTextFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetInsertTextFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetInsertTextFunc_001 START");
    auto ret = OH_TextEditorProxy_SetInsertTextFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetInsertTextFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetDeleteForwardFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetDeleteForwardFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetDeleteForwardFunc_001 START");
    auto ret = OH_TextEditorProxy_SetDeleteForwardFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetDeleteForwardFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetDeleteBackwardFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetDeleteBackwardFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetDeleteBackwardFunc_001 START");
    auto ret = OH_TextEditorProxy_SetDeleteBackwardFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetDeleteBackwardFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetSendKeyboardStatusFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetSendKeyboardStatusFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetSendKeyboardStatusFunc_001 START");
    auto ret = OH_TextEditorProxy_SetSendKeyboardStatusFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetSendKeyboardStatusFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetSendEnterKeyFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetSendEnterKeyFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetSendEnterKeyFunc_001 START");
    auto ret = OH_TextEditorProxy_SetSendEnterKeyFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetSendEnterKeyFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetMoveCursorFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetMoveCursorFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetMoveCursorFunc_001 START");
    auto ret = OH_TextEditorProxy_SetMoveCursorFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetMoveCursorFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetHandleSetSelectionFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetHandleSetSelectionFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetHandleSetSelectionFunc_001 START");
    auto ret = OH_TextEditorProxy_SetHandleSetSelectionFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetHandleSetSelectionFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetHandleExtendActionFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetHandleExtendActionFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetHandleExtendActionFunc_001 START");
    auto ret = OH_TextEditorProxy_SetHandleExtendActionFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetHandleExtendActionFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetGetLeftTextOfCursorFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetGetLeftTextOfCursorFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetGetLeftTextOfCursorFunc_001 START");
    auto ret = OH_TextEditorProxy_SetGetLeftTextOfCursorFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetGetLeftTextOfCursorFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetGetRightTextOfCursorFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetGetRightTextOfCursorFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetGetRightTextOfCursorFunc_001 START");
    auto ret = OH_TextEditorProxy_SetGetRightTextOfCursorFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetGetRightTextOfCursorFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetGetTextIndexAtCursorFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetGetTextIndexAtCursorFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetGetTextIndexAtCursorFunc_001 START");
    auto ret = OH_TextEditorProxy_SetGetTextIndexAtCursorFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetGetTextIndexAtCursorFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetReceivePrivateCommandFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetReceivePrivateCommandFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetReceivePrivateCommandFunc_001 START");
    auto ret = OH_TextEditorProxy_SetReceivePrivateCommandFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetReceivePrivateCommandFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetSetPreviewTextFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetSetPreviewTextFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetSetPreviewTextFunc_001 START");
    auto ret = OH_TextEditorProxy_SetSetPreviewTextFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetSetPreviewTextFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_SetFinishTextPreviewFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_SetFinishTextPreviewFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_SetFinishTextPreviewFunc_001 START");
    auto ret = OH_TextEditorProxy_SetFinishTextPreviewFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_SetFinishTextPreviewFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetGetTextConfigFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetGetTextConfigFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetGetTextConfigFunc_001 START");
    auto ret = OH_TextEditorProxy_GetGetTextConfigFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetGetTextConfigFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetInsertTextFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetInsertTextFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetInsertTextFunc_001 START");
    auto ret = OH_TextEditorProxy_GetInsertTextFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetInsertTextFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetDeleteForwardFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetDeleteForwardFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetDeleteForwardFunc_001 START");
    auto ret = OH_TextEditorProxy_GetDeleteForwardFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetDeleteForwardFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetDeleteBackwardFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetDeleteBackwardFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetDeleteBackwardFunc_001 START");
    auto ret = OH_TextEditorProxy_GetDeleteBackwardFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetDeleteBackwardFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetSendKeyboardStatusFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetSendKeyboardStatusFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetSendKeyboardStatusFunc_001 START");
    auto ret = OH_TextEditorProxy_GetSendKeyboardStatusFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetSendKeyboardStatusFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetSendEnterKeyFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetSendEnterKeyFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetSendEnterKeyFunc_001 START");
    auto ret = OH_TextEditorProxy_GetSendEnterKeyFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetSendEnterKeyFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetMoveCursorFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetMoveCursorFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetMoveCursorFunc_001 START");
    auto ret = OH_TextEditorProxy_GetMoveCursorFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetMoveCursorFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetHandleSetSelectionFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetHandleSetSelectionFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetHandleSetSelectionFunc_001 START");
    auto ret = OH_TextEditorProxy_GetHandleSetSelectionFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetHandleSetSelectionFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetHandleExtendActionFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetHandleExtendActionFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetHandleExtendActionFunc_001 START");
    auto ret = OH_TextEditorProxy_GetHandleExtendActionFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetHandleExtendActionFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetGetLeftTextOfCursorFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetGetLeftTextOfCursorFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetGetLeftTextOfCursorFunc_001 START");
    auto ret = OH_TextEditorProxy_GetGetLeftTextOfCursorFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetGetLeftTextOfCursorFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetGetRightTextOfCursorFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetGetRightTextOfCursorFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetGetRightTextOfCursorFunc_001 START");
    auto ret = OH_TextEditorProxy_GetGetRightTextOfCursorFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetGetRightTextOfCursorFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetGetTextIndexAtCursorFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetGetTextIndexAtCursorFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetGetTextIndexAtCursorFunc_001 START");
    auto ret = OH_TextEditorProxy_GetGetTextIndexAtCursorFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetGetTextIndexAtCursorFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetReceivePrivateCommandFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetReceivePrivateCommandFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetReceivePrivateCommandFunc_001 START");
    auto ret = OH_TextEditorProxy_GetReceivePrivateCommandFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetReceivePrivateCommandFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetSetPreviewTextFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetSetPreviewTextFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetSetPreviewTextFunc_001 START");
    auto ret = OH_TextEditorProxy_GetSetPreviewTextFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetSetPreviewTextFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: OH_TextEditorProxy_GetFinishTextPreviewFunc_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextEditorProxy_GetFinishTextPreviewFunc_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextEditorProxy_GetFinishTextPreviewFunc_001 START");
    auto ret = OH_TextEditorProxy_GetFinishTextPreviewFunc(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextEditorProxy *proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(proxy, nullptr);
    ret = OH_TextEditorProxy_GetFinishTextPreviewFunc(proxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextEditorProxy_Destroy(proxy);
}

static void CheckTextEditorCallbackAccessors(InputMethod_TextEditorProxy *proxy, InputMethod_ErrorCode expected)
{
    auto check = [proxy, expected](auto setter, auto getter, auto callback) {
        decltype(callback) actual = nullptr;
        EXPECT_EQ(expected, setter(proxy, callback));
        EXPECT_EQ(expected, getter(proxy, &actual));
        EXPECT_EQ(expected == IME_ERR_OK ? callback : nullptr, actual);
    };
    check(OH_TextEditorProxy_SetGetTextConfigFunc, OH_TextEditorProxy_GetGetTextConfigFunc, GetTextConfigFunc);
    check(OH_TextEditorProxy_SetInsertTextFunc, OH_TextEditorProxy_GetInsertTextFunc, InsertTextFunc);
    check(OH_TextEditorProxy_SetDeleteForwardFunc, OH_TextEditorProxy_GetDeleteForwardFunc, DeleteForwardFunc);
    check(OH_TextEditorProxy_SetDeleteBackwardFunc, OH_TextEditorProxy_GetDeleteBackwardFunc, DeleteBackwardFunc);
    check(OH_TextEditorProxy_SetSendKeyboardStatusFunc, OH_TextEditorProxy_GetSendKeyboardStatusFunc,
        SendKeyboardStatusFunc);
    check(OH_TextEditorProxy_SetSendEnterKeyFunc, OH_TextEditorProxy_GetSendEnterKeyFunc, SendEnterKeyFunc);
    check(OH_TextEditorProxy_SetMoveCursorFunc, OH_TextEditorProxy_GetMoveCursorFunc, MoveCursorFunc);
    check(OH_TextEditorProxy_SetHandleSetSelectionFunc, OH_TextEditorProxy_GetHandleSetSelectionFunc,
        HandleSetSelectionFunc);
    check(OH_TextEditorProxy_SetHandleExtendActionFunc, OH_TextEditorProxy_GetHandleExtendActionFunc,
        HandleExtendActionFunc);
    check(OH_TextEditorProxy_SetGetLeftTextOfCursorFunc, OH_TextEditorProxy_GetGetLeftTextOfCursorFunc,
        GetleftTextOfCursorFunc);
    check(OH_TextEditorProxy_SetGetRightTextOfCursorFunc, OH_TextEditorProxy_GetGetRightTextOfCursorFunc,
        GetRightTextOfCursorFunc);
    check(OH_TextEditorProxy_SetGetTextIndexAtCursorFunc, OH_TextEditorProxy_GetGetTextIndexAtCursorFunc,
        GetTextIndexAtCursorFunc);
    check(OH_TextEditorProxy_SetReceivePrivateCommandFunc, OH_TextEditorProxy_GetReceivePrivateCommandFunc,
        ReceivePrivateCommandFunc);
    check(OH_TextEditorProxy_SetSetPreviewTextFunc, OH_TextEditorProxy_GetSetPreviewTextFunc, SetPreviewTextFunc);
    check(OH_TextEditorProxy_SetFinishTextPreviewFunc, OH_TextEditorProxy_GetFinishTextPreviewFunc,
        FinishTextPreviewFunc);
    EXPECT_EQ(expected, OH_TextEditorProxy_SetCallbackInMainThread(proxy, true));
}

/**
 * @tc.name: TextEditorCallbacks_RoundTrip
 * @tc.desc: All atomic callback setters and getters preserve the registered function.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TextEditorCallbacks_RoundTrip, TestSize.Level0)
{
    auto proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(nullptr, proxy);
    CheckTextEditorCallbackAccessors(proxy, IME_ERR_OK);
    OH_TextEditorProxy_Destroy(proxy);
}

/**
 * @tc.name: TextEditorCallbacks_RejectUnregisteredHandle
 * @tc.desc: Every callback accessor rejects non-null unregistered storage.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TextEditorCallbacks_RejectUnregisteredHandle, TestSize.Level0)
{
    InputMethod_TextEditorProxy proxy;
    CheckTextEditorCallbackAccessors(&proxy, IME_ERR_NULL_POINTER);
    EXPECT_EQ(nullptr, proxy.insertTextFunc.load());
    EXPECT_FALSE(proxy.isCallbackInMainThread.load());
}

/**
 * @tc.name: TextEditorCallbacks_RejectRetiredHandle
 * @tc.desc: Keeping retired editor storage alive does not permit callback replacement.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TextEditorCallbacks_RejectRetiredHandle, TestSize.Level0)
{
    auto proxy = OH_TextEditorProxy_Create();
    ASSERT_NE(nullptr, proxy);
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    ASSERT_NE(nullptr, lease);
    OH_TextEditorProxy_Destroy(proxy);
    CheckTextEditorCallbackAccessors(proxy, IME_ERR_NULL_POINTER);
    EXPECT_EQ(nullptr, lease->insertTextFunc.load());
    EXPECT_FALSE(lease->isCallbackInMainThread.load());
}

/**
 * @tc.name: AttachOptions_RejectInvalidHandles
 * @tc.desc: Unregistered and retired options are rejected without changing outputs.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, AttachOptions_RejectInvalidHandles, TestSize.Level0)
{
    InputMethod_AttachOptions unregistered {};
    auto options = OH_AttachOptions_Create(true);
    ASSERT_NE(nullptr, options);
    auto lease = NativeObjectRegistry<InputMethod_AttachOptions>::GetInstance().Get(options);
    OH_AttachOptions_Destroy(options);
    for (auto invalid : { &unregistered, options }) {
        bool show = false;
        int reason = -1;
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_AttachOptions_IsShowKeyboard(invalid, &show));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_AttachOptions_GetRequestKeyboardReason(invalid, &reason));
        EXPECT_FALSE(show);
        EXPECT_EQ(-1, reason);
    }
    OH_AttachOptions_Destroy(options);
}

/**
 * @tc.name: OH_AttachOptions_IsShowKeyboard_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_AttachOptions_IsShowKeyboard_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_AttachOptions_IsShowKeyboard_001 START");
    auto ret = OH_AttachOptions_IsShowKeyboard(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_AttachOptions *options = OH_AttachOptions_Create(true);
    ASSERT_NE(options, nullptr);
    ret = OH_AttachOptions_IsShowKeyboard(options, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_AttachOptions_Destroy(options);
}

/**
 * @tc.name: OH_TextAvoidInfo_SetPositionY_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextAvoidInfo_SetPositionY_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextAvoidInfo_SetPositionY_001 START");
    double positionY = 0.0;
    auto ret = OH_TextAvoidInfo_SetPositionY(nullptr, positionY);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_TextAvoidInfo_SetHeight_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextAvoidInfo_SetHeight_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextAvoidInfo_SetHeight_001 START");
    double positionY = 0.0;
    auto ret = OH_TextAvoidInfo_SetHeight(nullptr, positionY);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_TextAvoidInfo_GetPositionY_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextAvoidInfo_GetPositionY_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextAvoidInfo_GetPositionY_001 START");
    double positionY = 0.0;
    double height = 0.0;
    auto ret = OH_TextAvoidInfo_GetPositionY(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextAvoidInfo *info = OH_TextAvoidInfo_Create(positionY, height);
    ASSERT_NE(info, nullptr);
    ret = OH_TextAvoidInfo_GetPositionY(info, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextAvoidInfo_Destroy(info);
}

/**
 * @tc.name: OH_TextAvoidInfo_GetHeight_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_TextAvoidInfo_GetHeight_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_TextAvoidInfo_GetHeight_001 START");
    double positionY = 0.0;
    double height = 0.0;
    auto ret = OH_TextAvoidInfo_GetHeight(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_TextAvoidInfo *info = OH_TextAvoidInfo_Create(positionY, height);
    ASSERT_NE(info, nullptr);
    ret = OH_TextAvoidInfo_GetHeight(info, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_TextAvoidInfo_Destroy(info);
}

/**
 * @tc.name: OH_PrivateCommand_SetKey_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_PrivateCommand_SetKey_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_PrivateCommand_SetKey_001 START");
    char key[] = "example key";
    size_t keyLength = strlen(key);
    auto ret = OH_PrivateCommand_SetKey(nullptr, nullptr, keyLength);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_PrivateCommand *command = OH_PrivateCommand_Create(key, keyLength);
    ASSERT_NE(command, nullptr);
    ret = OH_PrivateCommand_SetKey(command, nullptr, keyLength);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_PrivateCommand_Destroy(command);
}

/**
 * @tc.name: OH_PrivateCommand_SetBoolValue_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_PrivateCommand_SetBoolValue_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_PrivateCommand_SetBoolValue_001 START");
    bool value = false;
    auto ret = OH_PrivateCommand_SetBoolValue(nullptr, value);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_PrivateCommand_SetIntValue_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_PrivateCommand_SetIntValue_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_PrivateCommand_SetIntValue_001 START");
    int32_t value = 0;
    auto ret = OH_PrivateCommand_SetIntValue(nullptr, value);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_PrivateCommand_SetIntValue_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_PrivateCommand_SetStrValue_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_PrivateCommand_SetStrValue_001 START");
    char value[] = "example value";
    size_t valueLength = strlen(value);
    auto ret = OH_PrivateCommand_SetStrValue(nullptr, value, valueLength);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    char key[] = "example key";
    size_t keyLength = strlen(key);
    InputMethod_PrivateCommand *command = OH_PrivateCommand_Create(key, keyLength);
    ASSERT_NE(command, nullptr);
    ret = OH_PrivateCommand_SetStrValue(command, nullptr, valueLength);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_PrivateCommand_Destroy(command);
}

/**
 * @tc.name: OH_PrivateCommand_GetKey_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_PrivateCommand_GetKey_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_PrivateCommand_GetKey_001 START");
    char key[] = "example key";
    size_t keyLength = strlen(key);
    auto ret = OH_PrivateCommand_GetKey(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_PrivateCommand *command = OH_PrivateCommand_Create(key, keyLength);
    ASSERT_NE(command, nullptr);
    ret = OH_PrivateCommand_GetKey(command, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    const char *actStrKey = nullptr;
    ret = OH_PrivateCommand_GetKey(command, &actStrKey, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_PrivateCommand_Destroy(command);
}

/**
 * @tc.name: OH_PrivateCommand_GetValueType_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_PrivateCommand_GetValueType_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_PrivateCommand_GetValueType_001 START");
    auto ret = OH_PrivateCommand_GetValueType(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    char key[] = "example key";
    size_t keyLength = strlen(key);
    InputMethod_PrivateCommand *command = OH_PrivateCommand_Create(key, keyLength);
    ret = OH_PrivateCommand_GetValueType(command, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_PrivateCommand_Destroy(command);
}

/**
 * @tc.name: OH_PrivateCommand_GetBoolValue_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_PrivateCommand_GetBoolValue_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_PrivateCommand_GetBoolValue_001 START");
    auto ret = OH_PrivateCommand_GetBoolValue(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    char key[] = "example key";
    size_t keyLength = strlen(key);
    InputMethod_PrivateCommand *command = OH_PrivateCommand_Create(key, keyLength);
    ret = OH_PrivateCommand_GetBoolValue(command, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_PrivateCommand_GetBoolValue(command, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    int32_t expIntValue = 1;
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_SetIntValue(command, expIntValue));
    bool value = false;
    ret = OH_PrivateCommand_GetBoolValue(command, &value);
    EXPECT_EQ(ret, IME_ERR_QUERY_FAILED);
    OH_PrivateCommand_Destroy(command);
}

/**
 * @tc.name: OH_PrivateCommand_GetIntValue_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_PrivateCommand_GetIntValue_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_PrivateCommand_GetIntValue_001 START");
    auto ret = OH_PrivateCommand_GetIntValue(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    char key[] = "example key";
    size_t keyLength = strlen(key);
    InputMethod_PrivateCommand *command = OH_PrivateCommand_Create(key, keyLength);
    ret = OH_PrivateCommand_GetIntValue(command, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    bool expBoolValue = false;
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_SetBoolValue(command, expBoolValue));
    int32_t value = 0;
    ret = OH_PrivateCommand_GetIntValue(command, &value);
    EXPECT_EQ(ret, IME_ERR_QUERY_FAILED);
    OH_PrivateCommand_Destroy(command);
}

/**
 * @tc.name: OH_PrivateCommand_GetStrValue_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_PrivateCommand_GetStrValue_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_PrivateCommand_GetStrValue_001 START");
    const char *value = nullptr;
    size_t valueLength = 0;
    auto ret = OH_PrivateCommand_GetStrValue(nullptr, &value, &valueLength);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    char key[] = "example key";
    size_t keyLength = strlen(key);
    InputMethod_PrivateCommand *command = OH_PrivateCommand_Create(key, keyLength);
    ret = OH_PrivateCommand_GetStrValue(command, nullptr, &valueLength);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_PrivateCommand_GetStrValue(command, &value, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    bool expBoolValue = false;
    EXPECT_EQ(IME_ERR_OK, OH_PrivateCommand_SetBoolValue(command, expBoolValue));
    ret = OH_PrivateCommand_GetStrValue(command, &value, &valueLength);
    EXPECT_EQ(ret, IME_ERR_QUERY_FAILED);
    OH_PrivateCommand_Destroy(command);
}

/**
 * @tc.name: PrivateCommand_RejectInvalidHandles
 * @tc.desc: All private-command accessors reject unregistered and retired handles.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PrivateCommand_RejectInvalidHandles, TestSize.Level0)
{
    char key[] = "key";
    InputMethod_PrivateCommand unregistered {};
    auto command = OH_PrivateCommand_Create(key, 3);
    ASSERT_NE(nullptr, command);
    auto lease = NativeObjectRegistry<InputMethod_PrivateCommand>::GetInstance().Get(command);
    OH_PrivateCommand_Destroy(command);
    for (auto invalid : { &unregistered, command }) {
        const char *text = nullptr;
        size_t length = 0;
        bool boolValue = false;
        int32_t intValue = -1;
        InputMethod_CommandValueType type = IME_COMMAND_VALUE_TYPE_NONE;
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_PrivateCommand_SetKey(invalid, key, 3));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_PrivateCommand_SetBoolValue(invalid, true));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_PrivateCommand_SetIntValue(invalid, 1));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_PrivateCommand_SetStrValue(invalid, key, 3));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_PrivateCommand_GetKey(invalid, &text, &length));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_PrivateCommand_GetValueType(invalid, &type));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_PrivateCommand_GetBoolValue(invalid, &boolValue));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_PrivateCommand_GetIntValue(invalid, &intValue));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_PrivateCommand_GetStrValue(invalid, &text, &length));
        EXPECT_EQ(nullptr, text);
        EXPECT_EQ(0, length);
        EXPECT_FALSE(boolValue);
        EXPECT_EQ(-1, intValue);
        EXPECT_EQ(IME_COMMAND_VALUE_TYPE_NONE, type);
    }
    OH_PrivateCommand_Destroy(command);
}

/**
 * @tc.name: NativeSessionGuard_RejectNestedAndConcurrentEntry
 * @tc.desc: A rejected guard cannot release the current owner and acquisition recovers after exit.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NativeSessionGuard_RejectNestedAndConcurrentEntry, TestSize.Level0)
{
    {
        NativeSessionGuard owner;
        ASSERT_TRUE(owner.IsAcquired());
        {
            NativeSessionGuard nested;
            EXPECT_FALSE(nested.IsAcquired());
        }
        bool acquired = true;
        std::thread contender([&acquired]() {
            NativeSessionGuard guard;
            acquired = guard.IsAcquired();
        });
        contender.join();
        EXPECT_FALSE(acquired);
        NativeSessionGuard stillBlocked;
        EXPECT_FALSE(stillBlocked.IsAcquired());
    }
    NativeSessionGuard next;
    EXPECT_TRUE(next.IsAcquired());
}

/**
 * @tc.name: CSessionOperations_RejectReentryBeforeValidation
 * @tc.desc: Every session entry point rejects reentry without touching controller state.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, CSessionOperations_RejectReentryBeforeValidation, TestSize.Level0)
{
    {
        NativeSessionGuard owner;
        ASSERT_TRUE(owner.IsAcquired());
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodController_Attach(nullptr, nullptr, nullptr));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodController_AttachWithUIContext(nullptr, nullptr, nullptr, nullptr));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodController_Detach(nullptr));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodProxy_ShowKeyboard(nullptr));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodProxy_ShowTextInput(nullptr, nullptr));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodProxy_HideKeyboard(nullptr));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodProxy_NotifySelectionChange(nullptr, nullptr, 0, 0, 0));
        EXPECT_EQ(IME_ERR_IMCLIENT,
            OH_InputMethodProxy_NotifyConfigurationChange(nullptr, IME_ENTER_KEY_NONE, IME_TEXT_INPUT_TYPE_NONE));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodProxy_NotifyCursorUpdate(nullptr, nullptr));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodProxy_SendPrivateCommand(nullptr, nullptr, 0));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodProxy_SendMessage(nullptr, nullptr, 0, nullptr, 0));
        EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodProxy_RecvMessage(nullptr, nullptr));
    }
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(nullptr, nullptr, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodProxy_ShowKeyboard(nullptr));
}

/**
 * @tc.name: Attach_RejectRetiredOptions
 * @tc.desc: Both attach entry points reject retired options before a platform or IPC call.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, Attach_RejectRetiredOptions, TestSize.Level0)
{
    auto options = OH_AttachOptions_Create(true);
    ASSERT_NE(nullptr, options);
    auto lease = NativeObjectRegistry<InputMethod_AttachOptions>::GetInstance().Get(options);
    OH_AttachOptions_Destroy(options);
    InputMethod_InputMethodProxy *result = nullptr;
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_InputMethodController_Attach(textEditorProxy_, options, &result));
    EXPECT_EQ(IME_ERR_PARAMCHECK,
        OH_InputMethodController_AttachWithUIContext(
            reinterpret_cast<ArkUI_ContextHandle>(&result), textEditorProxy_, options, &result));
    EXPECT_EQ(nullptr, result);
}

/**
 * @tc.name: OH_InputMethodController_Attach_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_InputMethodController_Attach_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_InputMethodController_Attach_001 START");
    auto ret = OH_InputMethodController_Attach(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    auto textEditorProxy = OH_TextEditorProxy_Create();
    ret = OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ConstructTextEditorProxy(textEditorProxy);
    ret = OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    InputMethod_AttachOptions *options = OH_AttachOptions_Create(true);
    ret = OH_InputMethodController_Attach(textEditorProxy, options, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_AttachOptions_Destroy(options);
    OH_TextEditorProxy_Destroy(textEditorProxy);
}

/**
 * @tc.name: OH_InputMethodController_Detach_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_InputMethodController_Detach_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_InputMethodController_Detach_001 START");
    auto ret = OH_InputMethodController_Detach(nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: OH_InputMethodProxy_ShowKeyboard_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_InputMethodProxy_ShowKeyboard_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_InputMethodProxy_ShowKeyboard_001 START");
    auto ret = OH_InputMethodProxy_ShowKeyboard(nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: ShowKeyboardTest_SUCCESS
 * @tc.desc: show keyboard success after attach
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, ShowKeyboardTest_SUCCESS, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::ShowKeyboardTest_SUCCESS START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    auto ret = OH_InputMethodProxy_ShowKeyboard(inputMethodProxy);
    EXPECT_EQ(ret, IME_ERR_OK);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: ShowTextInput_SUCCESS
 * @tc.desc: show text input success after attach
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, ShowTextInput_SUCCESS, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::ShowTextInput_SUCCESS START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    auto ret = OH_InputMethodProxy_ShowTextInput(inputMethodProxy, attachOptions_);
    EXPECT_EQ(ret, IME_ERR_OK);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: ShowTextInputWithNullOptions_fail
 * @tc.desc: show text input with invalid param fail after attach
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, ShowTextInputWithNullOptions_fail, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::ShowTextInputWithNullOptions_fail START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    auto ret = OH_InputMethodProxy_ShowTextInput(inputMethodProxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);

    ret = OH_InputMethodProxy_ShowTextInput(nullptr, attachOptions_);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: OH_InputMethodProxy_HideKeyboard_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_InputMethodProxy_HideKeyboard_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_InputMethodProxy_HideKeyboard_001 START");
    auto ret = OH_InputMethodProxy_HideKeyboard(nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: HideKeyboard_SUCCESS
 * @tc.desc: hide keyboard success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, HideKeyboard_SUCCESS, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::HideKeyboard_SUCCESS START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    auto ret = OH_InputMethodProxy_HideKeyboard(inputMethodProxy);
    EXPECT_EQ(ret, IME_ERR_OK);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: OH_InputMethodProxy_NotifySelectionChange_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_InputMethodProxy_NotifySelectionChange_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_InputMethodProxy_NotifySelectionChange_001 START");
    size_t length = 0;
    int start = 0;
    int end = 0;
    auto ret = OH_InputMethodProxy_NotifySelectionChange(nullptr, nullptr, length, start, end);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: NotifySelectionChangeWithNullText_FAIL
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NotifySelectionChangeWithNullText_FAIL, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::NotifySelectionChangeWithNullText_FAIL START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));
    size_t length = 0;
    int start = 0;
    int end = 0;
    auto ret = OH_InputMethodProxy_NotifySelectionChange(inputMethodProxy, nullptr, length, start, end);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: NotifySelectionChangeWithInvalidLength_FAIL
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NotifySelectionChangeWithInvalidLength_FAIL, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::NotifySelectionChangeWithInvalidLength_FAIL START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));
    char16_t text[] = u"1234";
    auto ret = OH_InputMethodProxy_NotifySelectionChange(inputMethodProxy, text, MAX_TEXT_LENGTH + 1, 0, 0);
    EXPECT_EQ(ret, IME_ERR_PARAMCHECK);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: NotifySelectionChange_SUCCESS
 * @tc.desc: NotifySelectionChange success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NotifySelectionChange_SUCCESS, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::NotifySelectionChange_SUCCESS START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));
    char16_t text[] = u"1234";
    auto ret = OH_InputMethodProxy_NotifySelectionChange(inputMethodProxy, text, 4, 0, 0);
    EXPECT_EQ(ret, IME_ERR_OK);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: OH_InputMethodProxy_NotifyConfigurationChange_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_InputMethodProxy_NotifyConfigurationChange_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_InputMethodProxy_NotifyConfigurationChange_001 START");
    InputMethod_EnterKeyType enterKey = IME_ENTER_KEY_UNSPECIFIED;
    InputMethod_TextInputType expInput = IME_TEXT_INPUT_TYPE_NUMBER_DECIMAL;
    auto ret = OH_InputMethodProxy_NotifyConfigurationChange(nullptr, enterKey, expInput);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: NotifyConfigurationChange_SUCCESS
 * @tc.desc: notify configuration change success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NotifyConfigurationChange_SUCCESS, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::NotifyConfigurationChange_SUCCESS START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    InputMethod_EnterKeyType enterKey = IME_ENTER_KEY_UNSPECIFIED;
    InputMethod_TextInputType expInput = IME_TEXT_INPUT_TYPE_NUMBER_DECIMAL;
    auto ret = OH_InputMethodProxy_NotifyConfigurationChange(inputMethodProxy, enterKey, expInput);
    EXPECT_EQ(ret, IME_ERR_OK);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: NotifyCursorUpdate_SUCCESS
 * @tc.desc: notify cursor update success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NotifyCursorUpdate_SUCCESS, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::NotifyCursorUpdate_SUCCESS START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    double left = 0;
    double top = 1.0;
    double width = 2.0;
    double height = 3.0;
    InputMethod_CursorInfo *cursorInfo = OH_CursorInfo_Create(left, top, width, height);
    EXPECT_NE(cursorInfo, nullptr);
    auto ret = OH_InputMethodProxy_NotifyCursorUpdate(inputMethodProxy, cursorInfo);
    EXPECT_EQ(ret, IME_ERR_OK);
    OH_CursorInfo_Destroy(cursorInfo);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: NotifyCursorUpdateWithNullCursorInfo_FAIL
 * @tc.desc: notify cursor update with null cursorInfo fail
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NotifyCursorUpdateWithNullCursorInfo_FAIL, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::NotifyCursorUpdateWithNullCursorInfo_FAIL START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    auto ret = OH_InputMethodProxy_NotifyCursorUpdate(inputMethodProxy, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: OH_InputMethodProxy_NotifyCursorUpdate_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_InputMethodProxy_NotifyCursorUpdate_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_InputMethodProxy_NotifyCursorUpdate_001 START");
    double left = 0;
    double top = 1.0;
    double width = 2.0;
    double height = 3.0;
    InputMethod_CursorInfo *cursorInfo = OH_CursorInfo_Create(left, top, width, height);
    EXPECT_NE(cursorInfo, nullptr);
    auto ret = OH_InputMethodProxy_NotifyCursorUpdate(nullptr, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_InputMethodProxy_NotifyCursorUpdate(nullptr, cursorInfo);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    OH_CursorInfo_Destroy(cursorInfo);
}

/**
 * @tc.name: OH_InputMethodProxy_SendPrivateCommand_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, OH_InputMethodProxy_SendPrivateCommand_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::OH_InputMethodProxy_SendPrivateCommand_001 START");
    char key[] = "example key";
    size_t keyLength = strlen(key);
    char key1[] = "example key";
    size_t keyLength1 = strlen(key);
    InputMethod_PrivateCommand *privateCommand[] = { OH_PrivateCommand_Create(key, keyLength),
        OH_PrivateCommand_Create(key1, keyLength1), nullptr };
    size_t size = 3;
    auto ret = OH_InputMethodProxy_SendPrivateCommand(nullptr, nullptr, size);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_InputMethodProxy_SendPrivateCommand(nullptr, privateCommand, size);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: SendPrivateCommandWithInvalidCommandCount_FAIL
 * @tc.desc: input parameters is invalid
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, SendPrivateCommandWithInvalidCommandCount_FAIL, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::SendPrivateCommandWithInvalidCommandCount_FAIL START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    InputMethod_PrivateCommand *privateCommand[MAX_SYS_PRIVATE_COMMAND_COUNT + 1] = { nullptr };
    auto ret =
        OH_InputMethodProxy_SendPrivateCommand(inputMethodProxy, privateCommand, MAX_SYS_PRIVATE_COMMAND_COUNT + 1);
    EXPECT_EQ(ret, IME_ERR_PARAMCHECK);

    size_t size = 1;
    ret = OH_InputMethodProxy_SendPrivateCommand(inputMethodProxy, privateCommand, size);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: SendPrivateCommandWithNullCommand_FAIL
 * @tc.desc: input parameters is invalid
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, SendPrivateCommandWithNullCommand_FAIL, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::SendPrivateCommandWithNullCommand_FAIL START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    auto ret = OH_InputMethodProxy_SendPrivateCommand(inputMethodProxy, nullptr, 0);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);

    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: SendPrivateCommand_SUCCESS
 * @tc.desc: send private command success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, SendPrivateCommand_SUCCESS, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::SendPrivateCommand_SUCCESS START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));

    char key[] = "example key";
    size_t keyLength = strlen(key);
    InputMethod_PrivateCommand *privateCommand[] = { OH_PrivateCommand_Create(key, keyLength) };
    auto ret = OH_InputMethodProxy_SendPrivateCommand(inputMethodProxy, privateCommand, 1);
    EXPECT_EQ(ret, IME_ERR_OK);

    OH_PrivateCommand_Destroy(privateCommand[0]);
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: TestAttachWithNullParam_001
 * @tc.desc: input parameters is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TestAttachWithNullParam_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::TestAttachWithNullParam_001 START");
    auto ret = OH_InputMethodController_Attach(nullptr, nullptr, nullptr);
    EXPECT_EQ(IME_ERR_NULL_POINTER, ret);

    auto textEditorProxy = OH_TextEditorProxy_Create();
    EXPECT_NE(nullptr, textEditorProxy);

    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetTextConfigFunc(textEditorProxy, GetTextConfigFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetInsertTextFunc(textEditorProxy, InsertTextFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetDeleteForwardFunc(textEditorProxy, DeleteForwardFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetDeleteBackwardFunc(textEditorProxy, DeleteBackwardFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetSendKeyboardStatusFunc(textEditorProxy, SendKeyboardStatusFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetSendEnterKeyFunc(textEditorProxy, SendEnterKeyFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetMoveCursorFunc(textEditorProxy, MoveCursorFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetHandleSetSelectionFunc(textEditorProxy, HandleSetSelectionFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetHandleExtendActionFunc(textEditorProxy, HandleExtendActionFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetLeftTextOfCursorFunc(textEditorProxy, GetleftTextOfCursorFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetRightTextOfCursorFunc(textEditorProxy, GetRightTextOfCursorFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetGetTextIndexAtCursorFunc(textEditorProxy, GetTextIndexAtCursorFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetReceivePrivateCommandFunc(textEditorProxy, ReceivePrivateCommandFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    EXPECT_EQ(IME_ERR_OK, OH_TextEditorProxy_SetSetPreviewTextFunc(textEditorProxy, SetPreviewTextFunc));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodController_Attach(textEditorProxy, nullptr, nullptr));

    OH_TextEditorProxy_Destroy(textEditorProxy);
}

/**
 * @tc.name: TestAttachWithNorrmalParam_001
 * @tc.desc: input parameters is normal
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TestAttachWithNorrmalParam_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::TestAttachWithNorrmalParam_001 START");
    auto textEditorProxy = OH_TextEditorProxy_Create();
    EXPECT_NE(nullptr, textEditorProxy);
    ConstructTextEditorProxy(textEditorProxy);

    auto options = OH_AttachOptions_Create(true);
    EXPECT_NE(nullptr, options);
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy, options, &inputMethodProxy));
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy, options, &inputMethodProxy));

    auto textEditorProxy2 = OH_TextEditorProxy_Create();
    EXPECT_NE(nullptr, textEditorProxy2);
    ConstructTextEditorProxy(textEditorProxy2);
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy2, options, &inputMethodProxy));

    OH_InputMethodController_Detach(inputMethodProxy);
    OH_TextEditorProxy_Destroy(textEditorProxy2);
    OH_AttachOptions_Destroy(options);
    OH_TextEditorProxy_Destroy(textEditorProxy);
}

/**
 * @tc.name: TestAttachWithPlaceholderAndAbility_001
 * @tc.desc: the input parameter contains the placeholder and ability name
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, TestAttachWithPlaceholderAndAbility_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::TestAttachWithPlaceholderAndAbility_001 START");
    auto options = OH_AttachOptions_Create(true);
    auto textEditorProxy2 = OH_TextEditorProxy_Create();
    EXPECT_NE(nullptr, textEditorProxy2);
    ConstructTextEditorProxy(textEditorProxy2);
    auto fnGetTextConfigFunc = [](InputMethod_TextEditorProxy *textEditorProxy, InputMethod_TextConfig *config) {
        std::u16string placeholder = u"test placeholder";
        std::u16string abilityName = u"test ability name";
        OH_TextConfig_SetPlaceholder(config, placeholder.data(), placeholder.size());
        OH_TextConfig_SetAbilityName(config, abilityName.data(), abilityName.size());
    };
    OH_TextEditorProxy_SetGetTextConfigFunc(textEditorProxy2, fnGetTextConfigFunc);
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    auto ret = OH_InputMethodController_Attach(textEditorProxy2, options, &inputMethodProxy);
    EXPECT_EQ(ret, IME_ERR_OK);

    OH_InputMethodController_Detach(inputMethodProxy);
    OH_TextEditorProxy_Destroy(textEditorProxy2);
    OH_AttachOptions_Destroy(options);
}

/**
 * @tc.name: Attach_BorrowedConfigAndReentry
 * @tc.desc: Callback-owned config and children survive attempted destruction and expire on callback return.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, Attach_BorrowedConfigAndReentry, TestSize.Level0)
{
    auto editor = OH_TextEditorProxy_Create();
    ASSERT_NE(nullptr, editor);
    ConstructTextEditorProxy(editor);
    static std::shared_ptr<InputMethod_TextConfig> borrowed;
    static InputMethod_CursorInfo *cursor = nullptr;
    static InputMethod_TextAvoidInfo *avoid = nullptr;
    borrowed.reset();
    cursor = nullptr;
    avoid = nullptr;
    EXPECT_EQ(IME_ERR_OK,
        OH_TextEditorProxy_SetGetTextConfigFunc(
            editor, [](InputMethod_TextEditorProxy *proxy, InputMethod_TextConfig *config) {
                borrowed = NativeObjectRegistry<InputMethod_TextConfig>::GetInstance().Get(config);
                OH_TextConfig_Destroy(config);
                EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetWindowId(config, 123));
                EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetCursorInfo(config, &cursor));
                EXPECT_EQ(IME_ERR_OK, OH_TextConfig_GetTextAvoidInfo(config, &avoid));
                OH_CursorInfo_Destroy(cursor);
                OH_TextAvoidInfo_Destroy(avoid);
                EXPECT_EQ(IME_ERR_OK, OH_CursorInfo_SetRect(cursor, 1, 2, 3, 4));
                EXPECT_EQ(IME_ERR_OK, OH_TextAvoidInfo_SetHeight(avoid, 5));
                EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodController_Attach(proxy, nullptr, nullptr));
                EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodProxy_ShowKeyboard(nullptr));
            }));
    InputMethod_InputMethodProxy *result = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(editor, attachOptions_, &result));
    EXPECT_NE(nullptr, borrowed);
    int32_t windowId = -1;
    double value = -1;
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextConfig_GetWindowId(borrowed.get(), &windowId));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_CursorInfo_GetRect(cursor, &value, &value, &value, &value));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_TextAvoidInfo_GetHeight(avoid, &value));
    EXPECT_EQ(-1, windowId);
    EXPECT_EQ(-1, value);
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(result));
    OH_TextEditorProxy_Destroy(editor);
    borrowed.reset();
}

/**
 * @tc.name: Attach_CancelWhenEditorDestroyedInCallback
 * @tc.desc: Destroying the editor during GetTextConfig cancels attach instead of using a stale handle.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, Attach_CancelWhenEditorDestroyedInCallback, TestSize.Level0)
{
    auto editor = OH_TextEditorProxy_Create();
    ASSERT_NE(nullptr, editor);
    ConstructTextEditorProxy(editor);
    InputMethod_InputMethodProxy *result = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(editor, attachOptions_, &result));
    EXPECT_EQ(IME_ERR_OK,
        OH_TextEditorProxy_SetGetTextConfigFunc(
            editor, [](InputMethod_TextEditorProxy *proxy, InputMethod_TextConfig *config) {
                OH_TextEditorProxy_Destroy(proxy);
                EXPECT_EQ(IME_ERR_OK, OH_TextConfig_SetWindowId(config, 321));
            }));
    InputMethod_InputMethodProxy *cancelled = nullptr;
    EXPECT_EQ(IME_ERR_IMCLIENT, OH_InputMethodController_Attach(editor, attachOptions_, &cancelled));
    EXPECT_EQ(nullptr, cancelled);
    EXPECT_TRUE(TextEditorProxyManager::GetInstance().GetWeak(editor).expired());
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(result));
}

/**
 * @tc.name: InputMethodProxy_RejectRetiredValueHandles
 * @tc.desc: An attached proxy rejects invalid value and callback handles before native dispatch.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, InputMethodProxy_RejectRetiredValueHandles, TestSize.Level0)
{
    InputMethod_InputMethodProxy *proxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &proxy));
    InputMethod_AttachOptions options {};
    InputMethod_CursorInfo cursor;
    InputMethod_PrivateCommand command {};
    InputMethod_MessageHandlerProxy handler;
    InputMethod_PrivateCommand *commands[] = { &command };
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_InputMethodProxy_ShowTextInput(proxy, &options));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_InputMethodProxy_NotifyCursorUpdate(proxy, &cursor));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_InputMethodProxy_SendPrivateCommand(proxy, commands, 1));
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_InputMethodProxy_RecvMessage(proxy, &handler));
    auto messageHandler = OH_MessageHandlerProxy_Create();
    ASSERT_NE(nullptr, messageHandler);
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodProxy_RecvMessage(proxy, messageHandler));
    EXPECT_EQ(
        IME_ERR_OK, OH_MessageHandlerProxy_SetOnTerminatedFunc(messageHandler, [](InputMethod_MessageHandlerProxy *) {
            return 0;
        }));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethodProxy_RecvMessage(proxy, messageHandler));
    OH_MessageHandlerProxy_Destroy(messageHandler);
    EXPECT_EQ(IME_ERR_PARAMCHECK, OH_InputMethodProxy_RecvMessage(proxy, messageHandler));
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(proxy));
}

/**
 * @tc.name: SetOnTerminatedFuncWithNull_FAIL
 * @tc.desc: GetOnTerminatedFunc with null fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodControllerCapiTest, SetOnTerminatedFuncWithNull_FAIL, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::SetOnTerminatedFuncWithNull_FAIL START");
    auto proxy = OH_MessageHandlerProxy_Create();
    EXPECT_NE(proxy, nullptr);

    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_MessageHandlerProxy_SetOnTerminatedFunc(nullptr, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_MessageHandlerProxy_SetOnTerminatedFunc(proxy, nullptr));

    OH_MessageHandlerProxy_Destroy(proxy);
    OH_MessageHandlerProxy_Destroy(nullptr);
}

/**
 * @tc.name: GetOnTerminatedFuncWithNull_FAIL
 * @tc.desc: GetOnTerminatedFunc with null fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodControllerCapiTest, GetOnTerminatedFuncWithNull_FAIL, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::GetOnTerminatedFuncWithNull_FAIL START");
    auto proxy = OH_MessageHandlerProxy_Create();
    EXPECT_NE(proxy, nullptr);

    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_MessageHandlerProxy_GetOnTerminatedFunc(nullptr, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_MessageHandlerProxy_GetOnTerminatedFunc(proxy, nullptr));

    OH_MessageHandlerProxy_Destroy(proxy);
}

/**
 * @tc.name: SetOnMessageFuncWithNull_FAIL
 * @tc.desc: GetOnTerminatedFunc with null fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodControllerCapiTest, SetOnMessageFuncWithNull_FAIL, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::SetOnMessageFuncWithNull_FAIL START");
    auto proxy = OH_MessageHandlerProxy_Create();
    EXPECT_NE(proxy, nullptr);

    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_MessageHandlerProxy_SetOnMessageFunc(nullptr, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_MessageHandlerProxy_SetOnMessageFunc(proxy, nullptr));

    OH_MessageHandlerProxy_Destroy(proxy);
    OH_MessageHandlerProxy_Destroy(nullptr);
}

/**
 * @tc.name: GetOnMessageFuncWithNull_FAIL
 * @tc.desc: GetOnTerminatedFunc with null fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodControllerCapiTest, GetOnMessageFuncWithNull_FAIL, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::GetOnMessageFuncWithNull_FAIL START");
    auto proxy = OH_MessageHandlerProxy_Create();
    EXPECT_NE(proxy, nullptr);

    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_MessageHandlerProxy_GetOnMessageFunc(nullptr, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_MessageHandlerProxy_GetOnMessageFunc(proxy, nullptr));

    OH_MessageHandlerProxy_Destroy(proxy);
}

/**
 * @tc.name: RequestSystemInputCapability_NullProxy
 * @tc.desc: AC-1.5: pass nullptr proxy, expect IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, RequestSystemInputCapability_NullProxy, TestSize.Level0)
{
    IMSA_HILOGI("RequestSystemInputCapability_NullProxy START");
    auto ret = OH_InputMethod_InputMethodProxy_RequestSystemInputCapability(
        nullptr, OH_INPUTMETHOD_INPUT_CAPABILITY_TYPE_TRANSLATION);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}
 
/**
 * @tc.name: RequestSystemInputCapability_InvalidType
 * @tc.desc: AC-1.6: pass invalid type, expect IME_ERR_PARAMCHECK
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, RequestSystemInputCapability_InvalidType, TestSize.Level0)
{
    IMSA_HILOGI("RequestSystemInputCapability_InvalidType START");
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));
    OH_InputMethod_InputCapabilityType invalidType = static_cast<OH_InputMethod_InputCapabilityType>(99);
    auto ret = OH_InputMethod_InputMethodProxy_RequestSystemInputCapability(inputMethodProxy, invalidType);
    EXPECT_EQ(ret, IME_ERR_PARAMCHECK);
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: RequestSystemInputCapability_InvalidTypeWithoutAttach
 * @tc.desc: AC-1.7: invalid type without attach, expect IME_ERR_PARAMCHECK
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, RequestSystemInputCapability_InvalidTypeWithoutAttach, TestSize.Level0)
{
    IMSA_HILOGI("RequestSystemInputCapability_InvalidTypeWithoutAttach START");
    OH_InputMethod_InputCapabilityType invalidType = static_cast<OH_InputMethod_InputCapabilityType>(-1);
    auto ret = OH_InputMethod_InputMethodProxy_RequestSystemInputCapability(nullptr, invalidType);
    EXPECT_EQ(ret, IME_ERR_PARAMCHECK);
}

/**
 * @tc.name: RequestSystemInputCapability_Success
 * @tc.desc: AC-1.3: mock proxy returns NO_ERROR, expect IME_ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, RequestSystemInputCapability_Success, TestSize.Level0)
{
    IMSA_HILOGI("RequestSystemInputCapability_Success START");
    ON_CALL(*systemAbilityProxyMock_, RequestSystemInputCapability(_))
        .WillByDefault(Return(ErrorCode::NO_ERROR));
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));
    auto ret = OH_InputMethod_InputMethodProxy_RequestSystemInputCapability(
        inputMethodProxy, OH_INPUTMETHOD_INPUT_CAPABILITY_TYPE_TRANSLATION);
    EXPECT_EQ(ret, IME_ERR_OK);
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}

/**
 * @tc.name: RequestSystemInputCapability_NotDefaultIme
 * @tc.desc: AC-1.4: mock returns ERROR_NOT_DEFAULT_IME, expect OH_INPUTMETHOD_ERR_NOT_DEFAULT_IME
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, RequestSystemInputCapability_NotDefaultIme, TestSize.Level0)
{
    IMSA_HILOGI("RequestSystemInputCapability_NotDefaultIme START");
    ON_CALL(*systemAbilityProxyMock_, RequestSystemInputCapability(_))
        .WillByDefault(Return(ErrorCode::ERROR_NOT_DEFAULT_IME));
    InputMethod_InputMethodProxy *inputMethodProxy = nullptr;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Attach(textEditorProxy_, attachOptions_, &inputMethodProxy));
    auto ret = OH_InputMethod_InputMethodProxy_RequestSystemInputCapability(
        inputMethodProxy, OH_INPUTMETHOD_INPUT_CAPABILITY_TYPE_TRANSLATION);
    EXPECT_EQ(ret, OH_INPUTMETHOD_ERR_NOT_DEFAULT_IME);
    EXPECT_EQ(ret, 12800010);
    EXPECT_EQ(IME_ERR_OK, OH_InputMethodController_Detach(inputMethodProxy));
}
 
/**
 * @tc.name: GetCurrentInputMethod_NullParam
 * @tc.desc: AC-2.2: pass nullptr parameter, expect IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, GetCurrentInputMethod_NullParam, TestSize.Level0)
{
    IMSA_HILOGI("GetCurrentInputMethod_NullParam START");
    char *bundleName = nullptr;
    uint32_t bundleNameLength = 0;
    char *abilityName = nullptr;
    uint32_t abilityNameLength = 0;
    auto ret = OH_InputMethod_InputMethodController_GetCurrentInputMethod(
        nullptr, &bundleNameLength, &abilityName, &abilityNameLength);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_InputMethod_InputMethodController_GetCurrentInputMethod(
        &bundleName, nullptr, &abilityName, &abilityNameLength);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_InputMethod_InputMethodController_GetCurrentInputMethod(
        &bundleName, &bundleNameLength, nullptr, &abilityNameLength);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
    ret = OH_InputMethod_InputMethodController_GetCurrentInputMethod(
        &bundleName, &bundleNameLength, &abilityName, nullptr);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}
 
/**
 * @tc.name: GetCurrentInputMethod_Success
 * @tc.desc: AC-2.1: success, expect IME_ERR_OK and correct bundleName/abilityName
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, GetCurrentInputMethod_Success, TestSize.Level0)
{
    IMSA_HILOGI("GetCurrentInputMethod_Success START");
    Property mockProp;
    mockProp.name = "com.example.testime";
    mockProp.id = "ServiceExtAbility";
    ON_CALL(*systemAbilityProxyMock_, GetCurrentInputMethod(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(mockProp), Return(ErrorCode::NO_ERROR)));
    char *bundleName = nullptr;
    uint32_t bundleNameLength = 0;
    char *abilityName = nullptr;
    uint32_t abilityNameLength = 0;
    auto ret = OH_InputMethod_InputMethodController_GetCurrentInputMethod(
        &bundleName, &bundleNameLength, &abilityName, &abilityNameLength);
    EXPECT_EQ(ret, IME_ERR_OK);
    ASSERT_NE(nullptr, bundleName);
    ASSERT_NE(nullptr, abilityName);
    EXPECT_STREQ(bundleName, mockProp.name.c_str());
    EXPECT_STREQ(abilityName, mockProp.id.c_str());
    EXPECT_EQ(bundleNameLength, mockProp.name.size() + 1);
    EXPECT_EQ(abilityNameLength, mockProp.id.size() + 1);
    free(bundleName);
    free(abilityName);
}

/**
 * @tc.name: PreviewTextStyle_CreateAndDestroy_001
 * @tc.desc: Create and destroy OH_InputMethod_PreviewTextStyle success
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_CreateAndDestroy_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_CreateAndDestroy_001 START");
    auto style = OH_InputMethod_PreviewTextStyle_Create();
    ASSERT_NE(nullptr, style);
    OH_InputMethod_PreviewTextStyle_Destroy(style);
}

/**
 * @tc.name: PreviewTextStyle_Destroy_Null_001
 * @tc.desc: Destroy nullptr does not crash, and destroying a valid instance works correctly
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_Destroy_Null_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_Destroy_Null_001 START");
    // Destroy nullptr should be a no-op without crash
    OH_InputMethod_PreviewTextStyle_Destroy(nullptr);
    // Destroy a valid instance should release memory without crash
    auto style = OH_InputMethod_PreviewTextStyle_Create();
    ASSERT_NE(nullptr, style);
    OH_InputMethod_PreviewTextStyle_Destroy(style);
    // Destroy twice to verify idempotency is not guaranteed (style is already freed),
    // but destroying nullptr again is safe
    OH_InputMethod_PreviewTextStyle_Destroy(nullptr);
    SUCCEED();
}

/**
 * @tc.name: PreviewTextStyle_SetAndGetUnderlineStyle_001
 * @tc.desc: Set and get underline style with all enum values
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_SetAndGetUnderlineStyle_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_SetAndGetUnderlineStyle_001 START");
    auto style = OH_InputMethod_PreviewTextStyle_Create();
    ASSERT_NE(nullptr, style);

    OH_InputMethod_UnderlineStyle styles[] = {
        OH_INPUTMETHOD_UNDERLINE_STYLE_NONE,
        OH_INPUTMETHOD_UNDERLINE_STYLE_SOLID,
        OH_INPUTMETHOD_UNDERLINE_STYLE_WAVY,
        OH_INPUTMETHOD_UNDERLINE_STYLE_DASHED,
    };
    for (auto &expected : styles) {
        EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_SetUnderlineStyle(style, expected));
        OH_InputMethod_UnderlineStyle actual = OH_INPUTMETHOD_UNDERLINE_STYLE_NONE;
        EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(style, &actual));
        EXPECT_EQ(expected, actual);
    }
    OH_InputMethod_PreviewTextStyle_Destroy(style);
}

/**
 * @tc.name: PreviewTextStyle_SetUnderlineStyle_Null_001
 * @tc.desc: SetUnderlineStyle with null style returns IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_SetUnderlineStyle_Null_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_SetUnderlineStyle_Null_001 START");
    auto ret = OH_InputMethod_PreviewTextStyle_SetUnderlineStyle(nullptr, OH_INPUTMETHOD_UNDERLINE_STYLE_SOLID);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: PreviewTextStyle_GetUnderlineStyle_Null_001
 * @tc.desc: GetUnderlineStyle with null parameters returns IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_GetUnderlineStyle_Null_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_GetUnderlineStyle_Null_001 START");
    auto style = OH_InputMethod_PreviewTextStyle_Create();
    ASSERT_NE(nullptr, style);

    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(nullptr, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(style, nullptr));
    OH_InputMethod_UnderlineStyle out = OH_INPUTMETHOD_UNDERLINE_STYLE_NONE;
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(nullptr, &out));

    OH_InputMethod_PreviewTextStyle_Destroy(style);
}

/**
 * @tc.name: PreviewTextStyle_SetAndGetUnderlineColor_001
 * @tc.desc: Set and get underline color, verify hasUnderlineColor becomes true
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_SetAndGetUnderlineColor_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_SetAndGetUnderlineColor_001 START");
    auto style = OH_InputMethod_PreviewTextStyle_Create();
    ASSERT_NE(nullptr, style);

    // Before SetUnderlineColor, hasUnderlineColor should be false
    bool hasColor = true;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_HasUnderlineColor(style, &hasColor));
    EXPECT_FALSE(hasColor);

    uint32_t colors[] = { 0x00000000, 0xFFFF0000, 0xFF00FF00, 0x0000FFAA, 0xFFFFFFFF };
    for (auto &expected : colors) {
        EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_SetUnderlineColor(style, expected));
        // After SetUnderlineColor, hasUnderlineColor should be true
        hasColor = false;
        EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_HasUnderlineColor(style, &hasColor));
        EXPECT_TRUE(hasColor);
        uint32_t actual = 0;
        EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_GetUnderlineColor(style, &actual));
        EXPECT_EQ(expected, actual);
    }
    OH_InputMethod_PreviewTextStyle_Destroy(style);
}

/**
 * @tc.name: PreviewTextStyle_SetUnderlineColor_Null_001
 * @tc.desc: SetUnderlineColor with null style returns IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_SetUnderlineColor_Null_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_SetUnderlineColor_Null_001 START");
    auto ret = OH_InputMethod_PreviewTextStyle_SetUnderlineColor(nullptr, 0xFFFF0000);
    EXPECT_EQ(ret, IME_ERR_NULL_POINTER);
}

/**
 * @tc.name: PreviewTextStyle_GetUnderlineColor_Null_001
 * @tc.desc: GetUnderlineColor with null parameters returns IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_GetUnderlineColor_Null_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_GetUnderlineColor_Null_001 START");
    auto style = OH_InputMethod_PreviewTextStyle_Create();
    ASSERT_NE(nullptr, style);

    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethod_PreviewTextStyle_GetUnderlineColor(nullptr, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethod_PreviewTextStyle_GetUnderlineColor(style, nullptr));
    uint32_t out = 0;
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethod_PreviewTextStyle_GetUnderlineColor(nullptr, &out));

    OH_InputMethod_PreviewTextStyle_Destroy(style);
}

/**
 * @tc.name: PreviewTextStyle_HasUnderlineColor_Null_001
 * @tc.desc: HasUnderlineColor with null parameters returns IME_ERR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_HasUnderlineColor_Null_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_HasUnderlineColor_Null_001 START");
    auto style = OH_InputMethod_PreviewTextStyle_Create();
    ASSERT_NE(nullptr, style);

    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethod_PreviewTextStyle_HasUnderlineColor(nullptr, nullptr));
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethod_PreviewTextStyle_HasUnderlineColor(style, nullptr));
    bool out = false;
    EXPECT_EQ(IME_ERR_NULL_POINTER, OH_InputMethod_PreviewTextStyle_HasUnderlineColor(nullptr, &out));

    OH_InputMethod_PreviewTextStyle_Destroy(style);
}

/**
 * @tc.name: PreviewTextStyle_DefaultValues_001
 * @tc.desc: Newly created PreviewTextStyle has default values (NONE, 0, false)
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_DefaultValues_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_DefaultValues_001 START");
    auto style = OH_InputMethod_PreviewTextStyle_Create();
    ASSERT_NE(nullptr, style);

    OH_InputMethod_UnderlineStyle underlineStyle = OH_INPUTMETHOD_UNDERLINE_STYLE_DASHED;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(style, &underlineStyle));
    EXPECT_EQ(OH_INPUTMETHOD_UNDERLINE_STYLE_NONE, underlineStyle);

    uint32_t underlineColor = 0xFFFFFFFF;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_GetUnderlineColor(style, &underlineColor));
    EXPECT_EQ(0U, underlineColor);

    bool hasUnderlineColor = true;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_HasUnderlineColor(style, &hasUnderlineColor));
    EXPECT_FALSE(hasUnderlineColor);

    OH_InputMethod_PreviewTextStyle_Destroy(style);
}

/**
 * @tc.name: PreviewTextStyle_FullWorkflow_001
 * @tc.desc: Full workflow: create, set style+color, verify all, destroy
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, PreviewTextStyle_FullWorkflow_001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodControllerCapiTest::PreviewTextStyle_FullWorkflow_001 START");
    auto style = OH_InputMethod_PreviewTextStyle_Create();
    ASSERT_NE(nullptr, style);

    // Set SOLID style and red color
    EXPECT_EQ(IME_ERR_OK,
        OH_InputMethod_PreviewTextStyle_SetUnderlineStyle(style, OH_INPUTMETHOD_UNDERLINE_STYLE_SOLID));
    EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_SetUnderlineColor(style, 0xFFFF0000));

    // Verify all values
    OH_InputMethod_UnderlineStyle outStyle = OH_INPUTMETHOD_UNDERLINE_STYLE_NONE;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_GetUnderlineStyle(style, &outStyle));
    EXPECT_EQ(OH_INPUTMETHOD_UNDERLINE_STYLE_SOLID, outStyle);

    uint32_t outColor = 0;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_GetUnderlineColor(style, &outColor));
    EXPECT_EQ(0xFFFF0000U, outColor);

    bool hasColor = false;
    EXPECT_EQ(IME_ERR_OK, OH_InputMethod_PreviewTextStyle_HasUnderlineColor(style, &hasColor));
    EXPECT_TRUE(hasColor);

    OH_InputMethod_PreviewTextStyle_Destroy(style);
}

/**
 * @tc.name: MessageHandler_RejectInvalidHandles
 * @tc.desc: Callback setters and getters reject unregistered and retired handlers without changing outputs.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, MessageHandler_RejectInvalidHandles, TestSize.Level0)
{
    InputMethod_MessageHandlerProxy unregistered;
    auto proxy = OH_MessageHandlerProxy_Create();
    ASSERT_NE(nullptr, proxy);
    auto lease = NativeObjectRegistry<InputMethod_MessageHandlerProxy>::GetInstance().Get(proxy);
    OH_MessageHandlerProxy_Destroy(proxy);
    for (auto invalid : { &unregistered, proxy }) {
        OH_MessageHandlerProxy_OnTerminatedFunc terminated = nullptr;
        OH_MessageHandlerProxy_OnMessageFunc message = nullptr;
        EXPECT_EQ(IME_ERR_PARAMCHECK,
            OH_MessageHandlerProxy_SetOnTerminatedFunc(invalid, [](InputMethod_MessageHandlerProxy *) {
                return 0;
            }));
        EXPECT_EQ(IME_ERR_PARAMCHECK,
            OH_MessageHandlerProxy_SetOnMessageFunc(
                invalid, [](InputMethod_MessageHandlerProxy *, const char16_t *, size_t, const uint8_t *, size_t) {
                    return 0;
                }));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_MessageHandlerProxy_GetOnTerminatedFunc(invalid, &terminated));
        EXPECT_EQ(IME_ERR_PARAMCHECK, OH_MessageHandlerProxy_GetOnMessageFunc(invalid, &message));
        EXPECT_EQ(nullptr, terminated);
        EXPECT_EQ(nullptr, message);
    }
    OH_MessageHandlerProxy_Destroy(proxy);
}

/**
 * @tc.name: NativeMessageHandler_MissingCallbacks
 * @tc.desc: Missing handlers and missing callback slots return the existing null-pointer error.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NativeMessageHandler_MissingCallbacks, TestSize.Level0)
{
    ArrayBuffer buffer;
    NativeMessageHandlerCallback missing(nullptr);
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, missing.OnTerminated());
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, missing.OnMessage(buffer));
    auto proxy = OH_MessageHandlerProxy_Create();
    ASSERT_NE(nullptr, proxy);
    NativeMessageHandlerCallback callback(proxy);
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, callback.OnTerminated());
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, callback.OnMessage(buffer));
    OH_MessageHandlerProxy_Destroy(proxy);
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, callback.OnTerminated());
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, callback.OnMessage(buffer));
}

/**
 * @tc.name: NativeMessageHandler_RejectRetiredHandlerWithLease
 * @tc.desc: An external storage lease must not keep retired callbacks dispatchable.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NativeMessageHandler_RejectRetiredHandlerWithLease, TestSize.Level0)
{
    auto proxy = OH_MessageHandlerProxy_Create();
    ASSERT_NE(nullptr, proxy);
    auto lease = NativeObjectRegistry<InputMethod_MessageHandlerProxy>::GetInstance().Get(proxy);
    EXPECT_EQ(IME_ERR_OK, OH_MessageHandlerProxy_SetOnTerminatedFunc(proxy, [](InputMethod_MessageHandlerProxy *) {
        ADD_FAILURE() << "A retired handler must not dispatch";
        return 0;
    }));
    EXPECT_EQ(IME_ERR_OK,
        OH_MessageHandlerProxy_SetOnMessageFunc(
            proxy, [](InputMethod_MessageHandlerProxy *, const char16_t *, size_t, const uint8_t *, size_t) {
                ADD_FAILURE() << "A retired handler must not dispatch";
                return 0;
            }));
    NativeMessageHandlerCallback callback(proxy);
    OH_MessageHandlerProxy_Destroy(proxy);
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, callback.OnTerminated());
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, callback.OnMessage(ArrayBuffer {}));
}

/**
 * @tc.name: NativeMessageHandler_CallbackReplacementAndErrors
 * @tc.desc: Each dispatch snapshots its callback, and later dispatch sees replacement and failure mapping.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NativeMessageHandler_CallbackReplacementAndErrors, TestSize.Level0)
{
    auto proxy = OH_MessageHandlerProxy_Create();
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(
        IME_ERR_OK, OH_MessageHandlerProxy_SetOnTerminatedFunc(proxy, [](InputMethod_MessageHandlerProxy *handler) {
            EXPECT_EQ(
                IME_ERR_OK, OH_MessageHandlerProxy_SetOnTerminatedFunc(handler, [](InputMethod_MessageHandlerProxy *) {
                    return -1;
                }));
            return 0;
        }));
    EXPECT_EQ(IME_ERR_OK,
        OH_MessageHandlerProxy_SetOnMessageFunc(proxy,
            [](InputMethod_MessageHandlerProxy *handler, const char16_t *id, size_t idLength, const uint8_t *data,
                size_t dataLength) {
                EXPECT_EQ(u"message", std::u16string(id, idLength));
                EXPECT_EQ(2, dataLength);
                EXPECT_EQ(1, data[0]);
                EXPECT_EQ(2, data[1]);
                EXPECT_EQ(IME_ERR_OK,
                    OH_MessageHandlerProxy_SetOnMessageFunc(handler,
                        [](InputMethod_MessageHandlerProxy *, const char16_t *, size_t, const uint8_t *, size_t) {
                            return -1;
                        }));
                return 0;
            }));
    NativeMessageHandlerCallback callback(proxy);
    ArrayBuffer buffer;
    buffer.msgId = "message";
    buffer.msgParam = { 1, 2 };
    EXPECT_EQ(ErrorCode::NO_ERROR, callback.OnTerminated());
    EXPECT_EQ(ErrorCode::ERROR_MESSAGE_HANDLER, callback.OnTerminated());
    EXPECT_EQ(ErrorCode::NO_ERROR, callback.OnMessage(buffer));
    EXPECT_EQ(ErrorCode::ERROR_MESSAGE_HANDLER, callback.OnMessage(buffer));
    OH_MessageHandlerProxy_Destroy(proxy);
}

/**
 * @tc.name: NativeMessageHandler_DestroyDuringTermination
 * @tc.desc: A terminating callback may retire itself while the in-flight dispatch retains its storage.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NativeMessageHandler_DestroyDuringTermination, TestSize.Level0)
{
    auto proxy = OH_MessageHandlerProxy_Create();
    ASSERT_NE(nullptr, proxy);
    auto &registry = NativeObjectRegistry<InputMethod_MessageHandlerProxy>::GetInstance();
    std::weak_ptr<InputMethod_MessageHandlerProxy> storage = registry.Get(proxy);
    EXPECT_EQ(
        IME_ERR_OK, OH_MessageHandlerProxy_SetOnTerminatedFunc(proxy, [](InputMethod_MessageHandlerProxy *handler) {
            OH_MessageHandlerProxy_Destroy(handler);
            EXPECT_NE(nullptr, handler->onTerminatedFunc.load());
            return 0;
        }));
    NativeMessageHandlerCallback callback(proxy);
    EXPECT_EQ(ErrorCode::NO_ERROR, callback.OnTerminated());
    EXPECT_TRUE(storage.expired());
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, callback.OnTerminated());
}

/**
 * @tc.name: NativeMessageHandler_DestroyDuringMessage
 * @tc.desc: A message callback may destroy its handle without releasing its in-flight storage early.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodControllerCapiTest, NativeMessageHandler_DestroyDuringMessage, TestSize.Level0)
{
    auto proxy = OH_MessageHandlerProxy_Create();
    ASSERT_NE(nullptr, proxy);
    auto &registry = NativeObjectRegistry<InputMethod_MessageHandlerProxy>::GetInstance();
    std::weak_ptr<InputMethod_MessageHandlerProxy> storage = registry.Get(proxy);
    EXPECT_EQ(IME_ERR_OK,
        OH_MessageHandlerProxy_SetOnMessageFunc(
            proxy, [](InputMethod_MessageHandlerProxy *handler, const char16_t *, size_t, const uint8_t *, size_t) {
                OH_MessageHandlerProxy_Destroy(handler);
                EXPECT_NE(nullptr, handler->onMessageFunc.load());
                return 0;
            }));
    NativeMessageHandlerCallback callback(proxy);
    EXPECT_EQ(ErrorCode::NO_ERROR, callback.OnMessage(ArrayBuffer {}));
    EXPECT_TRUE(storage.expired());
    EXPECT_EQ(ErrorCode::ERROR_CLIENT_NULL_POINTER, callback.OnMessage(ArrayBuffer {}));
}
} // namespace MiscServices
} // namespace OHOS
