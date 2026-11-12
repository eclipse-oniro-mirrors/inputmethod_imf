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

#include "input_method_tools.h"

#include <gtest/gtest.h>
#include "message_parcel.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {

class InputMethodToolsTest : public testing::Test {
public:
    static void SetUpTestCase(void) { }
    static void TearDownTestCase(void) { }
    void SetUp() { }
    void TearDown() { }
};

// ExtraConfigToInner / InnerToExtraConfig RoundTrip
HWTEST_F(InputMethodToolsTest, ExtraConfig_RoundTrip, TestSize.Level0)
{
    IMSA_HILOGI("ExtraConfig_RoundTrip begin");
    ExtraConfig original;
    original.customSettings["key1"] = std::string("value1");
    original.customSettings["key2"] = true;
    original.customSettings["key3"] = 42;

    auto inner = InputMethodTools::GetInstance().ExtraConfigToInner(original);
    auto result = InputMethodTools::GetInstance().InnerToExtraConfig(inner);
    EXPECT_EQ(result, original);
}

// AttributeToInner / InnerToAttribute RoundTrip
HWTEST_F(InputMethodToolsTest, Attribute_RoundTrip, TestSize.Level0)
{
    IMSA_HILOGI("Attribute_RoundTrip begin");
    InputAttribute original;
    original.inputPattern = 7;
    original.enterKeyType = 3;
    original.inputOption = 1;
    original.isTextPreviewSupported = true;
    original.bundleName = "com.test.ime";
    original.immersiveMode = 2;
    original.gradientMode = 1;
    original.fluidLightMode = 3;
    original.editorWindowId = 100;
    original.editorDisplayId = 200;
    original.windowId = 50;
    original.callingDisplayId = 300;
    original.displayGroupId = 400;
    original.placeholder = u"hint";
    original.abilityName = u"MainAbility";
    original.capitalizeMode = CapitalizeMode::SENTENCES;
    original.needAutoInputNumkey = true;
    original.consumeKeyEvents = true;
    original.extraConfig.customSettings["k"] = std::string("v");

    auto inner = InputMethodTools::GetInstance().AttributeToInner(original);
    auto result = InputMethodTools::GetInstance().InnerToAttribute(inner);
    EXPECT_EQ(result.inputPattern, original.inputPattern);
    EXPECT_EQ(result.enterKeyType, original.enterKeyType);
    EXPECT_EQ(result.inputOption, original.inputOption);
    EXPECT_EQ(result.isTextPreviewSupported, original.isTextPreviewSupported);
    EXPECT_EQ(result.bundleName, original.bundleName);
    EXPECT_EQ(result.immersiveMode, original.immersiveMode);
    EXPECT_EQ(result.gradientMode, original.gradientMode);
    EXPECT_EQ(result.fluidLightMode, original.fluidLightMode);
    EXPECT_EQ(result.editorWindowId, original.editorWindowId);
    EXPECT_EQ(result.editorDisplayId, original.editorDisplayId);
    EXPECT_EQ(result.windowId, original.windowId);
    EXPECT_EQ(result.callingDisplayId, original.callingDisplayId);
    EXPECT_EQ(result.displayGroupId, original.displayGroupId);
    EXPECT_EQ(result.placeholder, original.placeholder);
    EXPECT_EQ(result.abilityName, original.abilityName);
    EXPECT_EQ(result.capitalizeMode, original.capitalizeMode);
    EXPECT_EQ(result.needAutoInputNumkey, original.needAutoInputNumkey);
    EXPECT_EQ(result.consumeKeyEvents, original.consumeKeyEvents);
}

// CursorInfoToInner / InnerToCursorInfo RoundTrip
HWTEST_F(InputMethodToolsTest, CursorInfo_RoundTrip, TestSize.Level0)
{
    IMSA_HILOGI("CursorInfo_RoundTrip begin");
    CursorInfo original;
    original.left = 10.5;
    original.top = 20.5;
    original.width = 300.0;
    original.height = 400.0;
    original.displayId = 999;

    auto inner = InputMethodTools::GetInstance().CursorInfoToInner(original);
    auto result = InputMethodTools::GetInstance().InnerToCursorInfo(inner);
    EXPECT_EQ(result, original);
}

// TextSelectionToInner / InnerToSelection RoundTrip
HWTEST_F(InputMethodToolsTest, TextSelection_RoundTrip, TestSize.Level0)
{
    IMSA_HILOGI("TextSelection_RoundTrip begin");
    TextSelection original;
    original.oldBegin = 1;
    original.oldEnd = 5;
    original.newBegin = 2;
    original.newEnd = 8;

    auto inner = InputMethodTools::GetInstance().TextSelectionToInner(original);
    auto result = InputMethodTools::GetInstance().InnerToSelection(inner);
    EXPECT_EQ(result.oldBegin, original.oldBegin);
    EXPECT_EQ(result.oldEnd, original.oldEnd);
    EXPECT_EQ(result.newBegin, original.newBegin);
    EXPECT_EQ(result.newEnd, original.newEnd);
}

// TextTotalConfigToInner / InnerToTextTotalConfig RoundTrip
HWTEST_F(InputMethodToolsTest, TextTotalConfig_RoundTrip, TestSize.Level0)
{
    IMSA_HILOGI("TextTotalConfig_RoundTrip begin");
    TextTotalConfig original;
    original.inputAttribute.inputPattern = 1;
    original.inputAttribute.enterKeyType = 2;
    original.cursorInfo.left = 10.0;
    original.cursorInfo.top = 20.0;
    original.textSelection.oldBegin = 5;
    original.textSelection.newEnd = 10;
    original.windowId = 50;
    original.positionY = 1.5;
    original.height = 2.5;
    original.privateCommand["cmd"] = std::string("val");
    original.requestKeyboardReason = RequestKeyboardReason::TOUCH;
    original.isSimpleKeyboardEnabled = true;

    auto inner = InputMethodTools::GetInstance().TextTotalConfigToInner(original);
    auto result = InputMethodTools::GetInstance().InnerToTextTotalConfig(inner);
    EXPECT_EQ(result.inputAttribute.inputPattern, original.inputAttribute.inputPattern);
    EXPECT_EQ(result.inputAttribute.enterKeyType, original.inputAttribute.enterKeyType);
    EXPECT_EQ(result.cursorInfo.left, original.cursorInfo.left);
    EXPECT_EQ(result.textSelection.oldBegin, original.textSelection.oldBegin);
    EXPECT_EQ(result.windowId, original.windowId);
    EXPECT_EQ(result.positionY, original.positionY);
    EXPECT_EQ(result.height, original.height);
    EXPECT_EQ(result.requestKeyboardReason, original.requestKeyboardReason);
    EXPECT_EQ(result.isSimpleKeyboardEnabled, original.isSimpleKeyboardEnabled);
}

// InputClientInfoToInner / InnerToInputClientInfo RoundTrip
HWTEST_F(InputMethodToolsTest, InputClientInfo_RoundTrip, TestSize.Level0)
{
    IMSA_HILOGI("InputClientInfo_RoundTrip begin");
    InputClientInfo original;
    original.pid = 1234;
    original.uid = 5678;
    original.userID = 100;
    original.isShowKeyboard = true;
    original.eventFlag = 0x03;
    original.attribute.inputPattern = 5;
    original.state = ClientState::ACTIVE;
    original.isNotifyInputStart = false;
    original.isStylusActivation = true;
    original.needHide = true;
    original.uiExtensionTokenId = 42;
    original.type = ClientType::JS;
    original.name = "test_client";

    auto inner = InputMethodTools::GetInstance().InputClientInfoToInner(original);
    auto result = InputMethodTools::GetInstance().InnerToInputClientInfo(inner);
    EXPECT_EQ(result.pid, original.pid);
    EXPECT_EQ(result.uid, original.uid);
    EXPECT_EQ(result.userID, original.userID);
    EXPECT_EQ(result.isShowKeyboard, original.isShowKeyboard);
    EXPECT_EQ(result.eventFlag, original.eventFlag);
    EXPECT_EQ(result.attribute.inputPattern, original.attribute.inputPattern);
    EXPECT_EQ(result.state, original.state);
    EXPECT_EQ(result.isNotifyInputStart, original.isNotifyInputStart);
    EXPECT_EQ(result.isStylusActivation, original.isStylusActivation);
    EXPECT_EQ(result.needHide, original.needHide);
    EXPECT_EQ(result.uiExtensionTokenId, original.uiExtensionTokenId);
    EXPECT_EQ(result.type, original.type);
    EXPECT_EQ(result.name, original.name);
}

// InnerToPanelStatusInfo
HWTEST_F(InputMethodToolsTest, InnerToPanelStatusInfo_001, TestSize.Level0)
{
    IMSA_HILOGI("InnerToPanelStatusInfo_001 begin");
    PanelStatusInfoInner inner;
    inner.panelInfo.panelType = PanelType::SOFT_KEYBOARD;
    inner.panelInfo.panelFlag = PanelFlag::FLG_FIXED;
    inner.inputType = InputType::CAMERA_INPUT;
    inner.visible = true;
    inner.trigger = Trigger::IMF;
    inner.sessionId = 5;
    inner.clientSessionId = 10;

    auto result = InputMethodTools::GetInstance().InnerToPanelStatusInfo(inner);
    EXPECT_EQ(result.panelInfo.panelType, PanelType::SOFT_KEYBOARD);
    EXPECT_EQ(result.panelInfo.panelFlag, PanelFlag::FLG_FIXED);
    EXPECT_EQ(result.inputType, InputType::CAMERA_INPUT);
    EXPECT_TRUE(result.visible);
    EXPECT_EQ(result.trigger, Trigger::IMF);
    EXPECT_EQ(result.sessionId, 5u);
    EXPECT_EQ(result.clientSessionId, 10);
}

// GetInstance returns the same singleton
HWTEST_F(InputMethodToolsTest, GetInstance_Singleton, TestSize.Level0)
{
    IMSA_HILOGI("GetInstance_Singleton begin");
    auto &inst1 = InputMethodTools::GetInstance();
    auto &inst2 = InputMethodTools::GetInstance();
    EXPECT_EQ(&inst1, &inst2);
}

// PanelStatusInfoToInner copies keyboardType
HWTEST_F(InputMethodToolsTest, PanelStatusInfoToInner_KeyboardType_001, TestSize.Level0)
{
    IMSA_HILOGI("PanelStatusInfoToInner_KeyboardType_001 begin");
    PanelStatusInfo info;
    info.keyboardType = KeyboardType::TYPE_CUSTOM;
    info.panelInfo.panelType = PanelType::SOFT_KEYBOARD;
    info.panelInfo.panelFlag = PanelFlag::FLG_FIXED;
    info.inputType = InputType::CAMERA_INPUT;
    info.visible = true;
    info.trigger = Trigger::IMF;
    info.sessionId = 5;
    info.clientSessionId = 10;

    auto result = InputMethodTools::GetInstance().PanelStatusInfoToInner(info);
    EXPECT_EQ(result.keyboardType, KeyboardType::TYPE_CUSTOM);
    EXPECT_EQ(result.panelInfo.panelType, PanelType::SOFT_KEYBOARD);
    EXPECT_EQ(result.panelInfo.panelFlag, PanelFlag::FLG_FIXED);
    EXPECT_EQ(result.inputType, InputType::CAMERA_INPUT);
    EXPECT_TRUE(result.visible);
    EXPECT_EQ(result.trigger, Trigger::IMF);
    EXPECT_EQ(result.sessionId, 5u);
    EXPECT_EQ(result.clientSessionId, 10);
}

// InnerToPanelStatusInfo copies keyboardType
HWTEST_F(InputMethodToolsTest, InnerToPanelStatusInfo_KeyboardType_001, TestSize.Level0)
{
    IMSA_HILOGI("InnerToPanelStatusInfo_KeyboardType_001 begin");
    PanelStatusInfoInner inner;
    inner.keyboardType = KeyboardType::TYPE_CUSTOM;
    inner.panelInfo.panelType = PanelType::SOFT_KEYBOARD;
    inner.panelInfo.panelFlag = PanelFlag::FLG_FIXED;
    inner.inputType = InputType::CAMERA_INPUT;
    inner.visible = true;
    inner.trigger = Trigger::IMF;
    inner.sessionId = 5;
    inner.clientSessionId = 10;

    auto result = InputMethodTools::GetInstance().InnerToPanelStatusInfo(inner);
    EXPECT_EQ(result.keyboardType, KeyboardType::TYPE_CUSTOM);
    EXPECT_EQ(result.panelInfo.panelType, PanelType::SOFT_KEYBOARD);
    EXPECT_EQ(result.panelInfo.panelFlag, PanelFlag::FLG_FIXED);
    EXPECT_EQ(result.inputType, InputType::CAMERA_INPUT);
    EXPECT_TRUE(result.visible);
    EXPECT_EQ(result.trigger, Trigger::IMF);
    EXPECT_EQ(result.sessionId, 5u);
    EXPECT_EQ(result.clientSessionId, 10);
}

// PanelStatusInfo round-trip with keyboardType
HWTEST_F(InputMethodToolsTest, PanelStatusInfo_KeyboardType_RoundTrip, TestSize.Level0)
{
    IMSA_HILOGI("PanelStatusInfo_KeyboardType_RoundTrip begin");
    PanelStatusInfo original;
    original.keyboardType = KeyboardType::TYPE_CUSTOM;
    original.panelInfo.panelType = PanelType::SOFT_KEYBOARD;
    original.panelInfo.panelFlag = PanelFlag::FLG_FIXED;
    original.inputType = InputType::CAMERA_INPUT;
    original.visible = true;
    original.trigger = Trigger::IMF;
    original.sessionId = 5;
    original.clientSessionId = 10;

    auto inner = InputMethodTools::GetInstance().PanelStatusInfoToInner(original);
    EXPECT_EQ(inner.keyboardType, KeyboardType::TYPE_CUSTOM);
    auto result = InputMethodTools::GetInstance().InnerToPanelStatusInfo(inner);
    EXPECT_EQ(result.keyboardType, KeyboardType::TYPE_CUSTOM);
    EXPECT_EQ(result.panelInfo.panelType, PanelType::SOFT_KEYBOARD);
    EXPECT_EQ(result.panelInfo.panelFlag, PanelFlag::FLG_FIXED);
    EXPECT_EQ(result.inputType, InputType::CAMERA_INPUT);
    EXPECT_TRUE(result.visible);
    EXPECT_EQ(result.trigger, Trigger::IMF);
    EXPECT_EQ(result.sessionId, 5u);
    EXPECT_EQ(result.clientSessionId, 10);
}

// PanelStatusInfoToInner with TYPE_PANEL keyboardType
HWTEST_F(InputMethodToolsTest, PanelStatusInfoToInner_KeyboardType_002, TestSize.Level0)
{
    IMSA_HILOGI("PanelStatusInfoToInner_KeyboardType_002 begin");
    PanelStatusInfo info;
    info.keyboardType = KeyboardType::TYPE_PANEL;
    info.panelInfo.panelType = PanelType::SOFT_KEYBOARD;
    info.panelInfo.panelFlag = PanelFlag::FLG_FIXED;
    info.inputType = InputType::NONE;
    info.visible = false;
    info.trigger = Trigger::END;
    info.sessionId = 0;
    info.clientSessionId = -1;

    auto result = InputMethodTools::GetInstance().PanelStatusInfoToInner(info);
    EXPECT_EQ(result.keyboardType, KeyboardType::TYPE_PANEL);
}

// PanelStatusInfoInner ReadFromParcel with valid keyboardType (TYPE_CUSTOM)
HWTEST_F(InputMethodToolsTest, PanelStatusInfoInner_ReadFromParcel_ValidKeyboardType, TestSize.Level0)
{
    IMSA_HILOGI("PanelStatusInfoInner_ReadFromParcel_ValidKeyboardType begin");
    MessageParcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(KeyboardType::TYPE_CUSTOM));
    PanelInfo panelInfo;
    panelInfo.panelType = PanelType::SOFT_KEYBOARD;
    panelInfo.panelFlag = PanelFlag::FLG_FIXED;
    parcel.WriteParcelable(&panelInfo);
    parcel.WriteInt32(static_cast<int32_t>(InputType::NONE));
    parcel.WriteBool(true);
    parcel.WriteInt32(static_cast<int32_t>(Trigger::IMF));
    parcel.WriteUint32(5);
    parcel.WriteInt32(10);
    parcel.RewindRead(0);

    PanelStatusInfoInner inner;
    EXPECT_TRUE(inner.ReadFromParcel(parcel));
    EXPECT_EQ(inner.keyboardType, KeyboardType::TYPE_CUSTOM);
}

// PanelStatusInfoInner ReadFromParcel with invalid keyboardType (negative)
HWTEST_F(InputMethodToolsTest, PanelStatusInfoInner_ReadFromParcel_InvalidKeyboardType, TestSize.Level0)
{
    IMSA_HILOGI("PanelStatusInfoInner_ReadFromParcel_InvalidKeyboardType begin");
    MessageParcel parcel;
    parcel.WriteInt32(-1);
    parcel.RewindRead(0);

    PanelStatusInfoInner inner;
    EXPECT_FALSE(inner.ReadFromParcel(parcel));
}

// PanelStatusInfoInner ReadFromParcel with keyboardType out of range (too large)
HWTEST_F(InputMethodToolsTest, PanelStatusInfoInner_ReadFromParcel_KeyboardTypeTooLarge, TestSize.Level0)
{
    IMSA_HILOGI("PanelStatusInfoInner_ReadFromParcel_KeyboardTypeTooLarge begin");
    MessageParcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(KeyboardType::TYPE_END) + 1);
    parcel.RewindRead(0);

    PanelStatusInfoInner inner;
    EXPECT_FALSE(inner.ReadFromParcel(parcel));
}

// PanelStatusInfoInner Marshalling/Unmarshalling round-trip with keyboardType
HWTEST_F(InputMethodToolsTest, PanelStatusInfoInner_KeyboardType_ParcelRoundTrip, TestSize.Level0)
{
    IMSA_HILOGI("PanelStatusInfoInner_KeyboardType_ParcelRoundTrip begin");
    PanelStatusInfoInner original;
    original.keyboardType = KeyboardType::TYPE_CUSTOM;
    original.panelInfo.panelType = PanelType::SOFT_KEYBOARD;
    original.panelInfo.panelFlag = PanelFlag::FLG_FIXED;
    original.inputType = InputType::CAMERA_INPUT;
    original.visible = true;
    original.trigger = Trigger::IMF;
    original.sessionId = 5;
    original.clientSessionId = 10;

    MessageParcel parcel;
    EXPECT_TRUE(original.Marshalling(parcel));
    parcel.RewindRead(0);

    PanelStatusInfoInner *result = PanelStatusInfoInner::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->keyboardType, KeyboardType::TYPE_CUSTOM);
    EXPECT_EQ(result->panelInfo.panelType, PanelType::SOFT_KEYBOARD);
    EXPECT_EQ(result->panelInfo.panelFlag, PanelFlag::FLG_FIXED);
    EXPECT_EQ(result->inputType, InputType::CAMERA_INPUT);
    EXPECT_TRUE(result->visible);
    EXPECT_EQ(result->trigger, Trigger::IMF);
    EXPECT_EQ(result->sessionId, 5u);
    EXPECT_EQ(result->clientSessionId, 10);
    delete result;
}
} // namespace MiscServices
} // namespace OHOS
