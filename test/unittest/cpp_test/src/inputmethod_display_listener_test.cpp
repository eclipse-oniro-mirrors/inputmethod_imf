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
#include "inputmethod_display_listener.h"
#include "input_method_ability.h"
#undef private
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include "tdd_util.h"
#include "parameters.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
const std::string FOLD_SCREEN_TYPE = OHOS::system::GetParameter("const.window.foldscreen.type", "0,0,0,0");
constexpr const char *EXTEND_FOLD_TYPE = "4";
class InputMethodDisplayAttributeListenerTest  : public testing::Test {
public:
    static sptr<InputMethodDisplayAttributeListener> displayListener_;
    static InputMethodAbility &inputMethodAbility_;

    static void SetUpTestCase(void)
    {
        IMSA_HILOGI("InputMethodDisplayAttributeListenerTest::SetUpTestCase");
    }
    static void TearDownTestCase(void)
    {
        IMSA_HILOGI("InputMethodDisplayAttributeListenerTest::TearDownTestCase");
    }
    void SetUp()
    {
        IMSA_HILOGI("InputMethodDisplayAttributeListenerTest::SetUp");
    }
    void TearDown()
    {
        IMSA_HILOGI("InputMethodDisplayAttributeListenerTest::TearDown");
    }
};

sptr<InputMethodDisplayAttributeListener> InputMethodDisplayAttributeListenerTest::displayListener_ =
    new InputMethodDisplayAttributeListener(nullptr);
InputMethodAbility &InputMethodDisplayAttributeListenerTest::inputMethodAbility_ = InputMethodAbility::GetInstance();

/**
 * @tc.name: testInitDisplayListener
 * @tc.desc: testInitDisplayListener
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodDisplayAttributeListenerTest, testInitDisplayListener, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodDisplayAttributeListenerTest::testInitDisplayListener");
    displayListener_->displayAttribute_.SetCacheDisplay(0, 0, Rosen::Rotation::ROTATION_0, Rosen::FoldStatus::UNKNOWN);
    EXPECT_EQ(displayListener_->displayAttribute_.displayWidth, 0);
    EXPECT_EQ(displayListener_->displayAttribute_.displayHeight, 0);
    displayListener_->InitDisplayListener();
    EXPECT_NE(displayListener_->displayAttribute_.displayWidth, 0);
    EXPECT_NE(displayListener_->displayAttribute_.displayHeight, 0);
    EXPECT_NE(displayListener_->configurationUpdate_, nullptr);
}

/**
 * @tc.name: testOnChange
 * @tc.desc: testOnChange
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodDisplayAttributeListenerTest, testOnChange, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodDisplayAttributeListenerTest::testOnChange START");
    bool isConfigurationUpdate = false;
    displayListener_->configurationUpdate_ = [&](Rosen::DisplayId displayId) {
        IMSA_HILOGI("InputMethodAbilityTest configrationUpdate");
        isConfigurationUpdate = true;
    };
    EXPECT_NE(displayListener_->configurationUpdate_, nullptr);

    std::vector<std::string> attributes;
    displayListener_->OnAttributeChange(0, attributes);
    EXPECT_EQ(isConfigurationUpdate, false);

    InputClientInfo clientInfo;
    clientInfo.name = "client";
    inputMethodAbility_.StartInput(clientInfo, false);
    InputAttribute inputAttribute;
    inputAttribute.callingDisplayId = 0;
    inputMethodAbility_.SetInputAttribute(inputAttribute);
    displayListener_->OnAttributeChange(0, attributes);
    EXPECT_EQ(isConfigurationUpdate, true);
    
    isConfigurationUpdate = false;
    displayListener_->OnChange(0);
    EXPECT_EQ(isConfigurationUpdate, true);

    isConfigurationUpdate = false;
    displayListener_->OnChange(1000);
    EXPECT_EQ(isConfigurationUpdate, false);
}


/**
 * @tc.name: testCheckNeedAdjustKeyboard
 * @tc.desc: testCheckNeedAdjustKeyboard
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodDisplayAttributeListenerTest, testCheckNeedAdjustKeyboard, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodDisplayAttributeListenerTest::testCheckNeedAdjustKeyboard START");
    displayListener_->displayAttribute_.SetCacheDisplay(
        10, 10, Rosen::Rotation::ROTATION_0, Rosen::FoldStatus::UNKNOWN);
    displayListener_->CheckNeedAdjustKeyboard(0);
    if (FOLD_SCREEN_TYPE.empty() || FOLD_SCREEN_TYPE[0] != *EXTEND_FOLD_TYPE) {
        EXPECT_EQ(displayListener_->displayAttribute_.displayWidth, 10);
        EXPECT_EQ(displayListener_->displayAttribute_.displayHeight, 10);
    } else {
        EXPECT_NE(displayListener_->displayAttribute_.displayWidth, 10);
        EXPECT_NE(displayListener_->displayAttribute_.displayHeight, 10);
    }
}


/**
 * @tc.name: testSetConfigurationUpdate
 * @tc.desc: testSetConfigurationUpdate
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodDisplayAttributeListenerTest, testSetConfigurationUpdate, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodDisplayAttributeListenerTest testSetConfigurationUpdate START");
    bool isConfigurationUpdate = false;
    std::function<void(Rosen::DisplayId displayId)> configurationUpdate = [&](Rosen::DisplayId displayId) {
        IMSA_HILOGI("InputMethodDisplayAttributeListenerTest configrationUpdate");
        isConfigurationUpdate = true;
    };
    inputMethodAbility_.SetConfigurationUpdate(configurationUpdate);
    EXPECT_NE(inputMethodAbility_.configurationUpdate_, nullptr);
    inputMethodAbility_.ConfigurationUpdate(0);
    EXPECT_TRUE(isConfigurationUpdate);
}
} // namespace MiscServices
} // namespace OHOS