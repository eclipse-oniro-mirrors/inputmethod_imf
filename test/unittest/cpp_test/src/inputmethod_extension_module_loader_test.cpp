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

#include "inputmethod_extension_module_loader.h"

#include <gtest/gtest.h>

#include "global.h"
#include "runtime.h"

#undef LOG_TAG
#define LOG_TAG "ImeExtLoaderTest"

// Forward declaration of the exported symbol from inputmethod_extension_module
extern "C" void *OHOS_EXTENSION_GetExtensionModule();

using namespace testing::ext;
namespace OHOS {
namespace AbilityRuntime {

class InputmethodExtensionModuleLoaderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void InputmethodExtensionModuleLoaderTest::SetUpTestCase(void)
{
    IMSA_HILOGI("InputmethodExtensionModuleLoaderTest::SetUpTestCase");
}

void InputmethodExtensionModuleLoaderTest::TearDownTestCase(void)
{
    IMSA_HILOGI("InputmethodExtensionModuleLoaderTest::TearDownTestCase");
}

void InputmethodExtensionModuleLoaderTest::SetUp(void)
{
    IMSA_HILOGI("InputmethodExtensionModuleLoaderTest::SetUp");
}

void InputmethodExtensionModuleLoaderTest::TearDown(void)
{
    IMSA_HILOGI("InputmethodExtensionModuleLoaderTest::TearDown");
}

/**
 * @tc.name: InputmethodExtensionModuleLoaderTest_GetParams001
 * @tc.desc: Verify GetParams returns correct map with type and name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputmethodExtensionModuleLoaderTest, InputmethodExtensionModuleLoaderTest_GetParams001, TestSize.Level0)
{
    IMSA_HILOGI("InputmethodExtensionModuleLoaderTest_GetParams001 start.");
    auto &loader = InputMethodExtensionModuleLoader::GetInstance();
    auto params = loader.GetParams();
    EXPECT_EQ(params.size(), 2u);
    EXPECT_EQ(params["type"], "2");
    EXPECT_EQ(params["name"], "InputMethodExtensionAbility");
}

/**
 * @tc.name: InputmethodExtensionModuleLoaderTest_Create001
 * @tc.desc: Verify Create with nullptr runtime returns valid extension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputmethodExtensionModuleLoaderTest, InputmethodExtensionModuleLoaderTest_Create001, TestSize.Level0)
{
    IMSA_HILOGI("InputmethodExtensionModuleLoaderTest_Create001 start.");
    auto &loader = InputMethodExtensionModuleLoader::GetInstance();
    std::unique_ptr<Runtime> runtime = nullptr;
    auto *ext = loader.Create(runtime);
    ASSERT_NE(ext, nullptr);
    delete ext;
}

/**
 * @tc.name: InputmethodExtensionModuleLoaderTest_GetExtensionModule001
 * @tc.desc: Verify OHOS_EXTENSION_GetExtensionModule returns valid singleton address
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputmethodExtensionModuleLoaderTest,
    InputmethodExtensionModuleLoaderTest_GetExtensionModule001, TestSize.Level0)
{
    IMSA_HILOGI("InputmethodExtensionModuleLoaderTest_GetExtensionModule001 start.");
    void *module = OHOS_EXTENSION_GetExtensionModule();
    ASSERT_NE(module, nullptr);
    auto loader = static_cast<InputMethodExtensionModuleLoader *>(module);
    auto params = loader->GetParams();
    EXPECT_EQ(params["type"], "2");
}

} //namespace AbilityRuntime
} //namespace OHOS