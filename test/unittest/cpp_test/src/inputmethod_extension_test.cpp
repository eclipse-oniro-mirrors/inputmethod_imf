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

#include "inputmethod_extension.h"

#include <gtest/gtest.h>

#include "global.h"
#include "runtime.h"
#include "cj_inputmethod_extension_loader.h"

#undef LOG_TAG
#define LOG_TAG "ImeExtTest"

using namespace testing::ext;
namespace OHOS {
namespace AbilityRuntime {

class InputMethodExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void InputMethodExtensionTest::SetUpTestCase(void)
{
    IMSA_HILOGI("InputMethodExtensionTest::SetUpTestCase");
}

void InputMethodExtensionTest::TearDownTestCase(void)
{
    IMSA_HILOGI("InputMethodExtensionTest::TearDownTestCase");
}

void InputMethodExtensionTest::SetUp(void)
{
    IMSA_HILOGI("InputMethodExtensionTest::SetUp");
}

void InputMethodExtensionTest::TearDown(void)
{
    IMSA_HILOGI("InputMethodExtensionTest::TearDown");
}

/**
 * @tc.name: InputMethodExtensionTest_Create001
 * @tc.desc: Verify Create with nullptr runtime returns default InputMethodExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionTest, InputMethodExtensionTest_Create001, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionTest_Create001 start.");
    std::unique_ptr<Runtime> runtime = nullptr;
    auto *ext = InputMethodExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    delete ext;
}

/**
 * @tc.name: InputMethodExtensionTest_Create002
 * @tc.desc: Verify Create with CJ runtime returns CjInputMethodExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMethodExtensionTest, InputMethodExtensionTest_Create002, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodExtensionTest_Create002 start.");
    Runtime::Options opts;
    auto runtime = Runtime::Create(opts);
    ASSERT_NE(runtime, nullptr);
    // The default Runtime language may not be CJ.Test the CJ branch directly.
    // CreateCjInputMethodExtension returns a new CjInputMethodExtension
    auto *ext = CreateCjInputMethodExtension();
    ASSERT_NE(ext, nullptr);
    delete ext;
}

} //namespace AbilityRuntime
} //namespace OHOS