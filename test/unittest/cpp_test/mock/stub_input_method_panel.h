/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

// This is a minimal stub for input_method_panel.h to avoid pulling in
// Rosen window manager types that are not available in the UT build environment.
// It provides just enough for InputMethodAbility to compile without the full panel implementation.

#ifndef TEST_UNITTEST_CPP_TEST_MOCK_STUB_INPUT_METHOD_PANEL_H
#define TEST_UNITTEST_CPP_TEST_MOCK_STUB_INPUT_METHOD_PANEL_H

#include <cstdint>
#include <memory>
#include <string>

#include "panel_info.h"

namespace OHOS {
namespace MiscServices {

// Minimal stub of InputMethodPanel - only provides what the compiled sources need
class InputMethodPanel {
public:
    static constexpr uint32_t INVALID_WINDOW_ID = 0;
    uint32_t windowId_ = INVALID_WINDOW_ID;

    InputMethodPanel() = default;
    ~InputMethodPanel() = default;
};

} // namespace MiscServices
} // namespace OHOS

#endif // TEST_UNITTEST_CPP_TEST_MOCK_STUB_INPUT_METHOD_PANEL_H
