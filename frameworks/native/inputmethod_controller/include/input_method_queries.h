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
#ifndef INPUT_METHOD_QUERIES_H
#define INPUT_METHOD_QUERIES_H

#include "input_method_controller.h"

namespace OHOS {
namespace MiscServices {
// Bindings use this internal status path without changing the legacy getters.
class InputMethodQueries {
public:
    IMF_API static int32_t GetCurrent(InputMethodController &controller, Property &property, int32_t userId);
    IMF_API static int32_t GetCurrentSubtype(InputMethodController &controller, SubProperty &property, int32_t userId);
};
} // namespace MiscServices
} // namespace OHOS
#endif // INPUT_METHOD_QUERIES_H
