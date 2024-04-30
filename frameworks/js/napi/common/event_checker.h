/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_PARAM_CHECK_H
#define OHOS_PARAM_CHECK_H
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace OHOS {
namespace MiscServices {
enum class EventSubscribeModule : uint32_t {
    INPUT_METHOD_CONTROLLER = 0,
    INPUT_METHOD_SETTING,
    INPUT_METHOD_ABILITY,
    KEYBOARD_DELEGATE,
    KEYBOARD_PANEL_MANAGER,
    PANEL,
};
class EventChecker {
public:
    static bool IsValidEventType(EventSubscribeModule module, const std::string &type);

private:
    static const std::unordered_map<EventSubscribeModule, std::unordered_set<std::string>> EVENT_TYPES;
};
} // namespace MiscServices
} // namespace OHOS
#endif // OHOS_PARAM_CHECK_H
