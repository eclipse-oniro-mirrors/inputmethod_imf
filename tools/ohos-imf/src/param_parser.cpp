/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "param_parser.h"

#include <algorithm>
namespace OHOS {
namespace MiscServices {
std::string ParamParse::GetParam(const std::vector<std::string> &argList, const std::string &key)
{
    auto keyIter = std::find_if(argList.cbegin(), argList.cend(), [&key](const auto &arg) { return arg == key; });
    if (keyIter == argList.cend()) {
        return "";
    }
    auto valIter = std::next(keyIter);
    if (valIter == argList.cend()) {
        return "";
    }
    return *valIter;
}
} // namespace MiscServices
} // namespace OHOS