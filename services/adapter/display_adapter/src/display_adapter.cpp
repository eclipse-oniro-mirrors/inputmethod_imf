/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "display_adapter.h"

#include <cinttypes>

#include "display_manager_lite.h"
#include "global.h"
#include "ime_info_inquirer.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::Rosen;
// LCOV_EXCL_START
std::string DisplayAdapter::GetDisplayName(uint64_t displayId)
{
    auto displayInfo = GetDisplayInfo(displayId);
    if (displayInfo == nullptr) {
        IMSA_HILOGE("displayInfo is null!");
        return "";
    }
    auto name = displayInfo->GetName();
    IMSA_HILOGD("display: %{public}" PRIu64 " name is %{public}s.", displayId, name.c_str());
    return name;
}

uint64_t DisplayAdapter::GetDefaultDisplayId()
{
    return DisplayManagerLite::GetInstance().GetDefaultDisplayId();
}
// LCOV_EXCL_STOP
bool DisplayAdapter::IsImeShowable(uint64_t displayId)
{
    auto displayInfo = GetDisplayInfo(displayId);
    if (displayInfo == nullptr) {
        IMSA_HILOGE("displayInfo is null!");
        return true;
    }
    auto isImeShowable = displayInfo->GetSupportsInput();
    IMSA_HILOGD("display: %{public}" PRIu64 " is %{public}u.", displayId, isImeShowable);
    return isImeShowable;
}

bool DisplayAdapter::IsFocusable(uint64_t displayId)
{
    auto displayInfo = GetDisplayInfo(displayId);
    if (displayInfo == nullptr) {
        IMSA_HILOGE("displayInfo is null!");
        return true;
    }
    auto isFocusable = displayInfo->GetSupportsFocus();
    IMSA_HILOGD("display: %{public}" PRIu64 " is %{public}u.", displayId, isFocusable);
    return isFocusable;
}
// LCOV_EXCL_START
uint64_t DisplayAdapter::GetFinalDisplayId(uint64_t displayId)
{
    IMSA_HILOGD("run in, display: %{public}" PRIu64 ".", displayId);
    if (!IsRestrictedMainDisplayId(displayId)) {
        return displayId;
    }
    return DEFAULT_DISPLAY_ID;
}

bool DisplayAdapter::IsRestrictedMainDisplayId(uint64_t displayId)
{
    IMSA_HILOGD("run in, display: %{public}" PRIu64 ".", displayId);
    if (displayId == DEFAULT_DISPLAY_ID) {
        return false;
    }
    if (ImeInfoInquirer::GetInstance().IsRestrictedMainDisplayId(displayId)) {
        IMSA_HILOGD("display: %{public}" PRIu64 " not support show ime.", displayId);
        return true;
    }
    if (IsImeShowable(displayId)) {
        return false;
    }
    IMSA_HILOGD("display:%{public}" PRIu64 " not support show ime.", displayId);
    return true;
}
// LCOV_EXCL_STOP
sptr<DisplayInfo> DisplayAdapter::GetDisplayInfo(uint64_t displayId)
{
    auto display = DisplayManagerLite::GetInstance().GetDisplayById(displayId);
    if (display == nullptr) {
        IMSA_HILOGE("display is null!");
        return nullptr;
    }
    auto displayInfo = display->GetDisplayInfo();
    if (displayInfo == nullptr) {
        IMSA_HILOGE("displayInfo is null!");
        return nullptr;
    }
    return displayInfo;
}
} // namespace MiscServices
} // namespace OHOS