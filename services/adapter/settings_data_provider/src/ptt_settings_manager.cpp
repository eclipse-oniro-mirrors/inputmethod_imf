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

#include "ptt_settings_manager.h"

#include <string>

#include "global.h"
#include "settings_data_utils.h"

namespace OHOS {
namespace MiscServices {
namespace {
constexpr const char *PTT_SETTING_KEY = "settings.keyboard.push_talk_switch";
}

bool PttSettingsManager::IsEnabled(int32_t userId)
{
    if (userId < 0) {
        IMSA_HILOGE("invalid PTT settings query userId: %{public}d.", userId);
        return false;
    }

    std::string value;
    auto ret = SettingsDataUtils::GetInstance().GetStringValue(SETTING_URI_PROXY, PTT_SETTING_KEY, value);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGW("get PTT setting failed, userId: %{public}d, ret: %{public}d.", userId, ret);
        return false;
    }

    return value == "true";
}
} // namespace MiscServices
} // namespace OHOS
