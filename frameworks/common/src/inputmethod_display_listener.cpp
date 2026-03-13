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
#include "inputmethod_display_listener.h"

#include "configuration_utils.h"
#include "input_method_ability.h"
#include "parameters.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::AbilityRuntime;
const std::string FOLD_SCREEN_TYPE = OHOS::system::GetParameter("const.window.foldscreen.type", "0,0,0,0");
constexpr const char *EXTEND_FOLD_TYPE = "4";

void InputMethodDisplayAttributeListener::OnAttributeChange(Rosen::DisplayId displayId,
    const std::vector<std::string>& attributes)
{
    IMSA_HILOGD("OnAttributeChange start.");
    OnChange(displayId);
    CheckNeedAdjustKeyboard(displayId);
}

void InputMethodDisplayAttributeListener::InitDisplayListener()
{
    auto foldStatus = Rosen::DisplayManager::GetInstance().GetFoldStatus();
    auto displayPtr = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    if (displayPtr == nullptr) {
        IMSA_HILOGE("displayPtr is null");
        return;
    }
    displayAttribute_.SetCacheDisplay(
        displayPtr->GetWidth(), displayPtr->GetHeight(), displayPtr->GetRotation(), foldStatus);
    configurationUpdate_ = [&](Rosen::DisplayId displayId) {
        if (context_ == nullptr) {
            IMSA_HILOGE("context is invalid!");
            return;
        }

        auto contextConfig = context_->GetConfiguration();
        if (contextConfig == nullptr) {
            IMSA_HILOGE("configuration is invalid!");
            return;
        }

        bool isConfigChanged = false;
        auto configUtils = std::make_shared<ConfigurationUtils>();
        configUtils->UpdateDisplayConfig(displayId, contextConfig, context_->GetResourceManager(), isConfigChanged);
        IMSA_HILOGD("updateConfigration, isConfigChanged: %{public}d, Config after update: %{public}s.",
            isConfigChanged, contextConfig->GetName().c_str());
    };
    InputMethodAbility::GetInstance().SetConfigurationUpdate(configurationUpdate_);
}

void InputMethodDisplayAttributeListener::CheckNeedAdjustKeyboard(Rosen::DisplayId displayId)
{
    if (FOLD_SCREEN_TYPE.empty() || FOLD_SCREEN_TYPE[0] != *EXTEND_FOLD_TYPE) {
        IMSA_HILOGD("The current device is a non-foldable device.");
        return;
    }
    auto displayPtr = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    if (displayPtr == nullptr) {
        return;
    }
    auto defaultDisplayId = displayPtr->GetId();
    if (displayId != defaultDisplayId) {
        return;
    }
    auto foldStatus = Rosen::DisplayManager::GetInstance().GetFoldStatus();
    auto displayInfo = displayPtr->GetDisplayInfo();
    if (displayInfo == nullptr) {
        IMSA_HILOGE("displayInfo is nullptr");
        return;
    }
    auto width = displayInfo->GetWidth();
    auto height = displayInfo->GetHeight();
    auto rotation = displayInfo->GetRotation();
    if (!displayAttribute_.IsEmpty()) {
        if ((displayAttribute_.displayWidth != width ||
            displayAttribute_.displayHeight != height) &&
            displayAttribute_.displayFoldStatus == foldStatus &&
            displayAttribute_.displayRotation == rotation) {
            IMSA_HILOGI("display width: %{public}d, height: %{public}d, rotation: %{public}d, foldStatus: %{public}d",
                width, height, rotation, foldStatus);
            InputMethodAbility::GetInstance().AdjustKeyboard();
        }
    }
    displayAttribute_.SetCacheDisplay(width, height, rotation, foldStatus);
}

void InputMethodDisplayAttributeListener::OnChange(Rosen::DisplayId displayId)
{
    IMSA_HILOGD("displayId: %{public}" PRIu64 "", displayId);
    auto clientInfo = InputMethodAbility::GetInstance().GetBindClientInfo();
    if (clientInfo.name.empty()) {
        IMSA_HILOGD("not bound");
        return;
    }
    auto callingDisplayId = InputMethodAbility::GetInstance().GetInputAttribute().callingDisplayId;
    if (displayId != callingDisplayId) {
        IMSA_HILOGE("displayId is not equal the callingDisplayId,  callingDisplayId: %{public}" PRIu64 "",
            callingDisplayId);
        return;
    }
    if (configurationUpdate_ != nullptr) {
        configurationUpdate_(displayId);
    }
}
} // namespace MiscServices
} // namespace OHOS
