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

#ifndef OHOS_INPUTMETHOD_DISPLAY_LISTENER_H
#define OHOS_INPUTMETHOD_DISPLAY_LISTENER_H

#include "display_manager.h"
#include "inputmethod_extension.h"
#include "inputmethod_extension_context.h"
#include "js_runtime.h"
#include <mutex>

namespace OHOS {
namespace MiscServices {
class InputMethodDisplayAttributeListener : public Rosen::DisplayManager::IDisplayAttributeListener {
struct DisplayAttribute {
    int32_t displayWidth = 0;
    int32_t displayHeight = 0;
    Rosen::Rotation displayRotation = Rosen::Rotation::ROTATION_0;
    Rosen::FoldStatus displayFoldStatus = Rosen::FoldStatus::UNKNOWN;
    bool IsEmpty()
    {
        return displayWidth == 0 && displayHeight == 0 && displayRotation == Rosen::Rotation::ROTATION_0 &&
            displayFoldStatus == Rosen::FoldStatus::UNKNOWN;
    };
    void SetCacheDisplay(int32_t width, int32_t height, Rosen::Rotation rotation, Rosen::FoldStatus foldStatus)
    {
        displayWidth = width;
        displayHeight = height;
        displayRotation = rotation;
        displayFoldStatus = foldStatus;
    };
};

public:
    explicit InputMethodDisplayAttributeListener(
        const std::shared_ptr<AbilityRuntime::InputMethodExtensionContext> context)
    {
        context_ = context;
        InitDisplayListener();
    }
    virtual ~InputMethodDisplayAttributeListener() {};
    void OnAttributeChange(Rosen::DisplayId displayId, const std::vector<std::string>& attributes) override;

private:
    void InitDisplayListener();
    void OnChange(Rosen::DisplayId displayId);
    void CheckNeedAdjustKeyboard(Rosen::DisplayId displayId);

    std::shared_ptr<AbilityRuntime::InputMethodExtensionContext> context_;
    DisplayAttribute displayAttribute_;
    std::function<void(Rosen::DisplayId displayId)> configurationUpdate_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // OHOS_INPUTMETHOD_DISPLAY_LISTENER_H