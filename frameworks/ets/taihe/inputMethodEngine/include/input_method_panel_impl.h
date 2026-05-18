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
#ifndef TAIHE_INPUT_METHOD_PANEL_IMPL_H
#define TAIHE_INPUT_METHOD_PANEL_IMPL_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <atomic>

#include "ani_common_engine.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "input_method_ability.h"
#include "block_queue.h"
#include "sys_panel_status.h"

namespace OHOS {
namespace MiscServices {
class PanelImpl : public std::enable_shared_from_this<PanelImpl> {
public:
    PanelImpl();
    ~PanelImpl();
    void CreatePanel(uintptr_t ctx, PanelInfo_t const& info, std::shared_ptr<InputMethodPanel> &panel);
    SystemPanelInsetsData_t GetSystemPanelCurrentInsetsAsync(int64_t id, int64_t displayId);
    void SetSystemPanelButtonColorAsync(int64_t id, FillColorData_t const& fillColor,
        BackgroundColorData_t const& backgroundColor);
    void SetShadow(double radius, ::taihe::string_view color, double offsetX, double offsetY);
    void StartMoving();
    void UpdateRegion(uintptr_t inputRegion);
    void AdjustPanelRect(PanelFlag_t flag, PanelRect_t const& rect);
    void AdjustPanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect);
    void UpdatePanelRect(PanelFlag_t flag, PanelRect_t const& rect);
    void UpdatePanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect);
    int64_t GetDisplayIdSync(int64_t id);
    ImmersiveMode_t GetImmersiveMode();
    void SetImmersiveMode(ImmersiveMode_t mode);
    void SetPrivacyMode(bool isPrivacyMode);
    void ChangeFlag(PanelFlag_t flag);
    void MoveToAsync(int64_t id, int32_t x, int32_t y);
    void ResizeAsync(int64_t id, int64_t width, int64_t height);
    void SetUiContent(int64_t id, taihe::string_view path, ani_object storage);
    void HideAsync(int64_t id);
    void ShowAsync(int64_t id);
    void SetKeepScreenOnAsync(bool isKeepScreenOn);
    void SetImmersiveEffect(ImmersiveEffect_t const& effect);
    void RegisterListener(std::string const &type, callbackTypes &&cb, uintptr_t opq);
    void UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq);
    int64_t LineUp();

private:
    bool IsPanelFlagValid(PanelFlag panelFlag, bool isEnhancedCalled);
    ImmersiveMode_t ConvertMode(ImmersiveMode mode);
    bool IsVaildImmersiveMode(ImmersiveMode mode);
    bool ParseUpdateRegionParam(std::vector<Rosen::Rect> &hotArea, uintptr_t inputRegion);
    std::shared_ptr<InputMethodPanel> inputMethodPanel_{ nullptr };
    static BlockQueue<uint32_t> jobQueue_;
    static std::atomic<uint32_t> jobId_;
    bool PrepareAdjustPanelRect(PanelFlag_t flag, PanelRect_t const& rect, LayoutParams& layoutParams);
    bool PrepareAdjustPanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect,
        EnhancedLayoutParams& enhancedLayoutParams, HotAreas& hotAreas);
    void HandleAdjustPanelRectResult(int32_t ret);
};

class IMFPanelImpl {
public:
    IMFPanelImpl(uintptr_t ctx, PanelInfo_t const& info)
        : panelImpl_(std::make_shared<PanelImpl>())
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->CreatePanel(ctx, info, value_);
    }

    int64_t GetImplPtr()
    {
        return reinterpret_cast<uintptr_t>(this);
    }

    std::shared_ptr<InputMethodPanel> GetNativePtr()
    {
        return value_;
    }

    void SetUiContentAsync(int64_t id, taihe::string_view path)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->SetUiContent(id, path, nullptr);
    }

    void SetUiContentSync(int64_t id, taihe::string_view path)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->SetUiContent(id, path, nullptr);
    }

    void SetUiContentStorage(int64_t id, ::taihe::string_view path, uintptr_t storage)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        ani_object obj = reinterpret_cast<ani_object>(storage);
        if (obj == nullptr) {
            IMSA_HILOGW("storage is nullptr");
        }
        panelImpl_->SetUiContent(id, path, obj);
    }

    void SetUiContentStorageSync(int64_t id, ::taihe::string_view path, uintptr_t storage)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        ani_object obj = reinterpret_cast<ani_object>(storage);
        if (obj == nullptr) {
            IMSA_HILOGW("storage is nullptr");
        }
        panelImpl_->SetUiContent(id, path, obj);
    }

    void ResizeAsync(int64_t id, int64_t width, int64_t height)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->ResizeAsync(id, width, height);
    }

    void MoveToAsync(int64_t id, int32_t x, int32_t y)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->MoveToAsync(id, x, y);
    }

    int64_t GetDisplayIdSync(int64_t id)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return 0;
        }
        return panelImpl_->GetDisplayIdSync(id);
    }

    void ShowAsync(int64_t id)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->ShowAsync(id);
    }

    void HideAsync(int64_t id)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->HideAsync(id);
    }

    void SetKeepScreenOnAsync(bool isKeepScreenOn)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->SetKeepScreenOnAsync(isKeepScreenOn);
    }

    SystemPanelInsetsData_t GetSystemPanelCurrentInsetsAsync(int64_t id, int64_t displayId)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return SystemPanelInsetsData_t::make_type_null();
        }
        return panelImpl_->GetSystemPanelCurrentInsetsAsync(id, displayId);
    }

    void SetSystemPanelButtonColorAsync(int64_t id, FillColorData_t const& fillColor,
        BackgroundColorData_t const& backgroundColor)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->SetSystemPanelButtonColorAsync(id, fillColor, backgroundColor);
    }

    void SetShadow(double radius, ::taihe::string_view color, double offsetX, double offsetY)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->SetShadow(radius, color, offsetX, offsetY);
    }

    void StartMoving()
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->StartMoving();
    }

    void ChangeFlag(PanelFlag_t flag)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->ChangeFlag(flag);
    }

    void SetPrivacyMode(bool isPrivacyMode)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->SetPrivacyMode(isPrivacyMode);
    }

    void AdjustPanelRect(PanelFlag_t flag, PanelRect_t const& rect)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->AdjustPanelRect(flag, rect);
    }

    void AdjustPanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->AdjustPanelRectEnhanced(flag, rect);
    }

    void UpdatePanelRect(PanelFlag_t flag, PanelRect_t const& rect)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->UpdatePanelRect(flag, rect);
    }

    void UpdatePanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->UpdatePanelRectEnhanced(flag, rect);
    }

    void UpdatePanelRectSync(PanelFlag_t flag, PanelRect_t const& rect)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->UpdatePanelRect(flag, rect);
    }

    void UpdatePanelRectEnhancedSync(PanelFlag_t flag, EnhancedPanelRect_t const& rect)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->UpdatePanelRectEnhanced(flag, rect);
    }

    void UpdateRegion(uintptr_t inputRegion)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->UpdateRegion(inputRegion);
    }

    void SetImmersiveMode(ImmersiveMode_t mode)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->SetImmersiveMode(mode);
    }

    ImmersiveMode_t GetImmersiveMode()
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return CommonConvert::ConvertMode(ImmersiveMode::NONE_IMMERSIVE);
        }
        return panelImpl_->GetImmersiveMode();
    }

    void SetImmersiveEffect(ImmersiveEffect_t const& effect)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->SetImmersiveEffect(effect);
    }

    void OnShow(taihe::callback_view<void(UndefinedType_t const&)> callback, uintptr_t opq)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->RegisterListener("show", callback, opq);
    }

    void OffShow(taihe::optional_view<uintptr_t> opq)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->UnRegisterListener("show", opq);
    }

    void OnHide(taihe::callback_view<void(UndefinedType_t const&)> callback, uintptr_t opq)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->RegisterListener("hide", callback, opq);
    }

    void OffHide(taihe::optional_view<uintptr_t> opq)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->UnRegisterListener("hide", opq);
    }

    void OnSizeUpdate(taihe::callback_view<void(uintptr_t, KeyboardArea_t const&)> callback, uintptr_t opq)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->RegisterListener("sizeUpdate", callback, opq);
    }

    void OffSizeUpdate(taihe::optional_view<uintptr_t> opq)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->UnRegisterListener("sizeUpdate", opq);
    }

    void OnSizeChange(taihe::callback_view<void(uintptr_t, taihe::optional_view<KeyboardArea_t>)> callback,
        uintptr_t opq)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->RegisterListener("sizeChange", callback, opq);
    }

    void OffSizeChange(taihe::optional_view<taihe::callback<void(uintptr_t, taihe::optional_view<KeyboardArea_t>)>> opq)
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return;
        }
        panelImpl_->UnRegisterListener("sizeChange", nullptr);
    }

    int64_t LineUp()
    {
        if (panelImpl_ == nullptr) {
            IMSA_HILOGE("panelImpl_ is nullptr!");
            return 0;
        }
        return panelImpl_->LineUp();
    }

    ~IMFPanelImpl();
    
    void ReleaseNative();

private:
    std::shared_ptr<InputMethodPanel> value_;
    std::shared_ptr<PanelImpl> panelImpl_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_INPUT_METHOD_PANEL_IMPL_H