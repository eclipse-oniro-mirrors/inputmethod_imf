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

namespace OHOS {
namespace MiscServices {
class PanelImpl {
public:
    static std::shared_ptr<PanelImpl> GetInstance();
    ~PanelImpl();
    void CreatePanel(uintptr_t ctx, PanelInfo_t const& info, std::shared_ptr<InputMethodPanel> &panel);
    void StartMoving();
    void UpdateRegion(uintptr_t inputRegion);
    void AdjustPanelRect(PanelFlag_t flag, PanelRect_t const& rect);
    void AdjustPanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect);
    uint32_t GetDisplayIdSync(int64_t id);
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
    void SetNative(const std::shared_ptr<InputMethodPanel> &panel);
    std::shared_ptr<InputMethodPanel> GetNative();
    bool ParseUpdateRegionParam(std::vector<Rosen::Rect> &hotArea, uintptr_t inputRegion);
    static std::mutex panelMutex_;
    static std::shared_ptr<PanelImpl> panel_;
    static std::shared_ptr<InputMethodPanel> inputMethodPanel_;
    static BlockQueue<uint32_t> jobQueue_;
    static std::atomic<uint32_t> jobId_;
};

class IMFPanelImpl {
public:
    IMFPanelImpl(uintptr_t ctx, PanelInfo_t const& info)
    {
        value_ = std::shared_ptr<InputMethodPanel>();
        PanelImpl::GetInstance()->CreatePanel(ctx, info, value_);
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
        PanelImpl::GetInstance()->SetUiContent(id, path, nullptr);
    }

    void SetUiContentSync(int64_t id, taihe::string_view path)
    {
        PanelImpl::GetInstance()->SetUiContent(id, path, nullptr);
    }

    void SetUiContentStorage(int64_t id, ::taihe::string_view path, uintptr_t storage)
    {
        ani_object obj = reinterpret_cast<ani_object>(storage);
        if (obj == nullptr) {
            IMSA_HILOGW("storage is nullptr");
        }
        PanelImpl::GetInstance()->SetUiContent(id, path, obj);
    }

    void SetUiContentStorageSync(int64_t id, ::taihe::string_view path, uintptr_t storage)
    {
        ani_object obj = reinterpret_cast<ani_object>(storage);
        if (obj == nullptr) {
            IMSA_HILOGW("storage is nullptr");
        }
        PanelImpl::GetInstance()->SetUiContent(id, path, obj);
    }

    void ResizeAsync(int64_t id, int64_t width, int64_t height)
    {
        PanelImpl::GetInstance()->ResizeAsync(id, width, height);
    }

    void MoveToAsync(int64_t id, int32_t x, int32_t y)
    {
        PanelImpl::GetInstance()->MoveToAsync(id, x, y);
    }

    uint32_t GetDisplayIdSync(int64_t id)
    {
        return PanelImpl::GetInstance()->GetDisplayIdSync(id);
    }

    void ShowAsync(int64_t id)
    {
        PanelImpl::GetInstance()->ShowAsync(id);
    }

    void HideAsync(int64_t id)
    {
        PanelImpl::GetInstance()->HideAsync(id);
    }

    void SetKeepScreenOnAsync(bool isKeepScreenOn)
    {
        PanelImpl::GetInstance()->SetKeepScreenOnAsync(isKeepScreenOn);
    }

    void StartMoving()
    {
        PanelImpl::GetInstance()->StartMoving();
    }

    void ChangeFlag(PanelFlag_t flag)
    {
        PanelImpl::GetInstance()->ChangeFlag(flag);
    }

    void SetPrivacyMode(bool isPrivacyMode)
    {
        PanelImpl::GetInstance()->SetPrivacyMode(isPrivacyMode);
    }

    void AdjustPanelRect(PanelFlag_t flag, PanelRect_t const& rect)
    {
        PanelImpl::GetInstance()->AdjustPanelRect(flag, rect);
    }

    void AdjustPanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect)
    {
        PanelImpl::GetInstance()->AdjustPanelRectEnhanced(flag, rect);
    }

    void UpdateRegion(uintptr_t inputRegion)
    {
        PanelImpl::GetInstance()->UpdateRegion(inputRegion);
    }

    void SetImmersiveMode(ImmersiveMode_t mode)
    {
        PanelImpl::GetInstance()->SetImmersiveMode(mode);
    }

    ImmersiveMode_t GetImmersiveMode()
    {
        return PanelImpl::GetInstance()->GetImmersiveMode();
    }

    void SetImmersiveEffect(ImmersiveEffect_t const& effect)
    {
        PanelImpl::GetInstance()->SetImmersiveEffect(effect);
    }

    void OnShow(taihe::callback_view<void()> callback, uintptr_t opq)
    {
        PanelImpl::GetInstance()->RegisterListener("show", callback, opq);
    }

    void OffShow(taihe::optional_view<uintptr_t> opq)
    {
        PanelImpl::GetInstance()->UnRegisterListener("show", opq);
    }

    void OnHide(taihe::callback_view<void()> callback, uintptr_t opq)
    {
        PanelImpl::GetInstance()->RegisterListener("hide", callback, opq);
    }

    void OffHide(taihe::optional_view<uintptr_t> opq)
    {
        PanelImpl::GetInstance()->UnRegisterListener("hide", opq);
    }

    void OnSizeUpdate(taihe::callback_view<void(uintptr_t, KeyboardArea_t const&)> callback, uintptr_t opq)
    {
        PanelImpl::GetInstance()->RegisterListener("sizeUpdate", callback, opq);
    }

    void OffSizeUpdate(taihe::optional_view<uintptr_t> opq)
    {
        PanelImpl::GetInstance()->UnRegisterListener("sizeUpdate", opq);
    }

    void OnSizeChange(taihe::callback_view<void(uintptr_t, taihe::optional_view<KeyboardArea_t>)> callback,
        uintptr_t opq)
    {
        PanelImpl::GetInstance()->RegisterListener("sizeChange", callback, opq);
    }

    void OffSizeChange(taihe::optional_view<uintptr_t> opq)
    {
        PanelImpl::GetInstance()->UnRegisterListener("sizeChange", opq);
    }

    int64_t LineUp()
    {
        return PanelImpl::GetInstance()->LineUp();
    }

private:
    std::shared_ptr<InputMethodPanel> value_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_INPUT_METHOD_PANEL_IMPL_H