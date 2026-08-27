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
 
#ifndef SERVICES_ADAPTER_FOLD_STATUS_ADAPTER_INCLUDE_FOLD_STATUS_ADAPTER_H
#define SERVICES_ADAPTER_FOLD_STATUS_ADAPTER_INCLUDE_FOLD_STATUS_ADAPTER_H
 
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>
 
#include "display_manager_lite.h"
 
namespace OHOS {
namespace MiscServices {
class FoldStatusAdapter {
public:
    using Callback = std::function<void(int32_t preScreenStatus, int32_t newScreenStatus)>;
 
    static FoldStatusAdapter &GetInstance();
 
    void Init();
    void SetScreenStatusChangedCallback(Callback callback);
    int32_t GetFoldStatus() const;
    int32_t GetVhMode() const;
    int32_t GetScreenStatus() const;
    bool IsFoldable() const;
 
private:
    FoldStatusAdapter() = default;
    ~FoldStatusAdapter() = default;
 
    class DisplayModeListenerImpl : public Rosen::DisplayManagerLite::IDisplayModeListener {
    public:
        explicit DisplayModeListenerImpl(FoldStatusAdapter &adapter) : adapter_(adapter) {}
        void OnDisplayModeChanged(Rosen::FoldDisplayMode displayMode) override;
    private:
        FoldStatusAdapter &adapter_;
    };
 
    class DisplayAttributeListenerImpl : public Rosen::DisplayManagerLite::IDisplayAttributeListener {
    public:
        explicit DisplayAttributeListenerImpl(FoldStatusAdapter &adapter) : adapter_(adapter) {}
        void OnAttributeChange(Rosen::DisplayId displayId,
            const std::vector<std::string> &attributes) override;
    private:
        FoldStatusAdapter &adapter_;
    };
 
    void HandleDisplayModeChanged(Rosen::FoldDisplayMode displayMode);
    void HandleDisplayChanged();
    void RegisterListeners();
    int32_t ConvertDisplayMode(Rosen::FoldDisplayMode displayMode) const;
    int32_t ConvertVhMode() const;
 
    Callback onScreenStatusChanged_;
    int32_t foldStatus_ = 0;
    int32_t vhMode_ = 0;
    bool isFoldable_ = false;
    bool isInitialized_ = false;
    sptr<DisplayModeListenerImpl> displayModeListener_;
    sptr<DisplayAttributeListenerImpl> displayAttributeListener_;
    mutable std::mutex mutex_;
};
} // namespace MiscServices
} // namespace OHOS
 
#endif // SERVICES_ADAPTER_FOLD_STATUS_ADAPTER_INCLUDE_FOLD_STATUS_ADAPTER_H