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

#include "fold_status_adapter.h"

#include "display_manager_lite.h"
#include "global.h"
#include "ime_usage_common.h"

using namespace OHOS::MiscServices::ImeFoldStatusBase;
using OHOS::MiscServices::IME_SCREEN_STATUS_UNAVAILABLE;

namespace OHOS {
namespace MiscServices {

FoldStatusAdapter &FoldStatusAdapter::GetInstance()
{
    static FoldStatusAdapter instance;
    return instance;
}

void FoldStatusAdapter::Init()
{
    IMSA_HILOGI("FoldStatusAdapter::Init start");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isInitialized_ || isInitializing_) {
            IMSA_HILOGI("FoldStatusAdapter already initialized or initializing, skip");
            return;
        }
        isInitializing_ = true;
    }

    // Ensure isInitializing_ is always reset, even if an early return occurs below.
    auto resetInitializing = [this]() {
        std::lock_guard<std::mutex> lock(mutex_);
        isInitializing_ = false;
    };

    auto &dm = Rosen::DisplayManagerLite::GetInstance();
    bool foldable = dm.IsFoldable();

    RegisterListeners();

    // Call DMS APIs outside the lock to avoid holding mutex_ during I/O
    int32_t vhMode = ConvertVhMode();
    int32_t foldStatus = UNFOLDED;
    if (foldable) {
        auto displayMode = dm.GetFoldDisplayMode();
        foldStatus = ConvertDisplayMode(displayMode);
        if (foldStatus == IME_SCREEN_STATUS_UNAVAILABLE) {
            IMSA_HILOGW("FoldStatusAdapter::Init: displayMode=%{public}d returned IME-unavailable, "
                        "using UNFOLDED as safe default until callback corrects it",
                static_cast<uint32_t>(displayMode));
            foldStatus = UNFOLDED;
        }
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        isFoldable_ = foldable;
        foldStatus_ = foldStatus;
        vhMode_ = vhMode;
        isInitialized_ = true;
        // isInitializing_ is reset by the guard below, not here
    }

    resetInitializing();

    if (!foldable) {
        IMSA_HILOGD("IsFoldable()=false, using UNFOLDED as default, vhMode=%{public}d, "
                    "screenStatus=%{public}d",
            vhMode, EncodeScreenStatus(foldStatus, vhMode));
    } else {
        IMSA_HILOGD("FoldStatusAdapter initialized for foldable device, "
                    "foldStatus=%{public}d, vhMode=%{public}d, screenStatus=%{public}d",
            foldStatus, vhMode, EncodeScreenStatus(foldStatus, vhMode));
    }
}

void FoldStatusAdapter::RegisterListeners()
{
    auto &dm = Rosen::DisplayManagerLite::GetInstance();

    // Always register DisplayModeListener regardless of IsFoldable() result.
    // IsFoldable() may return false when DMS is not yet ready (e.g., SA init
    // before DMS service is fully started). Once DMS fires OnDisplayModeChanged,
    // HandleDisplayModeChanged will correct isFoldable_ and foldStatus_.
    displayModeListener_ = new (std::nothrow) DisplayModeListenerImpl(*this);
    if (displayModeListener_ != nullptr) {
        dm.RegisterDisplayModeListener(displayModeListener_);
        IMSA_HILOGD("DisplayModeListener registered");
    } else {
        IMSA_HILOGE("Failed to create DisplayModeListener");
    }

    // Register display attribute listener for rotation changes
    displayAttributeListener_ = new (std::nothrow) DisplayAttributeListenerImpl(*this);
    if (displayAttributeListener_ != nullptr) {
        dm.RegisterDisplayAttributeListener(std::vector<std::string> { "rotation" }, displayAttributeListener_);
        IMSA_HILOGD("DisplayAttributeListener registered for rotation changes");
    } else {
        IMSA_HILOGE("Failed to create DisplayAttributeListener");
    }
}

void FoldStatusAdapter::SetScreenStatusChangedCallback(Callback callback)
{
    onScreenStatusChanged_ = std::move(callback);
}

int32_t FoldStatusAdapter::GetFoldStatus() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return foldStatus_;
}

int32_t FoldStatusAdapter::GetVhMode() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return vhMode_;
}

int32_t FoldStatusAdapter::GetScreenStatus() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return EncodeScreenStatus(foldStatus_, vhMode_);
}

bool FoldStatusAdapter::IsFoldable() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return isFoldable_;
}

void FoldStatusAdapter::HandleDisplayModeChanged(Rosen::FoldDisplayMode displayMode)
{
    int32_t newFoldStatus = ConvertDisplayMode(displayMode);

    // Skip IME-unavailable modes (SUB=3, V_MAIN=6)
    if (newFoldStatus == IME_SCREEN_STATUS_UNAVAILABLE) {
        IMSA_HILOGI("HandleDisplayModeChanged: IME unavailable mode=%{public}u, skip update",
            static_cast<uint32_t>(displayMode));
        return;
    }

    // Snapshot-Call-Update pattern: lock → snapshot state → unlock → call DMS
    // API → lock → update state. The race window between unlock and re-lock is
    // mitigated by using the current member variables (not the stale snapshot)
    // when computing oldScreenStatus in the final locked section. This ensures
    // that if another thread updates foldStatus_/vhMode_ between the two lock
    // sections, we correctly detect no-change and avoid redundant callbacks.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!isFoldable_) {
            IMSA_HILOGD("HandleDisplayModeChanged: correcting isFoldable_ from false to true");
            isFoldable_ = true;
        }
    }

    // Call DMS API outside the lock to avoid holding mutex_ during I/O
    int32_t newVhMode = ConvertVhMode();

    std::lock_guard<std::mutex> lock(mutex_);
    // Use current member variables for oldScreenStatus (not stale snapshot)
    // to avoid redundant callbacks in concurrent scenarios.
    int32_t oldScreenStatus = EncodeScreenStatus(foldStatus_, vhMode_);
    foldStatus_ = newFoldStatus;
    vhMode_ = newVhMode;
    int32_t newScreenStatus = EncodeScreenStatus(foldStatus_, vhMode_);

    IMSA_HILOGI("HandleDisplayModeChanged: old=%{public}d, new=%{public}d", oldScreenStatus, newScreenStatus);

    if (oldScreenStatus != newScreenStatus && onScreenStatusChanged_) {
        onScreenStatusChanged_(oldScreenStatus, newScreenStatus);
    }
}

int32_t FoldStatusAdapter::ConvertDisplayMode(Rosen::FoldDisplayMode displayMode) const
{
    // Direct mapping from FoldDisplayMode to internal screenStatus:
    //   FULL(1)        → EXPAND(3)   M态
    //   MAIN(2)        → FOLD(2)     F态
    //   SUB(3)         → IME unavailable, skip
    //   COORDINATION(4)→ EXPAND(3)   M态 (双屏同显)
    //   GLOBAL_FULL(5) → G(4)        G态
    //   V_MAIN(6)      → IME unavailable, skip
    //   N_MAIN(7)      → N(5)        N态
    //   L_FULL(8)      → LM(6)       LM态
    //   Unknown        → IME unavailable, skip
    //   Non-foldable   → UNFOLDED(1) (set in Init, not here)
    switch (displayMode) {
        case Rosen::FoldDisplayMode::FULL:
            return EXPAND;
        case Rosen::FoldDisplayMode::MAIN:
            return FOLD;
        case Rosen::FoldDisplayMode::SUB: // IME unavailable
            return IME_SCREEN_STATUS_UNAVAILABLE;
        case Rosen::FoldDisplayMode::COORDINATION:
            return EXPAND;
        case Rosen::FoldDisplayMode::GLOBAL_FULL:
            return G;
        case Rosen::FoldDisplayMode::V_MAIN: // IME unavailable
            return IME_SCREEN_STATUS_UNAVAILABLE;
        case Rosen::FoldDisplayMode::N_MAIN:
            return N;
        case Rosen::FoldDisplayMode::L_FULL:
            return LM;
        default:
            IMSA_HILOGW("ConvertDisplayMode: unknown mode=%{public}u, skip (IME unavailable)",
                static_cast<uint32_t>(displayMode));
            return IME_SCREEN_STATUS_UNAVAILABLE;
    }
}

int32_t FoldStatusAdapter::ConvertVhMode() const
{
    auto displayId = Rosen::DisplayManagerLite::GetInstance().GetDefaultDisplayId();
    auto display = Rosen::DisplayManagerLite::GetInstance().GetDisplayById(displayId);
    if (display == nullptr) {
        IMSA_HILOGI("ConvertVhMode: display is null, default PORTRAIT");
        return PORTRAIT;
    }
    auto displayInfo = display->GetDisplayInfo();
    if (displayInfo == nullptr) {
        IMSA_HILOGI("ConvertVhMode: displayInfo is null, default PORTRAIT");
        return PORTRAIT;
    }
    int32_t vh = (displayInfo->GetWidth() > displayInfo->GetHeight()) ? LANDSCAPE : PORTRAIT;
    IMSA_HILOGD("ConvertVhMode: width=%{public}d, height=%{public}d, vh=%{public}d", displayInfo->GetWidth(),
        displayInfo->GetHeight(), vh);
    return vh;
}

// DisplayModeListenerImpl implementation
void FoldStatusAdapter::DisplayModeListenerImpl::OnDisplayModeChanged(Rosen::FoldDisplayMode displayMode)
{
    adapter_.HandleDisplayModeChanged(displayMode);
}

// DisplayAttributeListenerImpl implementation
void FoldStatusAdapter::DisplayAttributeListenerImpl::OnAttributeChange(
    Rosen::DisplayId displayId, const std::vector<std::string> &attributes)
{
    adapter_.HandleDisplayChanged();
}

void FoldStatusAdapter::HandleDisplayChanged()
{
    // Snapshot-Call-Update pattern: call DMS API outside the lock, then use
    // current member variables for comparison in the final locked section.
    int32_t newVhMode = ConvertVhMode();

    std::lock_guard<std::mutex> lock(mutex_);
    // Use current member variables for oldScreenStatus (not stale snapshot)
    // to avoid redundant callbacks in concurrent scenarios.
    if (newVhMode == vhMode_) {
        IMSA_HILOGD("HandleDisplayChanged: vhMode unchanged=%{public}d, skip", vhMode_);
        return;
    }

    int32_t oldScreenStatus = EncodeScreenStatus(foldStatus_, vhMode_);
    vhMode_ = newVhMode;
    int32_t newScreenStatus = EncodeScreenStatus(foldStatus_, vhMode_);

    IMSA_HILOGD(
        "HandleDisplayChanged: orientation changed, old=%{public}d, new=%{public}d", oldScreenStatus, newScreenStatus);

    if (oldScreenStatus != newScreenStatus && onScreenStatusChanged_) {
        onScreenStatusChanged_(oldScreenStatus, newScreenStatus);
    }
}

} // namespace MiscServices
} // namespace OHOS
