/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "input_method_panel.h"

#include <tuple>

#include "display_info.h"
#include "dm_common.h"
#include "global.h"
#include "input_method_ability.h"
#include "input_method_ability_utils.h"
#include "inputmethod_trace.h"
#include "scene_board_judgement.h"
#include "sys_cfg_parser.h"
#include "ui/rs_surface_node.h"

namespace OHOS {
namespace MiscServices {
using WMError = OHOS::Rosen::WMError;
using WindowGravity = OHOS::Rosen::WindowGravity;
using WindowState = OHOS::Rosen::WindowState;
using namespace Rosen;
constexpr float FIXED_SOFT_KEYBOARD_PANEL_RATIO = 0.7;
constexpr float NON_FIXED_SOFT_KEYBOARD_PANEL_RATIO = 1;
constexpr int32_t NUMBER_ZERO = 0;
constexpr int32_t FIXED_PANEL_POS_X = 0;
constexpr int32_t ORIGIN_POS_X = 0;
constexpr int32_t ORIGIN_POS_Y = 0;
constexpr int32_t DEFAULT_AVOID_HEIGHT = -1;
std::atomic<uint32_t> InputMethodPanel::sequenceId_ { 0 };
constexpr int32_t MAXWAITTIME = 30;
constexpr int32_t WAITTIME = 10;
InputMethodPanel::~InputMethodPanel() = default;
constexpr float GRADIENT_HEIGHT_RATIO = 0.15;

int32_t InputMethodPanel::CreatePanel(
    const std::shared_ptr<AbilityRuntime::Context> &context, const PanelInfo &panelInfo)
{
    IMSA_HILOGD(
        "start, type/flag: %{public}d/%{public}d.", static_cast<int32_t>(panelType_), static_cast<int32_t>(panelFlag_));
    panelType_ = panelInfo.panelType;
    panelFlag_ = panelInfo.panelFlag;
    winOption_ = new (std::nothrow) OHOS::Rosen::WindowOption();
    if (winOption_ == nullptr) {
        return ErrorCode::ERROR_NULL_POINTER;
    }
    if (panelInfo.panelType == PanelType::STATUS_BAR) {
        winOption_->SetWindowType(OHOS::Rosen::WindowType::WINDOW_TYPE_INPUT_METHOD_STATUS_BAR);
    } else {
        winOption_->SetWindowType(OHOS::Rosen::WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT);
    }
    WMError wmError = WMError::WM_OK;
    window_ = OHOS::Rosen::Window::Create(GeneratePanelName(), winOption_, context, wmError);
    if (wmError == WMError::WM_ERROR_INVALID_PERMISSION || wmError == WMError::WM_ERROR_NOT_SYSTEM_APP) {
        IMSA_HILOGE("create window failed, permission denied, %{public}d!", wmError);
        return ErrorCode::ERROR_NOT_IME;
    }
    if (window_ == nullptr || wmError != WMError::WM_OK) {
        IMSA_HILOGE("create window failed: %{public}d!", wmError);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    isScbEnable_ = Rosen::SceneBoardJudgement::IsSceneBoardEnabled();
    if (SetPanelProperties() != ErrorCode::NO_ERROR) {
        wmError = window_->Destroy();
        IMSA_HILOGI("destroy window end, wmError is %{public}d.", wmError);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    windowId_ = window_->GetWindowId();
    IMSA_HILOGI("success, type/flag/windowId/isScbEnable_: %{public}d/%{public}d/%{public}u/%{public}d.",
        static_cast<int32_t>(panelType_), static_cast<int32_t>(panelFlag_), windowId_, isScbEnable_);
    if (panelInfo.panelType == SOFT_KEYBOARD && isScbEnable_) {
        RegisterKeyboardPanelInfoChangeListener();
    }
    return ErrorCode::NO_ERROR;
}

std::string InputMethodPanel::GeneratePanelName()
{
    uint32_t sequenceId = GenerateSequenceId();
    std::string windowName = panelType_ == SOFT_KEYBOARD ? "softKeyboard" + std::to_string(sequenceId) :
                                                           "statusBar" + std::to_string(sequenceId);
    IMSA_HILOGD("InputMethodPanel, windowName: %{public}s.", windowName.c_str());
    return windowName;
}

int32_t InputMethodPanel::FullScreenPrepare(Rosen::KeyboardLayoutParams &param)
{
    portraitChangeY_ = 0;
    landscapeChangeY_ = 0;
    if (param.portraitAvoidHeight_ < 0 || param.landscapeAvoidHeight_ < 0 || param.PortraitPanelRect_.posY_  < 0 ||
        param.LandscapePanelRect_.posY_ < 0) {
        IMSA_HILOGE("invalid portraitAvoidHeight_:%{public}d, landscapeAvoidHeight_:%{public}d, portraitPosY_:\
            %{public}d, landscapePosY_:%{public}d", param.portraitAvoidHeight_, param.landscapeAvoidHeight_,
            param.PortraitPanelRect_.posY_, param.LandscapePanelRect_.posY_);
        return ErrorCode::ERROR_INVALID_RANGE;
    }

    uint32_t avoidHeightTmp = static_cast<uint32_t>(param.portraitAvoidHeight_) + immersiveEffect_.gradientHeight;
    if (param.PortraitPanelRect_.height_ < avoidHeightTmp) {
        portraitChangeY_ = avoidHeightTmp - param.PortraitPanelRect_.height_;
        param.PortraitPanelRect_.height_ = avoidHeightTmp;
        param.PortraitPanelRect_.posY_ = static_cast<int32_t>(SafeSubtract(
            static_cast<uint32_t>(param.PortraitPanelRect_.posY_), portraitChangeY_));
    }

    avoidHeightTmp = static_cast<uint32_t>(param.landscapeAvoidHeight_) + immersiveEffect_.gradientHeight;
    if (param.LandscapePanelRect_.height_ < avoidHeightTmp) {
        landscapeChangeY_ = avoidHeightTmp - param.LandscapePanelRect_.height_;
        param.LandscapePanelRect_.height_ = avoidHeightTmp;
        param.LandscapePanelRect_.posY_ = static_cast<int32_t>(SafeSubtract(
            static_cast<uint32_t>(param.LandscapePanelRect_.posY_), landscapeChangeY_));
    }

    int32_t gradientHeightTemp = static_cast<int32_t>(immersiveEffect_.gradientHeight);
    if (param.landscapeAvoidHeight_ > INT32_MAX - gradientHeightTemp) {
        IMSA_HILOGE("landscapeAvoidHeight_ overflow detected");
        return ErrorCode::ERROR_INVALID_RANGE;
    }
    param.landscapeAvoidHeight_ += gradientHeightTemp;

    if (param.portraitAvoidHeight_ > INT32_MAX - gradientHeightTemp) {
        IMSA_HILOGE("portraitAvoidHeight_ overflow detected");
        return ErrorCode::ERROR_INVALID_RANGE;
    }
    param.portraitAvoidHeight_ += gradientHeightTemp;
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::NormalImePrepare(Rosen::KeyboardLayoutParams &param)
{
    if (param.PortraitPanelRect_.posY_ < 0 || param.LandscapePanelRect_.posY_ < 0) {
        IMSA_HILOGE("invalid portraitPosY_:%{public}d, landscapePosY_:%{public}d", param.PortraitPanelRect_.posY_,
            param.LandscapePanelRect_.posY_);
        return ErrorCode::ERROR_INVALID_RANGE;
    }
    uint32_t portraitHeight = param.PortraitPanelRect_.height_ + immersiveEffect_.gradientHeight;
    uint32_t landscapeHeight = param.LandscapePanelRect_.height_ + immersiveEffect_.gradientHeight;

    param.PortraitPanelRect_.height_ = portraitHeight;
    param.LandscapePanelRect_.height_ = landscapeHeight;
    param.LandscapePanelRect_.posY_ = static_cast<int32_t>(SafeSubtract(
        static_cast<uint32_t>(param.LandscapePanelRect_.posY_), immersiveEffect_.gradientHeight));
    param.PortraitPanelRect_.posY_ = static_cast<int32_t>(SafeSubtract(
        static_cast<uint32_t>(param.PortraitPanelRect_.posY_), immersiveEffect_.gradientHeight));
    portraitChangeY_ = immersiveEffect_.gradientHeight;
    landscapeChangeY_ = immersiveEffect_.gradientHeight;
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::PrepareAdjustLayout(Rosen::KeyboardLayoutParams &param)
{
    int32_t ret = ErrorCode::NO_ERROR;
    // full screen keyboard
    if (param.landscapeAvoidHeight_ != DEFAULT_AVOID_HEIGHT && param.portraitAvoidHeight_ != DEFAULT_AVOID_HEIGHT) {
        ret = FullScreenPrepare(param);
    } else {
        ret = NormalImePrepare(param);
    }
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("prepare failed");
        return ret;
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::AdjustLayout(const Rosen::KeyboardLayoutParams &param)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    Rosen::KeyboardLayoutParams paramTmp = param;
    if (immersiveEffect_.gradientHeight != 0) {
        IMSA_HILOGI("gradientHeight:%{public}u is not zero, need adjust layout",  immersiveEffect_.gradientHeight);
        auto ret = PrepareAdjustLayout(paramTmp);
        if (ret != ErrorCode::NO_ERROR) {
            return ret;
        }
    } else {
        portraitChangeY_ = 0;
        landscapeChangeY_ = 0;
    }
    // The actual system panel height includes the gradient height, which may not be consistent with the cached value.
    auto wmRet = window_->AdjustKeyboardLayout(paramTmp);
    if (wmRet != WMError::WM_OK) {
        IMSA_HILOGE("AdjustKeyboardLayout failed, wmError is %{public}d!", wmRet);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::SetPanelProperties()
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window is nullptr!");
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    WindowGravity gravity = WindowGravity::WINDOW_GRAVITY_FLOAT;
    if (panelType_ == SOFT_KEYBOARD && panelFlag_ == FLG_FIXED) {
        gravity = WindowGravity::WINDOW_GRAVITY_BOTTOM;
    } else if (panelType_ == SOFT_KEYBOARD && panelFlag_ == FLG_FLOATING) {
        auto surfaceNode = window_->GetSurfaceNode();
        if (surfaceNode == nullptr) {
            IMSA_HILOGE("surfaceNode is nullptr!");
            return ErrorCode::ERROR_OPERATE_PANEL;
        }
        surfaceNode->SetFrameGravity(Rosen::Gravity::TOP_LEFT);
        Rosen::RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
    } else if (panelType_ == STATUS_BAR) {
        auto surfaceNo = window_->GetSurfaceNode();
        if (surfaceNo == nullptr) {
            IMSA_HILOGE("surfaceNo is nullptr!");
            return ErrorCode::ERROR_OPERATE_PANEL;
        }
        surfaceNo->SetFrameGravity(Rosen::Gravity::TOP_LEFT);
        Rosen::RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
        return ErrorCode::NO_ERROR;
    }
    if (!isScbEnable_) {
        WMError wmError = window_->SetWindowGravity(gravity, invalidGravityPercent);
        if (wmError != WMError::WM_OK) {
            IMSA_HILOGE("failed to set window gravity, wmError is %{public}d, start destroy window!", wmError);
            return ErrorCode::ERROR_OPERATE_PANEL;
        }
        return ErrorCode::NO_ERROR;
    }
    keyboardLayoutParams_.gravity_ = gravity;
    auto ret = AdjustLayout(keyboardLayoutParams_);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SetWindowGravity failed, ret is %{public}d, start destroy window!", ret);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::DestroyPanel()
{
    auto ret = HidePanel();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("InputMethodPanel, hide panel failed, ret: %{public}d!", ret);
    }
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    if (panelType_ == SOFT_KEYBOARD) {
        UnregisterKeyboardPanelInfoChangeListener();
    }
    auto result = window_->Destroy();
    IMSA_HILOGI("destroy ret: %{public}d", result);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::GetResizeParams(
    Rosen::Rect &portrait, Rosen::Rect &landscape, uint32_t width, uint32_t height)
{
    LayoutParams currParams;
    DisplaySize displaySize;
    auto ret = GetDisplaySize(displaySize);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to GetDisplaySize ret: %{public}d", ret);
        return ret;
    }

    if (displaySize.portrait.height == displaySize.portrait.width) {
        portrait.height_ = height;
        portrait.width_ = width;
        landscape.height_ = height;
        landscape.width_ = width;
        IMSA_HILOGI("isScreenEqual now, update screen equal size");
        return ErrorCode::NO_ERROR;
    }

    if (IsDisplayUnfolded()) {
        IMSA_HILOGI("foldable device without fold state");
        if (!isInEnhancedAdjust_) {
            RectifyResizeParams(resizePanelUnfoldParams_, displaySize);
        }
        currParams = resizePanelUnfoldParams_;
    } else {
        IMSA_HILOGI("foldable device with fold state or non-foldable device");
        if (!isInEnhancedAdjust_) {
            RectifyResizeParams(resizePanelFoldParams_, displaySize);
        }
        currParams = resizePanelFoldParams_;
    }

    UpdateRectParams(portrait, landscape, width, height, currParams);
    return ErrorCode::NO_ERROR;
}

void InputMethodPanel::RectifyResizeParams(LayoutParams &params, const DisplaySize &displaySize)
{
    params.portraitRect.height_ =
        std::min(static_cast<float>(displaySize.portrait.height) * FIXED_SOFT_KEYBOARD_PANEL_RATIO,
            static_cast<float>(params.portraitRect.height_));
    params.landscapeRect.height_ =
        std::min(static_cast<float>(displaySize.landscape.height) * FIXED_SOFT_KEYBOARD_PANEL_RATIO,
            static_cast<float>(params.landscapeRect.height_));
    params.portraitRect.width_ =
        std::min(static_cast<float>(displaySize.portrait.width),
            static_cast<float>(params.portraitRect.width_));
    params.landscapeRect.width_ =
        std::min(static_cast<float>(displaySize.landscape.width),
            static_cast<float>(params.landscapeRect.width_));
}

void InputMethodPanel::UpdateRectParams(
    Rosen::Rect &portrait, Rosen::Rect &landscape, uint32_t width, uint32_t height, const LayoutParams &currParams)
{
    if (IsDisplayPortrait()) {
        landscape.height_ = currParams.landscapeRect.height_;
        landscape.width_ = currParams.landscapeRect.width_;
        portrait.height_ = height;
        portrait.width_ = width;
        IMSA_HILOGI("isPortrait now, update portrait size");
    } else {
        portrait.height_ = currParams.portraitRect.height_;
        portrait.width_ = currParams.portraitRect.width_;
        landscape.height_ = height;
        landscape.width_ = width;
        IMSA_HILOGI("isLandscapeRect now, update landscape size");
    }
}

void InputMethodPanel::UpdateResizeParams()
{
    if (IsDisplayUnfolded()) {
        IMSA_HILOGI("foldable device without fold state");
        resizePanelUnfoldParams_ = { keyboardLayoutParams_.LandscapeKeyboardRect_,
            keyboardLayoutParams_.PortraitKeyboardRect_ };
    } else {
        IMSA_HILOGI("foldable device in fold state or non-foldable device");
        resizePanelFoldParams_ = { keyboardLayoutParams_.LandscapeKeyboardRect_,
            keyboardLayoutParams_.PortraitKeyboardRect_ };
    }
}

int32_t InputMethodPanel::ResizeEnhancedPanel(uint32_t width, uint32_t height)
{
    EnhancedLayoutParams layoutParam = enhancedLayoutParams_;
    auto ret = GetResizeParams(layoutParam.portrait.rect, layoutParam.landscape.rect, width, height);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to GetResizeParams, ret: %{public}d", ret);
        return ret;
    }
    auto hotAreas = GetHotAreas();
    ret = AdjustPanelRect(panelFlag_, layoutParam, hotAreas);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to AdjustPanelRect, ret: %{public}d", ret);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    UpdateResizeParams();
    std::lock_guard<std::mutex> lock(keyboardSizeLock_);
    keyboardSize_ = { width, height };
    IMSA_HILOGI("success, width/height: %{public}u/%{public}u.", width, height);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::ResizeWithoutAdjust(uint32_t width, uint32_t height)
{
    if (!IsSizeValid(width, height)) {
        IMSA_HILOGE("size is invalid!");
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    auto ret = window_->Resize(width, height);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("failed to resize, ret: %{public}d", ret);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    std::lock_guard<std::mutex> lock(keyboardSizeLock_);
    keyboardSize_ = { width, height };
    IMSA_HILOGI("success, width/height: %{public}u/%{public}u.", width, height);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::ResizePanel(uint32_t width, uint32_t height)
{
    if (!IsSizeValid(width, height)) {
        IMSA_HILOGE("size is invalid!");
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    LayoutParams params = { enhancedLayoutParams_.landscape.rect, enhancedLayoutParams_.portrait.rect };
    auto ret = GetResizeParams(params.portraitRect, params.landscapeRect, width, height);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to GetResizeParams, ret: %{public}d", ret);
        return ret;
    }
    ret = AdjustPanelRect(panelFlag_, params);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to resize, ret: %{public}d", ret);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    UpdateResizeParams();
    std::lock_guard<std::mutex> lock(keyboardSizeLock_);
    keyboardSize_ = { width, height };
    IMSA_HILOGI("success, width/height: %{public}u/%{public}u.", width, height);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::Resize(uint32_t width, uint32_t height)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    if (!isScbEnable_ || window_->GetType() != WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT) {
        return ResizeWithoutAdjust(width, height);
    }
    if (isInEnhancedAdjust_.load()) {
        return ResizeEnhancedPanel(width, height);
    }
    return ResizePanel(width, height);
}

int32_t InputMethodPanel::MovePanelRect(int32_t x, int32_t y)
{
    LayoutParams params = { enhancedLayoutParams_.landscape.rect, enhancedLayoutParams_.portrait.rect };
    if (IsDisplayPortrait()) {
        params.portraitRect.posX_ = x;
        params.portraitRect.posY_ = y;
        IMSA_HILOGI("isPortrait now, updata portrait size");
    } else {
        params.landscapeRect.posX_ = x;
        params.landscapeRect.posY_ = y;
        IMSA_HILOGI("isLandscapeRect now, updata landscape size");
    }
    auto ret = AdjustPanelRect(panelFlag_, params, false);
    IMSA_HILOGI("x/y: %{public}d/%{public}d, ret = %{public}d", x, y, ret);
    return ret == ErrorCode::NO_ERROR ? ErrorCode::NO_ERROR : ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
}

int32_t InputMethodPanel::MoveEnhancedPanelRect(int32_t x, int32_t y)
{
    auto params = enhancedLayoutParams_;
    if (IsDisplayPortrait()) {
        params.portrait.rect.posX_ = x;
        params.portrait.rect.posY_ = y;
    } else {
        params.landscape.rect.posX_ = x;
        params.landscape.rect.posY_ = y;
    }
    auto hotAreas = GetHotAreas();
    auto ret = AdjustPanelRect(panelFlag_, params, hotAreas);
    IMSA_HILOGI("x/y: %{public}d/%{public}d, ret = %{public}d", x, y, ret);
    return ret == ErrorCode::NO_ERROR ? ErrorCode::NO_ERROR : ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
}

int32_t InputMethodPanel::MoveTo(int32_t x, int32_t y)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    if (panelType_ == SOFT_KEYBOARD && panelFlag_ == FLG_FIXED) {
        IMSA_HILOGE("FLG_FIXED panel can not moveTo!");
        return ErrorCode::NO_ERROR;
    }
    if (!isScbEnable_ || window_->GetType() != WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT) {
        auto ret = window_->MoveTo(x, y);
        IMSA_HILOGI("x/y: %{public}d/%{public}d, ret = %{public}d", x, y, ret);
        return ret == WMError::WM_ERROR_INVALID_PARAM ? ErrorCode::ERROR_PARAMETER_CHECK_FAILED : ErrorCode::NO_ERROR;
    } else if (isInEnhancedAdjust_.load()) {
        return MoveEnhancedPanelRect(x, y);
    } else {
        return MovePanelRect(x, y);
    }
}

int32_t InputMethodPanel::StartMoving()
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_IME;
    }
    if (panelType_ == PanelType::SOFT_KEYBOARD &&
        !(panelFlag_ == FLG_FLOATING || panelFlag_ == FLG_CANDIDATE_COLUMN)) {
        IMSA_HILOGE("invalid panel flag: %{public}d", panelFlag_);
        return ErrorCode::ERROR_INVALID_PANEL_FLAG;
    }
    auto ret = window_->StartMoveWindow();
    if (ret == WmErrorCode::WM_ERROR_DEVICE_NOT_SUPPORT) {
        IMSA_HILOGE("window manager service not support error ret = %{public}d.", ret);
        return ErrorCode::ERROR_DEVICE_UNSUPPORTED;
    }
    if (ret != WmErrorCode::WM_OK) {
        IMSA_HILOGE("window manager service error ret = %{public}d.", ret);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    IMSA_HILOGI("StartMoving  success!");
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::GetDisplayId(uint64_t &displayId)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_IME;
    }
    displayId = window_->GetDisplayId();
    if (displayId == Rosen::DISPLAY_ID_INVALID) {
        IMSA_HILOGE("display id invalid!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    IMSA_HILOGD("GetDisplayId success dispalyId = %{public}" PRIu64 "", displayId);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::AdjustKeyboard()
{
    isAdjustInfoInitialized_.store(false);
    int32_t ret = 0;
    if (isInEnhancedAdjust_.load()) {
        EnhancedLayoutParams params = enhancedLayoutParams_;
        DisplaySize displaySize;
        ret = GetDisplaySize(displaySize);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("failed to GetDisplaySize ret: %{public}d", ret);
            return ret;
        }
        params.portrait.avoidY = static_cast<int32_t>(displaySize.portrait.height - params.portrait.avoidHeight);
        params.landscape.avoidY = static_cast<int32_t>(displaySize.landscape.height - params.landscape.avoidHeight);
        auto hotAreas = GetHotAreas();
        ret = AdjustPanelRect(panelFlag_, params, hotAreas);
    } else {
        LayoutParams params = { enhancedLayoutParams_.landscape.rect, enhancedLayoutParams_.portrait.rect };
        ret = AdjustPanelRect(panelFlag_, params);
    }
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to adjust keyboard, ret: %{public}d", ret);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    IMSA_HILOGI("adjust keyboard success");
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::AdjustPanelRect(
    const PanelFlag panelFlag, const LayoutParams &layoutParams, bool needUpdateRegion)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    if (layoutParams.portraitRect.posX_ < 0 || layoutParams.portraitRect.posY_ < 0 ||
        layoutParams.landscapeRect.posX_ < 0 || layoutParams.landscapeRect.posY_ < 0) {
        IMSA_HILOGE("posX_ and posY_ cannot be less than 0!");
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    if (!CheckSize(panelFlag, layoutParams.portraitRect.width_, layoutParams.portraitRect.height_, true)) {
        IMSA_HILOGE("portrait invalid size!");
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    if (!CheckSize(panelFlag, layoutParams.landscapeRect.width_, layoutParams.landscapeRect.height_, false)) {
        IMSA_HILOGE("landscape invalid size!");
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    auto result = ParsePanelRect(panelFlag, layoutParams);
    if (result != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to parse panel rect, result: %{public}d!", result);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }

    keyboardLayoutParams_.landscapeAvoidHeight_ = DEFAULT_AVOID_HEIGHT;
    keyboardLayoutParams_.portraitAvoidHeight_ = DEFAULT_AVOID_HEIGHT;
    auto ret = AdjustLayout(keyboardLayoutParams_);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("AdjustPanelRect error, err: %{public}d!", ret);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    if (panelFlag_ != panelFlag) {
        InputMethodAbility::GetInstance().NotifyPanelStatus(true, panelFlag);
    }
    UpdateResizeParams();
    UpdateLayoutInfo(panelFlag, layoutParams, {}, keyboardLayoutParams_, false);
    if (needUpdateRegion) {
        UpdateHotAreas();
    }
    IMSA_HILOGI("success, type/flag: %{public}d/%{public}d.", static_cast<int32_t>(panelType_),
        static_cast<int32_t>(panelFlag_));
    return ErrorCode::NO_ERROR;
}

Rosen::KeyboardLayoutParams InputMethodPanel::ConvertToWMSParam(
    PanelFlag panelFlag, const EnhancedLayoutParams &layoutParams)
{
    Rosen::KeyboardLayoutParams wmsParams;
    if (panelFlag == PanelFlag::FLG_FIXED) {
        wmsParams.gravity_ = WindowGravity::WINDOW_GRAVITY_BOTTOM;
    } else {
        wmsParams.gravity_ = WindowGravity::WINDOW_GRAVITY_FLOAT;
    }
    wmsParams.LandscapeKeyboardRect_ = layoutParams.landscape.rect;
    wmsParams.LandscapePanelRect_ = layoutParams.landscape.rect;
    wmsParams.PortraitKeyboardRect_ = layoutParams.portrait.rect;
    wmsParams.PortraitPanelRect_ = layoutParams.portrait.rect;
    wmsParams.portraitAvoidHeight_ = layoutParams.portrait.avoidHeight;
    wmsParams.landscapeAvoidHeight_ = layoutParams.landscape.avoidHeight;
    return wmsParams;
}

Rosen::KeyboardTouchHotAreas InputMethodPanel::ConvertToWMSHotArea(const HotAreas &hotAreas)
{
    return { .landscapeKeyboardHotAreas_ = hotAreas.landscape.keyboardHotArea,
        .portraitKeyboardHotAreas_ = hotAreas.portrait.keyboardHotArea,
        .landscapePanelHotAreas_ = hotAreas.landscape.panelHotArea,
        .portraitPanelHotAreas_ = hotAreas.portrait.panelHotArea };
}

int32_t InputMethodPanel::IsEnhancedParamValid(PanelFlag panelFlag, EnhancedLayoutParams &params)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    if (panelType_ != PanelType::SOFT_KEYBOARD) {
        IMSA_HILOGE("not soft keyboard panel");
        return ErrorCode::ERROR_INVALID_PANEL_TYPE;
    }
    FullPanelAdjustInfo adjustInfo;
    auto ret = GetAdjustInfo(panelFlag, adjustInfo);
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    ret = ParseEnhancedParams(panelFlag, adjustInfo, params);
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::AdjustPanelRect(PanelFlag panelFlag, EnhancedLayoutParams params, HotAreas hotAreas)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    if (panelType_ != PanelType::SOFT_KEYBOARD) {
        IMSA_HILOGE("not soft keyboard panel");
        return ErrorCode::ERROR_INVALID_PANEL_TYPE;
    }
    FullPanelAdjustInfo adjustInfo;
    if (IsNeedConfig()) {
        auto ret = GetAdjustInfo(panelFlag, adjustInfo);
        if (ret != ErrorCode::NO_ERROR) {
            return ret;
        }
    }
    auto ret = ParseEnhancedParams(panelFlag, adjustInfo, params);
    if (ret != ErrorCode::NO_ERROR) {
        return ret;
    }
    // adjust rect
    auto wmsParams = ConvertToWMSParam(panelFlag, params);
    ret = AdjustLayout(wmsParams);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("AdjustKeyboardLayout error, err: %{public}d!", ret);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    // set hot area
    isInEnhancedAdjust_.store(true);
    CalculateHotAreas(params, wmsParams, adjustInfo, hotAreas);
    auto wmsHotAreas = ConvertToWMSHotArea(hotAreas);
    auto result = window_->SetKeyboardTouchHotAreas(wmsHotAreas);
    if (result != WMError::WM_OK) {
        IMSA_HILOGE("SetKeyboardTouchHotAreas error, err: %{public}d!", result);
        ret = AdjustLayout(keyboardLayoutParams_);
        IMSA_HILOGE("restore layout param, result: %{public}d", ret);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    SetHotAreas(hotAreas);
    if (panelFlag_ != panelFlag) {
        InputMethodAbility::GetInstance().NotifyPanelStatus(true, panelFlag);
    }
    UpdateLayoutInfo(panelFlag, {}, params, wmsParams, true);
    UpdateResizeParams();
    IMSA_HILOGI("success, type/flag: %{public}d/%{public}d.", static_cast<int32_t>(panelType_),
        static_cast<int32_t>(panelFlag_));
    return ErrorCode::NO_ERROR;
}

void InputMethodPanel::UpdateLayoutInfo(PanelFlag panelFlag, const LayoutParams &params,
    const EnhancedLayoutParams &enhancedParams, const KeyboardLayoutParams &wmsParams, bool isEnhanced)
{
    if (isEnhanced) {
        enhancedLayoutParams_ = enhancedParams;
        keyboardLayoutParams_ = wmsParams;
    } else {
        EnhancedLayoutParams enhancedLayoutParams = { .isFullScreen = false,
            .portrait = { .rect = params.portraitRect },
            .landscape = { .rect = params.landscapeRect } };
        enhancedLayoutParams_ = std::move(enhancedLayoutParams);
    }
    panelFlag_ = panelFlag;
    isInEnhancedAdjust_.store(isEnhanced);
}

int32_t InputMethodPanel::ParseEnhancedParams(
    PanelFlag panelFlag, const FullPanelAdjustInfo &adjustInfo, EnhancedLayoutParams &params)
{
    DisplaySize display;
    auto ret = GetDisplaySize(display);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to GetDisplaySize ret: %{public}d", ret);
        return ret;
    }
    ret = RectifyRect(params.isFullScreen, params.portrait, display.portrait, panelFlag, adjustInfo.portrait);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("RectifyRect portrait failed, ret: %{public}d", ret);
        return ret;
    }
    ret = RectifyRect(params.isFullScreen, params.landscape, display.landscape, panelFlag, adjustInfo.landscape);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("RectifyRect landscape failed, ret: %{public}d", ret);
        return ret;
    }
    ret = CalculateAvoidHeight(params.portrait, display.portrait, panelFlag, adjustInfo.portrait);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("CalculateAvoidHeight portrait failed, ret: %{public}d", ret);
        return ret;
    }
    ret = CalculateAvoidHeight(params.landscape, display.landscape, panelFlag, adjustInfo.landscape);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("CalculateAvoidHeight landscape failed, ret: %{public}d", ret);
        return ret;
    }
    IMSA_HILOGD("success, portrait: %{public}s, landscape: %{public}s", params.portrait.ToString().c_str(),
        params.landscape.ToString().c_str());
    return ErrorCode::NO_ERROR;
}

bool InputMethodPanel::IsRectValid(const Rosen::Rect &rect, const WindowSize &displaySize)
{
    if (rect.posX_ < 0 || rect.posY_ < 0) {
        IMSA_HILOGE("posX_ and posY_ cannot be less than 0!");
        return false;
    }
    if (rect.width_ > INT32_MAX || rect.height_ > INT32_MAX) {
        IMSA_HILOGE("width or height over maximum!");
        return false;
    }
    if (rect.width_ > displaySize.width || rect.height_ > displaySize.height) {
        IMSA_HILOGE("invalid width or height, target: %{public}u/%{public}u, display: %{public}u/%{public}u",
            rect.width_, rect.height_, displaySize.width, displaySize.height);
        return false;
    }
    return true;
}

int32_t InputMethodPanel::RectifyRect(bool isFullScreen, EnhancedLayoutParam &layoutParam,
    const WindowSize &displaySize, PanelFlag panelFlag, const PanelAdjustInfo &adjustInfo)
{
    if (isFullScreen) {
        layoutParam.rect = { ORIGIN_POS_X, ORIGIN_POS_Y, displaySize.width, displaySize.height };
        return ErrorCode::NO_ERROR;
    }
    if (!IsRectValid(layoutParam.rect, displaySize)) {
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    layoutParam.rect.height_ = std::max(layoutParam.rect.height_, static_cast<uint32_t>(adjustInfo.bottom));
    if (panelFlag == PanelFlag::FLG_FIXED) {
        layoutParam.rect = { FIXED_PANEL_POS_X, static_cast<int32_t>(displaySize.height - layoutParam.rect.height_),
            displaySize.width, layoutParam.rect.height_ };
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::CalculateAvoidHeight(EnhancedLayoutParam &layoutParam, const WindowSize &displaySize,
    PanelFlag panelFlag, const PanelAdjustInfo &adjustInfo)
{
    if (layoutParam.avoidY < 0 || layoutParam.avoidY > INT32_MAX) {
        IMSA_HILOGE("invalid avoidY");
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    if (static_cast<uint32_t>(layoutParam.avoidY) > layoutParam.rect.height_) {
        IMSA_HILOGE(
            "invalid avoidY %{public}d, keyboard height %{public}u", layoutParam.avoidY, layoutParam.rect.height_);
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    auto ratio = panelFlag == PanelFlag::FLG_FIXED ? FIXED_SOFT_KEYBOARD_PANEL_RATIO
                                                   : NON_FIXED_SOFT_KEYBOARD_PANEL_RATIO;
    uint32_t avoidHeight = layoutParam.rect.height_ -  static_cast<uint32_t>(layoutParam.avoidY);
    if (static_cast<float>(avoidHeight) > displaySize.height * ratio) {
        IMSA_HILOGE("invalid avoidY: %{public}d, avoidHeight: %{public}u, displayHeight: %{public}u",
            layoutParam.avoidY, avoidHeight, displaySize.height);
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    if (avoidHeight < static_cast<uint32_t>(adjustInfo.bottom)) {
        avoidHeight = adjustInfo.bottom;
        layoutParam.avoidY = static_cast<int32_t>(layoutParam.rect.height_) - static_cast<int32_t>(avoidHeight);
        IMSA_HILOGI("rectify avoidY to %{public}d", layoutParam.avoidY);
    }
    layoutParam.avoidHeight = avoidHeight;
    return ErrorCode::NO_ERROR;
}

void InputMethodPanel::UpdateHotAreas()
{
    auto hotAreas = GetHotAreas();
    if (!hotAreas.isSet) {
        IMSA_HILOGD("hot area is not customized, no need to update");
        return;
    }
    FullPanelAdjustInfo adjustInfo;
    auto ret = GetAdjustInfo(panelFlag_, adjustInfo);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetAdjustInfo failed ret: %{public}d", ret);
        return;
    }
    CalculateDefaultHotArea(keyboardLayoutParams_.LandscapeKeyboardRect_, keyboardLayoutParams_.LandscapePanelRect_,
        adjustInfo.landscape, hotAreas.landscape, landscapeChangeY_);
    CalculateDefaultHotArea(keyboardLayoutParams_.PortraitKeyboardRect_, keyboardLayoutParams_.PortraitPanelRect_,
        adjustInfo.portrait, hotAreas.portrait, portraitChangeY_);
    auto wmsHotAreas = ConvertToWMSHotArea(hotAreas);
    WMError result = window_->SetKeyboardTouchHotAreas(wmsHotAreas);
    if (result != WMError::WM_OK) {
        IMSA_HILOGE("SetKeyboardTouchHotAreas error, err: %{public}d!", result);
        return;
    }
    SetHotAreas(hotAreas);
    IMSA_HILOGI("success, portrait: %{public}s, landscape: %{public}s",
        HotArea::ToString(hotAreas.portrait.keyboardHotArea).c_str(),
        HotArea::ToString(hotAreas.landscape.keyboardHotArea).c_str());
}

void InputMethodPanel::CalculateHotAreas(const EnhancedLayoutParams &enhancedParams,
    const Rosen::KeyboardLayoutParams &params, const FullPanelAdjustInfo &adjustInfo, HotAreas &hotAreas)
{
    if (isInEnhancedAdjust_.load()) {
        CalculateEnhancedHotArea(enhancedParams.portrait, adjustInfo.portrait, hotAreas.portrait, portraitChangeY_);
        CalculateEnhancedHotArea(enhancedParams.landscape, adjustInfo.landscape, hotAreas.landscape, landscapeChangeY_);
    } else {
        CalculateHotArea(params.PortraitKeyboardRect_, params.PortraitPanelRect_, adjustInfo.portrait,
            hotAreas.portrait, portraitChangeY_);
        CalculateHotArea(params.LandscapeKeyboardRect_, params.LandscapePanelRect_, adjustInfo.landscape,
            hotAreas.landscape, landscapeChangeY_);
    }
    hotAreas.isSet = true;
    IMSA_HILOGD("portrait keyboard: %{public}s, panel: %{public}s",
        HotArea::ToString(hotAreas.portrait.keyboardHotArea).c_str(),
        HotArea::ToString(hotAreas.portrait.panelHotArea).c_str());
    IMSA_HILOGD("landscape keyboard: %{public}s, panel: %{public}s",
        HotArea::ToString(hotAreas.landscape.keyboardHotArea).c_str(),
        HotArea::ToString(hotAreas.landscape.panelHotArea).c_str());
}

void InputMethodPanel::CalculateHotArea(const Rosen::Rect &keyboard, const Rosen::Rect &panel,
    const PanelAdjustInfo &adjustInfo, HotArea &hotArea, uint32_t changeY)
{
    IMSA_HILOGI("changeY: %{public}u", changeY);
    // calculate keyboard hot area
    if (hotArea.keyboardHotArea.empty()) {
        hotArea.keyboardHotArea.push_back({ ORIGIN_POS_X, ORIGIN_POS_Y, keyboard.width_, keyboard.height_ });
    }
    std::vector<Rosen::Rect> availableAreas = { { { ORIGIN_POS_X, ORIGIN_POS_Y, keyboard.width_, keyboard.height_ } } };
    RectifyAreas(availableAreas, hotArea.keyboardHotArea);
    // calculate panel hot area
    Rosen::Rect left = { ORIGIN_POS_X, ORIGIN_POS_Y + changeY, static_cast<uint32_t>(adjustInfo.left), panel.height_ };
    Rosen::Rect right = { .posX_ = static_cast<int32_t>(panel.width_) - adjustInfo.right,
        .posY_ = ORIGIN_POS_Y + changeY,
        .width_ = static_cast<uint32_t>(adjustInfo.right),
        .height_ = panel.height_ };
    Rosen::Rect bottom = { .posX_ = ORIGIN_POS_X,
        .posY_ = static_cast<int32_t>(panel.height_ + changeY) - adjustInfo.bottom,
        .width_ = panel.width_,
        .height_ = static_cast<uint32_t>(adjustInfo.bottom) };
    hotArea.panelHotArea = { left, right, bottom };
}

void InputMethodPanel::CalculateEnhancedHotArea(
    const EnhancedLayoutParam &layout, const PanelAdjustInfo &adjustInfo, HotArea &hotArea, uint32_t changeY)
{
    IMSA_HILOGI("changeY: %{public}u", changeY);
    // calculate keyboard hot area
    if (hotArea.keyboardHotArea.empty()) {
        hotArea.keyboardHotArea.push_back({ ORIGIN_POS_X, ORIGIN_POS_Y, layout.rect.width_, layout.rect.height_ });
    }
    std::vector<Rosen::Rect> availableAreas;
    availableAreas.push_back({ ORIGIN_POS_X, ORIGIN_POS_Y, layout.rect.width_, static_cast<uint32_t>(layout.avoidY) });
    availableAreas.push_back({ .posX_ = adjustInfo.left,
        .posY_ = layout.avoidY,
        .width_ = SafeSubtract(layout.rect.width_, static_cast<uint32_t>(adjustInfo.left + adjustInfo.right)),
        .height_ = SafeSubtract(layout.avoidHeight, static_cast<uint32_t>(adjustInfo.bottom)) });
    RectifyAreas(availableAreas, hotArea.keyboardHotArea);
    // calculate panel hot area
    Rosen::Rect left = { ORIGIN_POS_X, layout.avoidY + changeY, static_cast<uint32_t>(adjustInfo.left),
        layout.avoidHeight };
    Rosen::Rect right = { .posX_ = static_cast<int32_t>(layout.rect.width_) - adjustInfo.right,
        .posY_ = layout.avoidY + changeY,
        .width_ = static_cast<uint32_t>(adjustInfo.right),
        .height_ = layout.avoidHeight };
    Rosen::Rect bottom = { .posX_ = ORIGIN_POS_X,
        .posY_ = static_cast<int32_t>(layout.rect.height_ + changeY) - adjustInfo.bottom,
        .width_ = layout.rect.width_,
        .height_ = static_cast<uint32_t>(adjustInfo.bottom) };
    hotArea.panelHotArea = { left, right, bottom };
}

void InputMethodPanel::CalculateDefaultHotArea(const Rosen::Rect &keyboard, const Rosen::Rect &panel,
    const PanelAdjustInfo &adjustInfo, HotArea &hotArea, uint32_t changeY)
{
    IMSA_HILOGI("changeY: %{public}u", changeY);
    // calculate keyboard hot area
    hotArea.keyboardHotArea.clear();
    hotArea.keyboardHotArea.push_back({ ORIGIN_POS_X, ORIGIN_POS_Y, keyboard.width_, keyboard.height_ });
    // calculate panel hot area
    Rosen::Rect left = { ORIGIN_POS_X, ORIGIN_POS_Y + changeY, static_cast<uint32_t>(adjustInfo.left), panel.height_ };
    Rosen::Rect right = { .posX_ = static_cast<int32_t>(panel.width_) - adjustInfo.right,
        .posY_ = ORIGIN_POS_Y + changeY,
        .width_ = static_cast<uint32_t>(adjustInfo.right),
        .height_ = panel.height_ };
    Rosen::Rect bottom = { .posX_ = ORIGIN_POS_X,
        .posY_ = static_cast<int32_t>(panel.height_ + changeY) - adjustInfo.bottom,
        .width_ = panel.width_,
        .height_ = static_cast<uint32_t>(adjustInfo.bottom) };
    hotArea.panelHotArea = { left, right, bottom };
}

void InputMethodPanel::RectifyAreas(const std::vector<Rosen::Rect> availableAreas, std::vector<Rosen::Rect> &areas)
{
    std::vector<Rosen::Rect> validAreas;
    for (const auto &availableArea : availableAreas) {
        std::vector<Rosen::Rect> modifiedAreas;
        for (const auto &area : areas) {
            auto inter = GetRectIntersection(area, availableArea);
            if (inter.width_ != 0 && inter.height_ != 0) {
                modifiedAreas.push_back(inter);
            }
        }
        validAreas.insert(validAreas.end(), modifiedAreas.begin(), modifiedAreas.end());
    }
    areas = std::move(validAreas);
    // If no valid area, set the region size to 0.
    if (areas.empty()) {
        areas.push_back({ 0, 0, 0, 0 });
    }
}

Rosen::Rect InputMethodPanel::GetRectIntersection(Rosen::Rect a, Rosen::Rect b)
{
    int32_t left = std::max(a.posX_, b.posX_);
    int32_t right = std::min(a.posX_ + static_cast<int32_t>(a.width_), b.posX_ + static_cast<int32_t>(b.width_));
    int32_t top = std::max(a.posY_, b.posY_);
    int32_t bottom = std::min(a.posY_ + static_cast<int32_t>(a.height_), b.posY_ + static_cast<int32_t>(b.height_));
    if (left < right && top < bottom) {
        return { left, top, static_cast<uint32_t>(right - left), static_cast<uint32_t>(bottom - top) };
    } else {
        return { 0, 0, 0, 0 };
    }
}

uint32_t InputMethodPanel::SafeSubtract(uint32_t minuend, uint32_t subtrahend)
{
    if (minuend < subtrahend) {
        IMSA_HILOGE("subtrahend:%{public}u is larger than minuend:%{public}u", subtrahend, minuend);
        return 0;
    }
    return minuend - subtrahend;
}

int32_t InputMethodPanel::UpdateRegion(std::vector<Rosen::Rect> region)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    if (panelType_ != PanelType::SOFT_KEYBOARD) {
        IMSA_HILOGE("not soft keyboard panel: %{public}d", panelType_);
        return ErrorCode::ERROR_INVALID_PANEL_TYPE;
    }
    if (panelFlag_ != PanelFlag::FLG_FIXED && panelFlag_ != PanelFlag::FLG_FLOATING) {
        IMSA_HILOGE("flag not fixed or floating: %{public}d", panelFlag_);
        return ErrorCode::ERROR_INVALID_PANEL_FLAG;
    }
    FullPanelAdjustInfo adjustInfo;
    auto ret = GetAdjustInfo(panelFlag_, adjustInfo);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetAdjustInfo failed ret: %{public}d", ret);
        return ret;
    }
    IMSA_HILOGD("region: %{public}s", HotArea::ToString(region).c_str());
    auto hotAreas = GetHotAreas();
    bool isPortrait = IsDisplayPortrait();
    if (isPortrait) {
        hotAreas.portrait.keyboardHotArea = region;
    } else {
        hotAreas.landscape.keyboardHotArea = region;
    }
    CalculateHotAreas(enhancedLayoutParams_, keyboardLayoutParams_, adjustInfo, hotAreas);
    auto wmsHotAreas = ConvertToWMSHotArea(hotAreas);
    WMError result = window_->SetKeyboardTouchHotAreas(wmsHotAreas);
    if (result != WMError::WM_OK) {
        IMSA_HILOGE("SetKeyboardTouchHotAreas error, err: %{public}d!", result);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    SetHotAreas(hotAreas);
    if (isPortrait) {
        IMSA_HILOGI("success, portrait: %{public}s", HotArea::ToString(hotAreas.portrait.keyboardHotArea).c_str());
    } else {
        IMSA_HILOGI("success, landscape: %{public}s", HotArea::ToString(hotAreas.landscape.keyboardHotArea).c_str());
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::InitAdjustInfo()
{
    std::lock_guard<std::mutex> initLk(adjustInfoInitLock_);
    auto curDisplayId = GetCurDisplayId();
    if (isAdjustInfoInitialized_.load() && adjustInfoDisplayId_ == curDisplayId) {
        return ErrorCode::NO_ERROR;
    }
    std::vector<SysPanelAdjust> configs;
    auto isSuccess = SysCfgParser::ParsePanelAdjust(configs);
    if (!isSuccess) {
        adjustInfoDisplayId_ = curDisplayId;
        isAdjustInfoInitialized_.store(true);
        return ErrorCode::NO_ERROR;
    }
    float densityDpi = 0;
    if (GetDensityDpi(densityDpi) != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get density dpi");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    std::lock_guard<std::mutex> lk(panelAdjustLock_);
    panelAdjust_.clear();
    for (const auto &config : configs) {
        PanelAdjustInfo info = {
            .top = static_cast<int32_t>(config.top * densityDpi),
            .left = static_cast<int32_t>(config.left * densityDpi),
            .right = static_cast<int32_t>(config.right * densityDpi),
            .bottom = static_cast<int32_t>(config.bottom * densityDpi) };
        panelAdjust_.insert({ config.style, info });
    }
    adjustInfoDisplayId_ = curDisplayId;
    isAdjustInfoInitialized_.store(true);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::ParsePanelRect(const PanelFlag panelFlag, const LayoutParams &layoutParams)
{
    keyboardLayoutParams_.landscapeAvoidHeight_ = DEFAULT_AVOID_HEIGHT;
    keyboardLayoutParams_.portraitAvoidHeight_ = DEFAULT_AVOID_HEIGHT;
    std::vector<SysPanelAdjust> configs;
    auto isSuccess = SysCfgParser::ParsePanelAdjust(configs);
    if (isSuccess) {
        InitAdjustInfo();
    } else {
        IMSA_HILOGE("there is no configuration file!");
        auto ret = CalculateNoConfigRect(panelFlag, layoutParams);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("failed to calculate NoConfigRect, err: %{public}d!", ret);
            return ret;
        }
        return ErrorCode::NO_ERROR;
    }
    std::tuple<std::vector<std::string>, std::vector<std::string>> keys = GetScreenStatus(panelFlag);
    auto ret = GetSysPanelAdjust(panelFlag, keys, layoutParams);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetSysPanelAdjust failed!");
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::CalculateNoConfigRect(const PanelFlag panelFlag, const LayoutParams &layoutParams)
{
    if (panelFlag == PanelFlag::FLG_FIXED) {
        keyboardLayoutParams_.gravity_ = WindowGravity::WINDOW_GRAVITY_BOTTOM;
        WindowSize portraitDisplaySize;
        if (!GetDisplaySize(true, portraitDisplaySize)) {
            IMSA_HILOGE("GetPortraitDisplaySize failed!");
            return ErrorCode::ERROR_WINDOW_MANAGER;
        }
        keyboardLayoutParams_.PortraitPanelRect_.width_ = portraitDisplaySize.width;
        keyboardLayoutParams_.PortraitPanelRect_.height_ = layoutParams.portraitRect.height_;
        keyboardLayoutParams_.PortraitPanelRect_.posY_ = static_cast<int32_t>(SafeSubtract(
            portraitDisplaySize.height, keyboardLayoutParams_.PortraitPanelRect_.height_));
        keyboardLayoutParams_.PortraitPanelRect_.posX_ = NUMBER_ZERO;
        // fixed Portraitkeyboard
        keyboardLayoutParams_.PortraitKeyboardRect_.width_ = keyboardLayoutParams_.PortraitPanelRect_.width_;
        keyboardLayoutParams_.PortraitKeyboardRect_.height_ = keyboardLayoutParams_.PortraitPanelRect_.height_;
        keyboardLayoutParams_.PortraitKeyboardRect_.posY_ = keyboardLayoutParams_.PortraitPanelRect_.posY_;
        keyboardLayoutParams_.PortraitKeyboardRect_.posX_ = keyboardLayoutParams_.PortraitPanelRect_.posX_;
        WindowSize landscapeDisplaySize;
        if (!GetDisplaySize(false, landscapeDisplaySize)) {
            IMSA_HILOGE("GetLandscapeDisplaySize failed!");
            return ErrorCode::ERROR_WINDOW_MANAGER;
        }
        keyboardLayoutParams_.LandscapePanelRect_.width_ = landscapeDisplaySize.width;
        keyboardLayoutParams_.LandscapePanelRect_.height_ = layoutParams.landscapeRect.height_;
        keyboardLayoutParams_.LandscapePanelRect_.posY_ = static_cast<int32_t>(SafeSubtract(
            landscapeDisplaySize.height, keyboardLayoutParams_.LandscapePanelRect_.height_));
        keyboardLayoutParams_.LandscapePanelRect_.posX_ = NUMBER_ZERO;
        // Landscapekeyboard
        keyboardLayoutParams_.LandscapeKeyboardRect_.width_ = keyboardLayoutParams_.LandscapePanelRect_.width_;
        keyboardLayoutParams_.LandscapeKeyboardRect_.height_ = keyboardLayoutParams_.LandscapePanelRect_.height_;
        keyboardLayoutParams_.LandscapeKeyboardRect_.posY_ = keyboardLayoutParams_.LandscapePanelRect_.posY_;
        keyboardLayoutParams_.LandscapeKeyboardRect_.posX_ = keyboardLayoutParams_.LandscapePanelRect_.posX_;
    } else {
        keyboardLayoutParams_.gravity_ = WindowGravity::WINDOW_GRAVITY_FLOAT;
        keyboardLayoutParams_.LandscapeKeyboardRect_ = layoutParams.landscapeRect;
        keyboardLayoutParams_.PortraitKeyboardRect_ = layoutParams.portraitRect;
        keyboardLayoutParams_.LandscapePanelRect_ = layoutParams.landscapeRect;
        keyboardLayoutParams_.PortraitPanelRect_ = layoutParams.portraitRect;
    }
    return ErrorCode::NO_ERROR;
}

std::tuple<std::vector<std::string>, std::vector<std::string>> InputMethodPanel::GetScreenStatus(
    const PanelFlag panelFlag)
{
    std::string flag = "invaildFlag";
    std::string foldStatus = "default";
    if (panelFlag == PanelFlag::FLG_FIXED) {
        flag = "fix";
        keyboardLayoutParams_.gravity_ = WindowGravity::WINDOW_GRAVITY_BOTTOM;
    } else if (panelFlag == PanelFlag::FLG_FLOATING) {
        flag = "floating";
        keyboardLayoutParams_.gravity_ = WindowGravity::WINDOW_GRAVITY_FLOAT;
    }
    if (Rosen::DisplayManager::GetInstance().IsFoldable() &&
        Rosen::DisplayManager::GetInstance().GetFoldStatus() != Rosen::FoldStatus::FOLDED) {
        foldStatus = "foldable";
    }
    std::vector<std::string> lanPanel = { flag, foldStatus, "landscape" };
    std::vector<std::string> porPanel = { flag, foldStatus, "portrait" };
    return std::make_tuple(lanPanel, porPanel);
}

int32_t InputMethodPanel::GetAdjustInfo(PanelFlag panelFlag, FullPanelAdjustInfo &fullPanelAdjustInfo)
{
    int32_t ret = InitAdjustInfo();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to init adjust info, ret: %{public}d", ret);
        return ret;
    }
    auto keys = GetScreenStatus(panelFlag);
    auto landscapeKey = std::get<0>(keys);
    auto portraitKey = std::get<1>(keys);
    std::lock_guard<std::mutex> lock(panelAdjustLock_);
    auto lanIter = panelAdjust_.find(landscapeKey);
    auto porIter = panelAdjust_.find(portraitKey);
    if (lanIter != panelAdjust_.end()) {
        fullPanelAdjustInfo.landscape = lanIter->second;
    }
    if (porIter != panelAdjust_.end()) {
        fullPanelAdjustInfo.portrait = porIter->second;
    }
    IMSA_HILOGD("GetAdjustInfo, portrait: %{public}s, landscape: %{public}s",
        fullPanelAdjustInfo.portrait.ToString().c_str(), fullPanelAdjustInfo.landscape.ToString().c_str());
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::GetSysPanelAdjust(const PanelFlag panelFlag,
    std::tuple<std::vector<std::string>, std::vector<std::string>> &keys, const LayoutParams &layoutParams)
{
    PanelAdjustInfo lanIterValue;
    PanelAdjustInfo porIterValue;
    std::lock_guard<std::mutex> lock(panelAdjustLock_);
    auto lanPanel = std::get<0>(keys);
    auto porPanel = std::get<1>(keys);
    auto lanIter = panelAdjust_.find(lanPanel);
    auto porIter = panelAdjust_.find(porPanel);
    if (lanIter != panelAdjust_.end()) {
        lanIterValue = lanIter->second;
    }
    if (porIter != panelAdjust_.end()) {
        porIterValue = porIter->second;
    }
    IMSA_HILOGI("GetSysPanelAdjust, portrait: %{public}s, landscape: %{public}s",
        porIterValue.ToString().c_str(), lanIterValue.ToString().c_str());
    return CalculatePanelRect(panelFlag, lanIterValue, porIterValue, layoutParams);
}

int32_t InputMethodPanel::CalculatePanelRect(const PanelFlag panelFlag, PanelAdjustInfo &lanIterValue,
    PanelAdjustInfo &porIterValue, const LayoutParams &layoutParams)
{
    if (!IsNeedConfig()) {
        IMSA_HILOGI("The security keyboard is handled according to no configuration file");
        return CalculateNoConfigRect(panelFlag, layoutParams);
    }
    auto defaultDisplay = GetCurDisplay();
    if (defaultDisplay == nullptr) {
        IMSA_HILOGE("GetDefaultDisplay failed!");
        return ErrorCode::ERROR_EX_SERVICE_SPECIFIC;
    }
    IMSA_HILOGI("defaultDisplay height: %{public}d, width %{public}d",
        defaultDisplay->GetHeight(), defaultDisplay->GetWidth());
    if (panelFlag == PanelFlag::FLG_FIXED) {
        // fixed PortraitPanel
        WindowSize portraitDisplaySize;
        if (!GetDisplaySize(true, portraitDisplaySize)) {
            IMSA_HILOGE("GetDisplaySize failed!");
            return ErrorCode::ERROR_WINDOW_MANAGER;
        }
        keyboardLayoutParams_.PortraitPanelRect_.width_ = portraitDisplaySize.width;
        keyboardLayoutParams_.PortraitPanelRect_.height_ = layoutParams.portraitRect.height_ +
            static_cast<uint32_t>(porIterValue.top + porIterValue.bottom);
        if (keyboardLayoutParams_.PortraitPanelRect_.height_ >
            portraitDisplaySize.height * FIXED_SOFT_KEYBOARD_PANEL_RATIO) {
            keyboardLayoutParams_.PortraitPanelRect_.height_ =
                portraitDisplaySize.height * FIXED_SOFT_KEYBOARD_PANEL_RATIO;
        }
        keyboardLayoutParams_.PortraitPanelRect_.posY_ =
            static_cast<int32_t>(portraitDisplaySize.height - keyboardLayoutParams_.PortraitPanelRect_.height_);
        keyboardLayoutParams_.PortraitPanelRect_.posX_ = NUMBER_ZERO;
        // fixed Portraitkeyboard
        keyboardLayoutParams_.PortraitKeyboardRect_.width_ = keyboardLayoutParams_.PortraitPanelRect_.width_ -
            static_cast<uint32_t>(porIterValue.left + porIterValue.right);
        keyboardLayoutParams_.PortraitKeyboardRect_.height_ = keyboardLayoutParams_.PortraitPanelRect_.height_ -
            static_cast<uint32_t>(porIterValue.top + porIterValue.bottom);
        keyboardLayoutParams_.PortraitKeyboardRect_.posY_ =
            keyboardLayoutParams_.PortraitPanelRect_.posY_ + static_cast<int32_t>(porIterValue.top);
        keyboardLayoutParams_.PortraitKeyboardRect_.posX_ =
            keyboardLayoutParams_.PortraitPanelRect_.posX_ + static_cast<int32_t>(porIterValue.left);
        return CalculateLandscapeRect(defaultDisplay, layoutParams, lanIterValue);
    }
    return CalculateFloatRect(layoutParams, lanIterValue, porIterValue);
}

int32_t InputMethodPanel::CalculateFloatRect(
    const LayoutParams &layoutParams, PanelAdjustInfo &lanIterValue, PanelAdjustInfo &porIterValue)
{
    keyboardLayoutParams_.gravity_ = WindowGravity::WINDOW_GRAVITY_FLOAT;
    // portrait floating keyboard
    keyboardLayoutParams_.PortraitKeyboardRect_.width_ = layoutParams.portraitRect.width_;
    keyboardLayoutParams_.PortraitKeyboardRect_.height_ = layoutParams.portraitRect.height_;
    keyboardLayoutParams_.PortraitKeyboardRect_.posY_ = layoutParams.portraitRect.posY_;
    keyboardLayoutParams_.PortraitKeyboardRect_.posX_ = layoutParams.portraitRect.posX_;
    // portrait floating panel
    keyboardLayoutParams_.PortraitPanelRect_.width_ = keyboardLayoutParams_.PortraitKeyboardRect_.width_ +
        static_cast<uint32_t>(porIterValue.left + porIterValue.right);
    keyboardLayoutParams_.PortraitPanelRect_.height_ = keyboardLayoutParams_.PortraitKeyboardRect_.height_ +
        static_cast<uint32_t>(porIterValue.top + porIterValue.bottom);
    keyboardLayoutParams_.PortraitPanelRect_.posY_ =
        keyboardLayoutParams_.PortraitKeyboardRect_.posY_ - static_cast<int32_t>(porIterValue.top);
    keyboardLayoutParams_.PortraitPanelRect_.posX_ =
        keyboardLayoutParams_.PortraitKeyboardRect_.posX_ - static_cast<int32_t>(porIterValue.left);

    // landscape floating keyboard
    keyboardLayoutParams_.LandscapeKeyboardRect_.width_ = layoutParams.landscapeRect.width_;
    keyboardLayoutParams_.LandscapeKeyboardRect_.height_ = layoutParams.landscapeRect.height_;
    keyboardLayoutParams_.LandscapeKeyboardRect_.posY_ = layoutParams.landscapeRect.posY_;
    keyboardLayoutParams_.LandscapeKeyboardRect_.posX_ = layoutParams.landscapeRect.posX_;
    // landscape floating panel
    keyboardLayoutParams_.LandscapePanelRect_.width_ = keyboardLayoutParams_.LandscapeKeyboardRect_.width_ +
        static_cast<uint32_t>(lanIterValue.left + lanIterValue.right);
    keyboardLayoutParams_.LandscapePanelRect_.height_ = keyboardLayoutParams_.LandscapeKeyboardRect_.height_ +
        static_cast<uint32_t>(lanIterValue.top + lanIterValue.bottom);
    keyboardLayoutParams_.LandscapePanelRect_.posY_ =
        keyboardLayoutParams_.LandscapeKeyboardRect_.posY_ - static_cast<int32_t>(lanIterValue.top);
    keyboardLayoutParams_.LandscapePanelRect_.posX_ =
        keyboardLayoutParams_.LandscapeKeyboardRect_.posX_ - static_cast<int32_t>(lanIterValue.left);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::CalculateLandscapeRect(sptr<OHOS::Rosen::Display> &defaultDisplay,
    const LayoutParams &layoutParams, PanelAdjustInfo &lanIterValue)
{
    // LandscapePanel
    WindowSize landscapeDisplaySize;
    if (!GetDisplaySize(false, landscapeDisplaySize)) {
        IMSA_HILOGE("GetDisplaySize failed!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    keyboardLayoutParams_.LandscapePanelRect_.width_ = landscapeDisplaySize.width;
    keyboardLayoutParams_.LandscapePanelRect_.height_ = layoutParams.landscapeRect.height_ +
        static_cast<uint32_t>(lanIterValue.top + lanIterValue.bottom);
    if (keyboardLayoutParams_.LandscapePanelRect_.height_ >
        landscapeDisplaySize.height * FIXED_SOFT_KEYBOARD_PANEL_RATIO) {
        keyboardLayoutParams_.LandscapePanelRect_.height_ =
            landscapeDisplaySize.height * FIXED_SOFT_KEYBOARD_PANEL_RATIO;
    }
    keyboardLayoutParams_.LandscapePanelRect_.posY_ =
        static_cast<int32_t>(landscapeDisplaySize.height - keyboardLayoutParams_.LandscapePanelRect_.height_);
    keyboardLayoutParams_.LandscapePanelRect_.posX_ = NUMBER_ZERO;
    // Landscapekeyboard
    keyboardLayoutParams_.LandscapeKeyboardRect_.width_ = keyboardLayoutParams_.LandscapePanelRect_.width_ -
        static_cast<uint32_t>(lanIterValue.left + lanIterValue.right);
    keyboardLayoutParams_.LandscapeKeyboardRect_.height_ = keyboardLayoutParams_.LandscapePanelRect_.height_ -
        static_cast<uint32_t>(lanIterValue.top + lanIterValue.bottom);
    keyboardLayoutParams_.LandscapeKeyboardRect_.posY_ =
        keyboardLayoutParams_.LandscapePanelRect_.posY_ + static_cast<int32_t>(lanIterValue.top);
    keyboardLayoutParams_.LandscapeKeyboardRect_.posX_ =
        keyboardLayoutParams_.LandscapePanelRect_.posX_ + static_cast<int32_t>(lanIterValue.left);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::ChangePanelFlag(PanelFlag panelFlag)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    if (panelFlag_ == panelFlag) {
        return ErrorCode::NO_ERROR;
    }
    if (panelType_ == STATUS_BAR) {
        IMSA_HILOGE("STATUS_BAR cannot ChangePanelFlag!");
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    if (panelType_ == SOFT_KEYBOARD && panelFlag == FLG_CANDIDATE_COLUMN) {
        PanelStatusChangeToImc(InputWindowStatus::HIDE, { 0, 0, 0, 0 });
    }
    WindowGravity gravity = WindowGravity::WINDOW_GRAVITY_FLOAT;
    if (panelFlag == FLG_FIXED) {
        gravity = WindowGravity::WINDOW_GRAVITY_BOTTOM;
    } else {
        auto surfaceNode = window_->GetSurfaceNode();
        if (surfaceNode == nullptr) {
            IMSA_HILOGE("surfaceNode is nullptr!");
            return ErrorCode::ERROR_NULL_POINTER;
        }
        surfaceNode->SetFrameGravity(Rosen::Gravity::TOP_LEFT);
        Rosen::RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
    }
    if (!isScbEnable_) {
        auto ret = window_->SetWindowGravity(gravity, invalidGravityPercent);
        if (ret == WMError::WM_OK) {
            panelFlag_ = panelFlag;
        }
        IMSA_HILOGI("flag: %{public}d, ret: %{public}d.", panelFlag, ret);
        return ret == WMError::WM_OK ? ErrorCode::NO_ERROR : ErrorCode::ERROR_OPERATE_PANEL;
    }
    keyboardLayoutParams_.gravity_ = gravity;
    auto ret = AdjustLayout(keyboardLayoutParams_);
    if (ret == ErrorCode::NO_ERROR) {
        panelFlag_ = panelFlag;
    }
    InputMethodAbility::GetInstance().NotifyPanelStatus(true, panelFlag);
    IMSA_HILOGI("flag: %{public}d, ret: %{public}d.", panelFlag, ret);
    return ret == ErrorCode::NO_ERROR ? ErrorCode::NO_ERROR : ErrorCode::ERROR_OPERATE_PANEL;
}

PanelType InputMethodPanel::GetPanelType()
{
    return panelType_;
}

PanelFlag InputMethodPanel::GetPanelFlag()
{
    return panelFlag_;
}

int32_t InputMethodPanel::ShowPanel()
{
    IMSA_HILOGD("InputMethodPanel start.");
    int32_t waitTime = 0;
    while (isWaitSetUiContent_ && waitTime < MAXWAITTIME) {
        std::this_thread::sleep_for(std::chrono::milliseconds(WAITTIME));
        waitTime += WAITTIME;
        IMSA_HILOGI("InputMethodPanel show pannel waitTime %{public}d.", waitTime);
    }
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_IMA_NULLPTR;
    }
    if (IsShowing()) {
        IMSA_HILOGI("panel already shown.");
        return ErrorCode::NO_ERROR;
    }
    auto ret = WMError::WM_OK;
    {
        KeyboardEffectOption option = ConvertToWmEffect(immersiveMode_, immersiveEffect_);
        InputMethodSyncTrace tracer("InputMethodPanel_ShowPanel");
        ret = window_->ShowKeyboard(option);
    }
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("ShowPanel error, err = %{public}d", ret);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    IMSA_HILOGI("success, type/flag: %{public}d/%{public}d.", static_cast<int32_t>(panelType_),
        static_cast<int32_t>(panelFlag_));
    PanelStatusChange(InputWindowStatus::SHOW);
    if (!isScbEnable_) {
        PanelStatusChangeToImc(InputWindowStatus::SHOW, window_->GetRect());
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::SetTextFieldAvoidInfo(double positionY, double height)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto ret = window_->SetTextFieldAvoidInfo(positionY, height);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("SetTextFieldAvoidInfo error, err: %{public}d!", ret);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::HidePanel()
{
    IMSA_HILOGD("InputMethodPanel start");
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    if (IsHidden()) {
        IMSA_HILOGI("panel already hidden.");
        return ErrorCode::NO_ERROR;
    }
    auto ret = WMError::WM_OK;
    {
        InputMethodSyncTrace tracer("InputMethodPanel_HidePanel");
        ret = window_->Hide();
    }
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("HidePanel error, err: %{public}d!", ret);
        return ErrorCode::ERROR_OPERATE_PANEL;
    }
    IMSA_HILOGI("success, type/flag: %{public}d/%{public}d.", static_cast<int32_t>(panelType_),
        static_cast<int32_t>(panelFlag_));
    PanelStatusChange(InputWindowStatus::HIDE);
    if (!isScbEnable_) {
        PanelStatusChangeToImc(InputWindowStatus::HIDE, { 0, 0, 0, 0 });
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::SetCallingWindow(uint32_t windowId)
{
    IMSA_HILOGD("InputMethodPanel start, windowId: %{public}d.", windowId);
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_PANEL_NOT_FOUND;
    }
    auto ret = window_->SetCallingWindow(windowId);
    IMSA_HILOGI("ret: %{public}d, windowId: %{public}u", ret, windowId);
    return ret == WMError::WM_OK ? ErrorCode::NO_ERROR : ErrorCode::ERROR_WINDOW_MANAGER;
}

int32_t InputMethodPanel::GetCallingWindowInfo(CallingWindowInfo &windowInfo)
{
    IMSA_HILOGD("InputMethodPanel start.");
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_PANEL_NOT_FOUND;
    }
    auto ret = window_->GetCallingWindowWindowStatus(windowInfo.status);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("get status failed, ret: %{public}d!", ret);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    ret = window_->GetCallingWindowRect(windowInfo.rect);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("get rect failed, ret: %{public}d!", ret);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    IMSA_HILOGI("status: %{public}u, rect[x/y/w/h]: [%{public}d/%{public}d/%{public}u/%{public}u].",
        static_cast<uint32_t>(windowInfo.status), windowInfo.rect.posX_, windowInfo.rect.posY_, windowInfo.rect.width_,
        windowInfo.rect.height_);
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::SetPrivacyMode(bool isPrivacyMode)
{
    IMSA_HILOGD("isPrivacyMode: %{public}d.", isPrivacyMode);
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto ret = window_->SetPrivacyMode(isPrivacyMode);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("SetWindowPrivacyMode error, ret: %{public}d", ret);
        return static_cast<int32_t>(ret);
    }
    IMSA_HILOGD("end, isPrivacyMode: %{public}d.", isPrivacyMode);
    return ErrorCode::NO_ERROR;
}

void InputMethodPanel::PanelStatusChange(const InputWindowStatus &status)
{
    if (status == InputWindowStatus::SHOW && showRegistered_ && panelStatusListener_ != nullptr) {
        IMSA_HILOGD("ShowPanel panelStatusListener_ is not nullptr.");
        panelStatusListener_->OnPanelStatus(windowId_, true);
    }
    if (status == InputWindowStatus::HIDE && hideRegistered_ && panelStatusListener_ != nullptr) {
        IMSA_HILOGD("HidePanel panelStatusListener_ is not nullptr.");
        panelStatusListener_->OnPanelStatus(windowId_, false);
    }
}

void InputMethodPanel::PanelStatusChangeToImc(const InputWindowStatus &status, const Rosen::Rect &rect)
{
    ImeWindowInfo info;
    info.panelInfo.panelType = panelType_;
    info.panelInfo.panelFlag = panelFlag_;
    if (info.panelInfo.panelType != SOFT_KEYBOARD || info.panelInfo.panelFlag == FLG_CANDIDATE_COLUMN) {
        IMSA_HILOGD("no need to deal.");
        return;
    }
    auto proxy = ImaUtils::GetImsaProxy();
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr!");
        return;
    }

    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return;
    }

    std::string name = window_->GetWindowName() + "/" + std::to_string(window_->GetWindowId());
    info.windowInfo.name = std::move(name);
    info.windowInfo.left = rect.posX_;
    info.windowInfo.top = rect.posY_;
    info.windowInfo.width = rect.width_;
    info.windowInfo.height = rect.height_;
    IMSA_HILOGD("rect[%{public}d, %{public}d, %{public}u, %{public}u], status: %{public}d, "
                "panelFlag: %{public}d.",
        rect.posX_, rect.posY_, rect.width_, rect.height_, status, info.panelInfo.panelFlag);
    proxy->PanelStatusChange(static_cast<uint32_t>(status), info);
}

bool InputMethodPanel::IsShowing()
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return false;
    }
    auto windowState = window_->GetWindowState();
    if (windowState == WindowState::STATE_SHOWN) {
        return true;
    }
    IMSA_HILOGD("windowState: %{public}d.", static_cast<int>(windowState));
    return false;
}

bool InputMethodPanel::IsHidden()
{
    auto windowState = window_->GetWindowState();
    if (windowState == WindowState::STATE_HIDDEN) {
        return true;
    }
    IMSA_HILOGD("windowState: %{public}d.", static_cast<int>(windowState));
    return false;
}

int32_t InputMethodPanel::SetUiContent(
    const std::string &contentInfo, napi_env env, std::shared_ptr<NativeReference> storage)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr, can not SetUiContent!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    WMError ret = WMError::WM_OK;
    if (storage == nullptr) {
        ret = window_->NapiSetUIContent(contentInfo, env, nullptr);
    } else {
        ret = window_->NapiSetUIContent(contentInfo, env, storage->GetNapiValue());
    }
    WMError wmError = window_->SetTransparent(true);
    if (isWaitSetUiContent_) {
        isWaitSetUiContent_ = false;
    }
    IMSA_HILOGI("SetTransparent ret: %{public}u.", wmError);
    IMSA_HILOGI("NapiSetUIContent ret: %{public}d.", ret);
    return ret == WMError::WM_ERROR_INVALID_PARAM ? ErrorCode::ERROR_PARAMETER_CHECK_FAILED : ErrorCode::NO_ERROR;
}

bool InputMethodPanel::SetPanelStatusListener(
    std::shared_ptr<PanelStatusListener> statusListener, const std::string &type)
{
    if (!MarkListener(type, true)) {
        return false;
    }
    IMSA_HILOGD("type: %{public}s.", type.c_str());
    if (type == "show" || type == "hide") {
        if (panelStatusListener_ == nullptr) {
            IMSA_HILOGD("panelStatusListener_ is nullptr, need to be set");
            panelStatusListener_ = std::move(statusListener);
        }
        if (window_ != nullptr) {
            if (type == "show" && IsShowing()) {
                panelStatusListener_->OnPanelStatus(windowId_, true);
            }
            if (type == "hide" && IsHidden()) {
                panelStatusListener_->OnPanelStatus(windowId_, false);
            }
        }
    }
    if (type == "sizeChange" || type == "sizeUpdate") {
        return SetPanelSizeChangeListener(statusListener);
    }
    return true;
}

bool InputMethodPanel::SetPanelSizeChangeListener(std::shared_ptr<PanelStatusListener> statusListener)
{
    if (panelType_ != PanelType::SOFT_KEYBOARD
        || (panelFlag_ != PanelFlag::FLG_FIXED && panelFlag_ != PanelFlag::FLG_FLOATING)) {
        return true;
    }
    if (panelStatusListener_ == nullptr && statusListener != nullptr) {
        panelStatusListener_ = std::move(statusListener);
    }
    std::lock_guard<std::mutex> lock(windowListenerLock_);
    if (windowChangedListener_ != nullptr) {
        IMSA_HILOGD("windowChangedListener already registered.");
        return true;
    }
    windowChangedListener_ = new (std::nothrow)
        WindowChangeListenerImpl([this](WindowSize windowSize) { SizeChange(windowSize); });
    if (windowChangedListener_ == nullptr || window_ == nullptr) {
        IMSA_HILOGE("observer or window_ is nullptr!");
        return false;
    }
    auto ret = window_->RegisterWindowChangeListener(windowChangedListener_);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("RegisterWindowChangeListener error: %{public}d!", ret);
        return false;
    }
    return true;
}

void InputMethodPanel::ClearPanelListener(const std::string &type)
{
    if (!MarkListener(type, false)) {
        return;
    }
    IMSA_HILOGD("type: %{public}s.", type.c_str());
    if (!sizeChangeRegistered_ && !sizeUpdateRegistered_ && windowChangedListener_ != nullptr && window_ != nullptr) {
        auto ret = window_->UnregisterWindowChangeListener(windowChangedListener_);
        IMSA_HILOGI("UnregisterWindowChangeListener ret: %{public}d.", ret);
        windowChangedListener_ = nullptr;
    }
    if (panelStatusListener_ == nullptr) {
        IMSA_HILOGD("panelStatusListener_ not set, don't need to remove.");
        return;
    }
    if (showRegistered_ || hideRegistered_ || sizeChangeRegistered_ || sizeUpdateRegistered_) {
        return;
    }
    panelStatusListener_ = nullptr;
}

std::shared_ptr<PanelStatusListener> InputMethodPanel::GetPanelListener()
{
    return panelStatusListener_;
}

bool InputMethodPanel::MarkListener(const std::string &type, bool isRegister)
{
    if (type == "show") {
        showRegistered_ = isRegister;
    } else if (type == "hide") {
        hideRegistered_ = isRegister;
    } else if (type == "sizeChange") {
        sizeChangeRegistered_ = isRegister;
    } else if (type == "sizeUpdate") {
        sizeUpdateRegistered_ = isRegister;
    } else {
        IMSA_HILOGE("type error!");
        return false;
    }
    return true;
}

uint32_t InputMethodPanel::GenerateSequenceId()
{
    uint32_t seqId = ++sequenceId_;
    if (seqId == std::numeric_limits<uint32_t>::max()) {
        return ++sequenceId_;
    }
    return seqId;
}

bool InputMethodPanel::IsSizeValid(uint32_t width, uint32_t height)
{
    if (width > INT32_MAX || height > INT32_MAX) {
        IMSA_HILOGE("width or height over maximum!");
        return false;
    }
    auto defaultDisplay = GetCurDisplay();
    if (defaultDisplay == nullptr) {
        IMSA_HILOGE("GetDefaultDisplay failed!");
        return false;
    }
    float ratio = panelType_ == PanelType::SOFT_KEYBOARD && panelFlag_ == PanelFlag::FLG_FIXED ?
        FIXED_SOFT_KEYBOARD_PANEL_RATIO :
        NON_FIXED_SOFT_KEYBOARD_PANEL_RATIO;
    if (static_cast<float>(height) > defaultDisplay->GetHeight() * ratio ||
        static_cast<int32_t>(width) > defaultDisplay->GetWidth()) {
        IMSA_HILOGE("param is invalid, defaultDisplay height: %{public}d, defaultDisplay width %{public}d, target "
                    "height: %{public}u, target width: %{public}u!",
            defaultDisplay->GetHeight(), defaultDisplay->GetWidth(), height, width);
        return false;
    }
    return true;
}

WindowSize InputMethodPanel::GetKeyboardSize()
{
    std::lock_guard<std::mutex> lock(keyboardSizeLock_);
    return keyboardSize_;
}

int32_t InputMethodPanel::SizeChange(const WindowSize &size)
{
    IMSA_HILOGD("InputMethodPanel start.");
    IMSA_HILOGI("type/flag: %{public}d/%{public}d, width/height: %{public}d/%{public}d.",
        static_cast<int32_t>(panelType_), static_cast<int32_t>(panelFlag_), static_cast<int32_t>(size.width),
        static_cast<int32_t>(size.height));
    {
        std::lock_guard<std::mutex> lock(keyboardSizeLock_);
        keyboardSize_ = size;
    }
    auto listener = GetPanelListener();
    if (listener == nullptr) {
        IMSA_HILOGD("panelStatusListener_ is nullptr");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    PanelAdjustInfo keyboardArea;
    if (isInEnhancedAdjust_.load() && GetKeyboardArea(panelFlag_, size, keyboardArea) != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to GetKeyboardArea");
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    if (sizeChangeRegistered_) {
        listener->OnSizeChange(windowId_, keyboardSize_, keyboardArea, "sizeChange");
    }
    if (sizeUpdateRegistered_) {
        listener->OnSizeChange(windowId_, keyboardSize_, keyboardArea, "sizeUpdate");
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::GetKeyboardArea(PanelFlag panelFlag, const WindowSize &size, PanelAdjustInfo &keyboardArea)
{
    bool isPortrait = false;
    if (GetWindowOrientation(panelFlag, size.width, isPortrait) != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to GetWindowOrientation");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    FullPanelAdjustInfo adjustInfo;
    if (GetAdjustInfo(panelFlag, adjustInfo) != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetAdjustInfo failed");
        return ErrorCode::ERROR_BAD_PARAMETERS;
    }
    if (isPortrait) {
        keyboardArea = adjustInfo.portrait;
        keyboardArea.top = enhancedLayoutParams_.portrait.avoidY;
    } else {
        keyboardArea = adjustInfo.landscape;
        keyboardArea.top = enhancedLayoutParams_.landscape.avoidY;
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::GetWindowOrientation(PanelFlag panelFlag, uint32_t windowWidth, bool &isPortrait)
{
    if (panelFlag != PanelFlag::FLG_FIXED) {
        isPortrait = IsDisplayPortrait();
        return ErrorCode::NO_ERROR;
    }
    DisplaySize displaySize;
    if (GetDisplaySize(displaySize) != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to GetDisplaySize");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    if (displaySize.portrait.width == displaySize.portrait.height) {
        isPortrait = IsDisplayPortrait();
        return ErrorCode::NO_ERROR;
    }
    if (windowWidth == displaySize.portrait.width) {
        isPortrait = true;
    }
    if (windowWidth == displaySize.landscape.width) {
        isPortrait = false;
    }
    return ErrorCode::NO_ERROR;
}

void InputMethodPanel::RegisterKeyboardPanelInfoChangeListener()
{
    kbPanelInfoListener_ =
        new (std::nothrow) KeyboardPanelInfoChangeListener([this](const KeyboardPanelInfo &keyboardPanelInfo) {
            OnPanelHeightChange(keyboardPanelInfo);
            HandleKbPanelInfoChange(keyboardPanelInfo);
        });
    if (kbPanelInfoListener_ == nullptr) {
        return;
    }
    if (window_ == nullptr) {
        return;
    }
    auto ret = window_->RegisterKeyboardPanelInfoChangeListener(kbPanelInfoListener_);
    IMSA_HILOGD("ret: %{public}d.", ret);
}

void InputMethodPanel::OnPanelHeightChange(const Rosen::KeyboardPanelInfo &keyboardPanelInfo)
{
    if (panelHeightCallback_ == nullptr) {
        return;
    }
    if (!isInEnhancedAdjust_.load()) {
        panelHeightCallback_(keyboardPanelInfo.rect_.height_, panelFlag_);
        return;
    }
    bool isPortrait = false;
    if (GetWindowOrientation(panelFlag_, keyboardPanelInfo.rect_.width_, isPortrait) != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to GetWindowOrientation");
        return;
    }
    if (isPortrait) {
        panelHeightCallback_(enhancedLayoutParams_.portrait.avoidHeight, panelFlag_);
    } else {
        panelHeightCallback_(enhancedLayoutParams_.landscape.avoidHeight, panelFlag_);
    }
}

void InputMethodPanel::UnregisterKeyboardPanelInfoChangeListener()
{
    if (window_ == nullptr) {
        return;
    }
    auto ret = window_->UnregisterKeyboardPanelInfoChangeListener(kbPanelInfoListener_);
    kbPanelInfoListener_ = nullptr;
    IMSA_HILOGD("ret: %{public}d.", ret);
}

void InputMethodPanel::HandleKbPanelInfoChange(const KeyboardPanelInfo &keyboardPanelInfo)
{
    IMSA_HILOGD("start.");
    InputWindowStatus status = InputWindowStatus::HIDE;
    if (keyboardPanelInfo.isShowing_) {
        status = InputWindowStatus::SHOW;
    }
    PanelStatusChangeToImc(status, keyboardPanelInfo.rect_);
}

bool InputMethodPanel::GetDisplaySize(bool isPortrait, WindowSize &size)
{
    auto defaultDisplay = GetCurDisplay();
    if (defaultDisplay == nullptr) {
        IMSA_HILOGE("GetDefaultDisplay failed!");
        return false;
    }
    auto width = defaultDisplay->GetWidth();
    auto height = defaultDisplay->GetHeight();
    bool isDisplayPortrait = width < height;
    if (isPortrait != isDisplayPortrait) {
        size = { .width = height, .height = width };
    } else {
        size = { .width = width, .height = height };
    }
    return true;
}

bool InputMethodPanel::IsDisplayPortrait()
{
    auto defaultDisplay = GetCurDisplay();
    if (defaultDisplay == nullptr) {
        IMSA_HILOGE("GetDefaultDisplay failed!");
        return false;
    }
    auto width = defaultDisplay->GetWidth();
    auto height = defaultDisplay->GetHeight();
    if (width != height) {
        return width < height;
    }
    auto displayInfo = defaultDisplay->GetDisplayInfo();
    if (displayInfo == nullptr) {
        IMSA_HILOGE("GetDisplayInfo failed");
        return false;
    }
    auto orientation = displayInfo->GetDisplayOrientation();
    IMSA_HILOGI("width equals to height, orientation: %{public}u", static_cast<uint32_t>(orientation));
    return orientation == DisplayOrientation::PORTRAIT || orientation == DisplayOrientation::PORTRAIT_INVERTED;
}

bool InputMethodPanel::IsDisplayUnfolded()
{
    return Rosen::DisplayManager::GetInstance().IsFoldable()
           && Rosen::DisplayManager::GetInstance().GetFoldStatus() != Rosen::FoldStatus::FOLDED;
}

bool InputMethodPanel::CheckSize(PanelFlag panelFlag, uint32_t width, uint32_t height, bool isDataPortrait)
{
    WindowSize displaySize;
    if (!GetDisplaySize(isDataPortrait, displaySize)) {
        IMSA_HILOGE("GetDisplaySize failed!");
        return false;
    }
    return IsSizeValid(panelFlag, width, height, displaySize.width, displaySize.height);
}

bool InputMethodPanel::IsSizeValid(
    PanelFlag panelFlag, uint32_t width, uint32_t height, int32_t displayWidth, int32_t displayHeight)
{
    if (width > INT32_MAX || height > INT32_MAX) {
        IMSA_HILOGE("width or height over maximum!");
        return false;
    }
    float ratio = panelType_ == PanelType::SOFT_KEYBOARD && panelFlag == PanelFlag::FLG_FIXED ?
        FIXED_SOFT_KEYBOARD_PANEL_RATIO :
        NON_FIXED_SOFT_KEYBOARD_PANEL_RATIO;
    if (static_cast<float>(height) > displayHeight * ratio || static_cast<int32_t>(width) > displayWidth) {
        IMSA_HILOGE("param is invalid, defaultDisplay height: %{public}d, defaultDisplay width %{public}d, target "
                    "height: %{public}u, target width: %{public}u!",
            displayHeight, displayWidth, height, width);
        return false;
    }
    return true;
}

void InputMethodPanel::SetPanelHeightCallback(CallbackFunc heightCallback)
{
    panelHeightCallback_ = std::move(heightCallback);
}

int32_t InputMethodPanel::GetDensityDpi(float &densityDpi)
{
    auto defaultDisplay = GetCurDisplay();
    if (defaultDisplay == nullptr) {
        IMSA_HILOGE("GetDefaultDisplay failed!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    auto displayInfo = defaultDisplay->GetDisplayInfo();
    if (displayInfo == nullptr) {
        IMSA_HILOGE("GetDisplayInfo failed!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    densityDpi = displayInfo->GetDensityInCurResolution();
    IMSA_HILOGI("densityDpi: %{public}f", densityDpi);
    if (densityDpi <= 0) {
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputMethodPanel::GetDisplaySize(DisplaySize &size)
{
    auto defaultDisplay = GetCurDisplay();
    if (defaultDisplay == nullptr) {
        IMSA_HILOGE("GetDefaultDisplay failed!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    auto width = defaultDisplay->GetWidth();
    auto height = defaultDisplay->GetHeight();
    if (width < height) {
        size.portrait = { .width = width, .height = height };
        size.landscape = { .width = height, .height = width };
    } else {
        size.portrait = { .width = height, .height = width };
        size.landscape = { .width = width, .height = height };
    }
    return ErrorCode::NO_ERROR;
}

void InputMethodPanel::SetImmersiveEffectToNone()
{
    if (immersiveEffect_.gradientHeight == 0) {
        immersiveEffect_.gradientMode = GradientMode::NONE;
        immersiveEffect_.fluidLightMode = FluidLightMode::NONE;
        return;
    }

    // The SetImmersiveEffect API must be called after the AdjustPanelRect API is called.
    Rosen::KeyboardLayoutParams emptyParams;
    if (keyboardLayoutParams_ == emptyParams) {
        IMSA_HILOGW("set gradientHeight to zero");
        return;
    }

    auto effectTmp = immersiveEffect_;
    immersiveEffect_.gradientHeight = 0;
    immersiveEffect_.gradientMode = GradientMode::NONE;
    immersiveEffect_.fluidLightMode = FluidLightMode::NONE;
    auto ret = AdjustLayout(keyboardLayoutParams_);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("adjust failed, ret: %{public}d", ret);
        immersiveEffect_ = effectTmp;
        return;
    }
    UpdateImmersiveHotArea();
    IMSA_HILOGW("set gradientHeight to zero and adjust layout success");
}

int32_t InputMethodPanel::SetImmersiveMode(ImmersiveMode mode)
{
    if ((mode != ImmersiveMode::NONE_IMMERSIVE && mode != ImmersiveMode::LIGHT_IMMERSIVE &&
        mode != ImmersiveMode::DARK_IMMERSIVE)) {
        IMSA_HILOGE("invalid mode: %{public}d", mode);
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    if (!IsShowing()) {
        if (mode != immersiveMode_ && mode == ImmersiveMode::NONE_IMMERSIVE) {
            SetImmersiveEffectToNone();
        }
        immersiveMode_ = mode;
        IMSA_HILOGD("window is not show, mode: %{public}d", mode);
        return ErrorCode::NO_ERROR;
    }

    if (window_ == nullptr) {
        IMSA_HILOGE("window is null");
        return ErrorCode::ERROR_IME;
    }

    if (mode != immersiveMode_ && mode == ImmersiveMode::NONE_IMMERSIVE) {
        SetImmersiveEffectToNone();
    }
    KeyboardEffectOption option = ConvertToWmEffect(mode, immersiveEffect_);
    // call window manager to set immersive mode
    auto ret = window_->ChangeKeyboardEffectOption(option);
    if (ret == WMError::WM_DO_NOTHING) {
        IMSA_HILOGW("repeat set mode new:%{public}d, old:%{public}d", mode, immersiveMode_);
        return ErrorCode::NO_ERROR;
    }
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("ChangeKeyboardViewMode failed, ret: %{public}d", ret);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    immersiveMode_ = mode;
    IMSA_HILOGI("SetImmersiveMode success, mode: %{public}d", mode);
    return ErrorCode::NO_ERROR;
}

bool InputMethodPanel::IsValidGradientHeight(uint32_t gradientHeight)
{
    if (gradientHeight > INT32_MAX) {
        IMSA_HILOGE("gradientHeight over maximum!");
        return false;
    }
    DisplaySize displaySize;
    auto ret = GetDisplaySize(displaySize);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("Get portrait display size failed, ret: %{public}d", ret);
        return false;
    }

    if (static_cast<float>(gradientHeight) > displaySize.portrait.height * GRADIENT_HEIGHT_RATIO) {
        IMSA_HILOGE("invalid gradientHeight:%{public}u, portraitHeight:%{public}u", gradientHeight,
            displaySize.portrait.height);
        return false;
    }

    if (static_cast<float>(gradientHeight) > displaySize.landscape.height * GRADIENT_HEIGHT_RATIO) {
        IMSA_HILOGE("invalid gradientHeight:%{public}u, landscapeHeight:%{public}u", gradientHeight,
            displaySize.landscape.height);
        return false;
    }

    return true;
}

int32_t InputMethodPanel::IsValidParam(const ImmersiveEffect &effect)
{
    if (effect.gradientMode < GradientMode::NONE || effect.gradientMode >= GradientMode::END ||
        effect.fluidLightMode < FluidLightMode::NONE || effect.fluidLightMode >= FluidLightMode::END) {
        IMSA_HILOGE("invalid effect, gradientMpde:%{public}d, fluidLightMode:%{public}d", effect.gradientMode,
            effect.fluidLightMode);
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }

    // The gradient mode and the fluid light mode can only be used when the immersive mode is enabled.
    if (immersiveMode_ == ImmersiveMode::NONE_IMMERSIVE) {
        if (effect.gradientMode != GradientMode::NONE || effect.fluidLightMode != FluidLightMode::NONE ||
            effect.gradientHeight != 0) {
            IMSA_HILOGE("immersiveMode is NONE, but gradientMode=%{public}d, fluidLightMode=%{public}d",
                effect.gradientMode, effect.fluidLightMode);
            return ErrorCode::ERROR_IMA_INVALID_IMMERSIVE_EFFECT;
        }
        return ErrorCode::NO_ERROR;
    }

    // The fluid light mode can only be used when the gradient mode is enabled.
    if (effect.gradientMode == GradientMode::NONE && effect.fluidLightMode != FluidLightMode::NONE) {
        IMSA_HILOGE("gradientMode is NONE, but fluidLightMode=%{public}d", effect.fluidLightMode);
        return ErrorCode::ERROR_IMA_INVALID_IMMERSIVE_EFFECT;
    }

    if (effect.gradientMode == GradientMode::NONE && effect.gradientHeight != 0) {
        IMSA_HILOGE("gradientMode is NONE, but gradientHeight:%{public}u", effect.gradientHeight);
        return ErrorCode::ERROR_IMA_INVALID_IMMERSIVE_EFFECT;
    }

    // Only system applications can set the fluid light mode.
    if (!InputMethodAbility::GetInstance().IsSystemApp() && effect.fluidLightMode != FluidLightMode::NONE) {
        IMSA_HILOGE("only system app can set fluidLightMode:%{public}d", effect.fluidLightMode);
        return ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION;
    }

    // The gradient height cannot be greater than the screen height * GRADIENT_HEIGHT_RATIO.
    if (!IsValidGradientHeight(effect.gradientHeight)) {
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }

    // The SetImmersiveEffect API must be called after the AdjustPanelRect API is called.
    Rosen::KeyboardLayoutParams emptyParams;
    if (keyboardLayoutParams_ == emptyParams) {
        IMSA_HILOGE("adjust is not call, %{public}s", effect.ToString().c_str());
        return ErrorCode::ERROR_IMA_PRECONDITION_REQUIRED;
    }
    return ErrorCode::NO_ERROR;
}

bool InputMethodPanel::IsImmersiveEffectSupported()
{
    static int32_t isSupport = 0;
    static std::mutex isSupportMutex;
    if (isSupport != 0) {
        return isSupport == 1 ? true : false;
    }

    std::lock_guard<std::mutex> lock(isSupportMutex);
    bool isSupportTemp = false;
    int32_t ret = InputMethodAbility::GetInstance().IsCapacitySupport(
        static_cast<int32_t>(CapacityType::IMMERSIVE_EFFECT), isSupportTemp);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("IsCapacitySupport failed, ret:%{public}d", ret);
        return false;
    }

    if (isSupportTemp) {
        isSupport = 1;
    } else {
        isSupport = -1;
    }
    IMSA_HILOGI("isSupportTemp:%{public}d", isSupportTemp);
    return isSupportTemp;
}

KeyboardEffectOption InputMethodPanel::ConvertToWmEffect(ImmersiveMode mode, const ImmersiveEffect &effect)
{
    KeyboardEffectOption option;
    option.blurHeight_ = effect.gradientHeight;
    option.viewMode_ = static_cast<KeyboardViewMode>(mode);
    option.gradientMode_ = static_cast<KeyboardGradientMode>(effect.gradientMode);
    option.flowLightMode_ = static_cast<KeyboardFlowLightMode>(effect.fluidLightMode);
    IMSA_HILOGI("effect: %{public}s", effect.ToString().c_str());
    return option;
}

void InputMethodPanel::UpdateImmersiveHotArea()
{
    auto hotAreas = GetHotAreas();
    if (!hotAreas.isSet) {
        return;
    }
    FullPanelAdjustInfo adjustInfo;
    auto ret = GetAdjustInfo(panelFlag_, adjustInfo);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetAdjustInfo failed ret: %{public}d", ret);
        return;
    }

    CalculateHotAreas(enhancedLayoutParams_, keyboardLayoutParams_, adjustInfo, hotAreas);
    auto wmsHotAreas = ConvertToWMSHotArea(hotAreas);
    WMError result = window_->SetKeyboardTouchHotAreas(wmsHotAreas);
    if (result != WMError::WM_OK) {
        IMSA_HILOGE("SetKeyboardTouchHotAreas error, err: %{public}d!", result);
        return;
    }
    SetHotAreas(hotAreas);
    IMSA_HILOGI("success, portrait: %{public}s", HotArea::ToString(hotAreas.portrait.keyboardHotArea).c_str());
    IMSA_HILOGI("success, landscape: %{public}s", HotArea::ToString(hotAreas.landscape.keyboardHotArea).c_str());
}

int32_t InputMethodPanel::SetImmersiveEffect(const ImmersiveEffect &effect)
{
    if (!IsImmersiveEffectSupported()) {
        IMSA_HILOGE("immersive effect is not supported");
        return ErrorCode::ERROR_DEVICE_UNSUPPORTED;
    }

    auto ret = IsValidParam(effect);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("invalid param, ret:%{public}d", ret);
        return ret;
    }

    // adjust again
    ImmersiveEffect effectTmp = immersiveEffect_;
    immersiveEffect_ = effect;
    if (effectTmp.gradientMode != effect.gradientMode && effect.gradientMode == GradientMode::NONE) {
        immersiveEffect_.gradientHeight = 0;
        immersiveEffect_.gradientMode = GradientMode::NONE;
        immersiveEffect_.fluidLightMode = FluidLightMode::NONE;
    }
    ret = AdjustLayout(keyboardLayoutParams_);
    if (ret != ErrorCode::NO_ERROR) {
        immersiveEffect_ = effectTmp;
        IMSA_HILOGE("AdjustLayout failed, ret:%{public}d", ret);
        return ret;
    }
    UpdateImmersiveHotArea();

    if (!IsShowing()) {
        IMSA_HILOGW("keyboard is not showing, do nothing");
        return ErrorCode::NO_ERROR;
    }

    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    KeyboardEffectOption option = ConvertToWmEffect(immersiveMode_, immersiveEffect_);
    // call window manager to set immersive mode
    auto wmRet = window_->ChangeKeyboardEffectOption(option);
    if (wmRet == WMError::WM_DO_NOTHING) {
        IMSA_HILOGW("repeat set mode new:, old:%{public}d", immersiveMode_);
        return ErrorCode::NO_ERROR;
    }
    if (wmRet != WMError::WM_OK) {
        IMSA_HILOGE("ChangeKeyboardViewMode failed, wmRet: %{public}d", wmRet);
        immersiveEffect_ = effectTmp;
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    IMSA_HILOGI("success, %{public}s", effect.ToString().c_str());
    return ErrorCode::NO_ERROR;
}

ImmersiveMode InputMethodPanel::GetImmersiveMode()
{
    IMSA_HILOGD("GetImmersiveMode mode: %{public}d", immersiveMode_);
    return immersiveMode_;
}

void InputMethodPanel::SetHotAreas(const HotAreas &hotAreas)
{
    std::lock_guard<std::mutex> lock(hotAreasLock_);
    hotAreas_ = hotAreas;
}

HotAreas InputMethodPanel::GetHotAreas()
{
    std::lock_guard<std::mutex> lock(hotAreasLock_);
    return hotAreas_;
}

sptr<Rosen::Display> InputMethodPanel::GetCurDisplay()
{
    IMSA_HILOGD("enter!!");
    uint64_t displayId = GetCurDisplayId();
    auto displayInfo = Rosen::DisplayManager::GetInstance().GetDisplayById(displayId);
    if (displayInfo == nullptr) {
        IMSA_HILOGE("get display info err:%{public}" PRIu64 "!", displayId);
        displayInfo = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    }
    return displayInfo;
}

uint64_t InputMethodPanel::GetCurDisplayId()
{
    return InputMethodAbility::GetInstance().GetInputAttribute().callingDisplayId;
}

bool InputMethodPanel::IsInMainDisplay()
{
    IMSA_HILOGD("enter!!");
    uint64_t displayId = GetCurDisplayId();
    auto primaryDisplay = Rosen::DisplayManager::GetInstance().GetPrimaryDisplaySync();
    if (primaryDisplay == nullptr) {
        IMSA_HILOGE("primaryDisplay failed!");
        return true;
    }
    return primaryDisplay->GetId() == displayId;
}

void InputMethodPanel::SetIgnoreAdjustInputTypes(const std::vector<int32_t> &inputTypes)
{
    std::lock_guard<std::mutex> lock(ignoreAdjustInputTypeLock_);
    ignoreAdjustInputTypes_ = inputTypes;
}

std::vector<int32_t> InputMethodPanel::GetIgnoreAdjustInputTypes()
{
    std::lock_guard<std::mutex> lock(ignoreAdjustInputTypeLock_);
    return ignoreAdjustInputTypes_;
}

bool InputMethodPanel::IsNeedConfig()
{
    bool needConfig = true;
    bool isSpecialInputType = false;
    auto inputType = InputMethodAbility::GetInstance().GetInputType();
    if (!isIgnorePanelAdjustInitialized_.load()) {
        IgnoreSysPanelAdjust ignoreSysPanelAdjust;
        auto isSuccess = SysCfgParser::ParseIgnoreSysPanelAdjust(ignoreSysPanelAdjust);
        if (isSuccess) {
            SetIgnoreAdjustInputTypes(ignoreSysPanelAdjust.inputType);
        }
        isIgnorePanelAdjustInitialized_.store(true);
    }
    std::vector<int32_t> ignoreAdjustInputTypes = GetIgnoreAdjustInputTypes();
    auto it = std::find_if(
        ignoreAdjustInputTypes.begin(), ignoreAdjustInputTypes.end(), [inputType](const int32_t &mInputType) {
            return static_cast<int32_t>(inputType) == mInputType;
        });
    isSpecialInputType = (it != ignoreAdjustInputTypes.end());
    if (isSpecialInputType || !IsInMainDisplay()) {
        needConfig = false;
    }
    IMSA_HILOGD("isNeedConfig is %{public}d", needConfig);
    return needConfig;
}

int32_t InputMethodPanel::SetKeepScreenOn(bool isKeepScreenOn)
{
    if (window_ == nullptr) {
        IMSA_HILOGE("window_ is nullptr!");
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    auto ret = window_->SetKeepScreenOn(isKeepScreenOn);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("SetKeepScreenOn error: %{public}d!", ret);
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    IMSA_HILOGI("SetKeepScreenOn success");
    return ErrorCode::NO_ERROR;
}
} // namespace MiscServices
} // namespace OHOS