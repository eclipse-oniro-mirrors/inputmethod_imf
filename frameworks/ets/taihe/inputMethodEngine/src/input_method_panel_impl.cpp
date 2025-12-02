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
#include "input_method_panel_impl.h"
#include "js_utils.h"
#include "input_method_panel_listener.h"
#include "event_checker.h"
#include "ani_base_context.h"

namespace OHOS {
namespace MiscServices {
using namespace taihe;
using WMError = OHOS::Rosen::WMError;
constexpr int32_t MAX_WAIT_TIME = 10;
std::mutex PanelImpl::panelMutex_;
std::shared_ptr<PanelImpl> PanelImpl::panel_{ nullptr };
std::shared_ptr<InputMethodPanel> PanelImpl::inputMethodPanel_{ nullptr };
BlockQueue<uint32_t> PanelImpl::jobQueue_{ MAX_WAIT_TIME };
std::atomic<uint32_t> PanelImpl::jobId_{ 0 };
std::shared_ptr<PanelImpl> PanelImpl::GetInstance()
{
    std::shared_ptr<InputMethodPanelListener> panelImpl = InputMethodPanelListener::GetInstance();
    if (panelImpl != nullptr) {
        IMSA_HILOGD("set eventHandler.");
        panelImpl->SetEventHandler(AppExecFwk::EventHandler::Current());
    }
    if (panel_ == nullptr) {
        std::lock_guard<std::mutex> lock(panelMutex_);
        auto panel = std::make_shared<PanelImpl>();
        if (panel == nullptr) {
            IMSA_HILOGE("create panel failed!");
            return nullptr;
        }
        panel_ = panel;
    }
    return panel_;
}

PanelImpl::~PanelImpl()
{
    inputMethodPanel_ = nullptr;
}

void PanelImpl::SetNative(const std::shared_ptr<InputMethodPanel> &panel)
{
    inputMethodPanel_ = panel;
}
std::shared_ptr<InputMethodPanel> PanelImpl::GetNative()
{
    return inputMethodPanel_;
}

void PanelImpl::CreatePanel(uintptr_t ctx, PanelInfo_t const& info, std::shared_ptr<InputMethodPanel> &panel)
{
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr!");
        set_business_error(IMFErrorCode::EXCEPTION_IME,
            JsUtils::ToMessage(JsUtils::Convert(IMFErrorCode::EXCEPTION_IME)));
        return;
    }
    ani_object value = reinterpret_cast<ani_object>(ctx);
    if (value == nullptr) {
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            JsUtils::ToMessage(JsUtils::Convert(IMFErrorCode::EXCEPTION_PARAMCHECK)));
        return;
    }
    std::shared_ptr<AbilityRuntime::Context> context = OHOS::AbilityRuntime::GetStageModeContext(env, value);
    if (context == nullptr) {
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            JsUtils::ToMessage(JsUtils::Convert(IMFErrorCode::EXCEPTION_PARAMCHECK)));
        return;
    }
    PanelInfo panelInfo = CommonConvert::AniConvertPanelInfoToNative(info);
    auto ret = InputMethodAbility::GetInstance().CreatePanel(context, panelInfo, panel);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("CreatePanel failed!");
        set_business_error(IMFErrorCode::EXCEPTION_IME,
            JsUtils::ToMessage(JsUtils::Convert(IMFErrorCode::EXCEPTION_IME)));
        return;
    }
    if (panel != nullptr) {
        inputMethodPanel_ = panel;
        IMSA_HILOGI("CreatePanel success!");
        return;
    }
    IMSA_HILOGE("CreatePanel failed, panel is nullptr!");
}

void PanelImpl::StartMoving()
{
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        return;
    }
    auto ret = inputMethodPanel_->StartMoving();
    if (ret != ErrorCode::NO_ERROR) {
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
    }
}

bool PanelImpl::IsPanelFlagValid(PanelFlag panelFlag, bool isEnhancedCalled)
{
    bool isValid = false;
    if (InputMethodAbility::GetInstance().IsDefaultIme()) {
        isValid = panelFlag == FLG_FIXED || panelFlag == FLG_FLOATING || panelFlag == FLG_CANDIDATE_COLUMN;
    } else {
        isValid = panelFlag == FLG_FIXED || panelFlag == FLG_FLOATING;
    }
    IMSA_HILOGI("flag: %{public}d, isEnhanced: %{public}d, isValid: %{public}d", panelFlag, isEnhancedCalled, isValid);
    if (!isEnhancedCalled && !isValid) {
        IMSA_HILOGE("invalid panelFlag!");
        return false;
    }
    return true;
}

bool PanelImpl::ParseUpdateRegionParam(std::vector<Rosen::Rect> &hotArea, uintptr_t inputRegion)
{
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        return false;
    }
    if (inputMethodPanel_->GetPanelType() != PanelType::SOFT_KEYBOARD) {
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_INVALID_PANEL_TYPE),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_INVALID_PANEL_TYPE)));
        return false;
    }
    if (!IsPanelFlagValid(inputMethodPanel_->GetPanelFlag(), true)) {
        IMSA_HILOGE("invalid panelFlag!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_INVALID_PANEL_FLAG),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_INVALID_PANEL_FLAG)));
        return false;
    }
    ani_object aniArray = reinterpret_cast<ani_object>(inputRegion);
    if (aniArray == nullptr) {
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        return false;
    }
    if (!CommonConvert::ParseRects(aniArray, hotArea, MAX_INPUT_REGION_LEN)) {
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        return false;
    }
    return true;
}

void PanelImpl::UpdateRegion(uintptr_t inputRegion)
{
    int64_t id = LineUp();
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    std::vector<Rosen::Rect> hotArea;
    if (!ParseUpdateRegionParam(hotArea, inputRegion)) {
        jobQueue_.Pop();
        return;
    }
    int32_t code = inputMethodPanel_->UpdateRegion(hotArea);
    jobQueue_.Pop();
    if (code == ErrorCode::NO_ERROR) {
        IMSA_HILOGI("UpdateRegion success!");
        return;
    } else if (code == ErrorCode::ERROR_INVALID_PANEL_TYPE) {
        IMSA_HILOGE("only used for SOFT_KEYBOARD panel!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    } else if (code == ErrorCode::ERROR_INVALID_PANEL_FLAG) {
        IMSA_HILOGE("only used for fixed or floating panel!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGE("UpdateRegion failed!");
    set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
    return;
}

void PanelImpl::AdjustPanelRect(PanelFlag_t flag, PanelRect_t const& rect)
{
    int64_t id = LineUp();
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return;
    }
    PanelFlag panelFlag = static_cast<PanelFlag>(flag.get_value());
    ani_env* env = taihe::get_env();
    LayoutParams layoutParams;
    if (!CommonConvert::ParsePanelRect(env, rect, layoutParams)) {
        IMSA_HILOGE("ParsePanelRect is failed!");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        jobQueue_.Pop();
        return;
    }
    int32_t ret = inputMethodPanel_->AdjustPanelRect(panelFlag, layoutParams);
    jobQueue_.Pop();
    if (ret == ErrorCode::NO_ERROR) {
        IMSA_HILOGI("AdjustPanelRect success!");
        return;
    } else if (ret == ErrorCode::ERROR_PARAMETER_CHECK_FAILED) {
        IMSA_HILOGE("invalid param");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    } else {
        IMSA_HILOGE("AdjustPanelRect failed!");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
    }
}

void PanelImpl::AdjustPanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect)
{
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        return;
    }
    PanelFlag panelFlag = static_cast<PanelFlag>(flag.get_value());
    EnhancedLayoutParams enhancedLayoutParams;
    HotAreas hotAreas;
    ani_env* env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr!");
        set_business_error(IMFErrorCode::EXCEPTION_IME, JsUtils::ToMessage(IMFErrorCode::EXCEPTION_IME));
        return;
    }
    if (!CommonConvert::ParseEnhancedPanelRect(env, rect, enhancedLayoutParams, hotAreas)) {
        IMSA_HILOGE("parse  EnhancedPanelRect failed");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        return;
    }
    int32_t ret = inputMethodPanel_->AdjustPanelRect(panelFlag, enhancedLayoutParams, hotAreas);
    if (ret == ErrorCode::NO_ERROR) {
        IMSA_HILOGI("AdjustPanelRect success!");
        return;
    } else if (ret == ErrorCode::ERROR_PARAMETER_CHECK_FAILED) {
        IMSA_HILOGE("invalid param");
        set_business_error(JsUtils::Convert(ret),
            JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    } else if (ret == ErrorCode::ERROR_INVALID_PANEL_TYPE) {
        IMSA_HILOGE("only used for SOFT_KEYBOARD panel");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
}

uint32_t PanelImpl::GetDisplayIdSync(int64_t id)
{
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    uint64_t displayId = 0;
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return static_cast<uint32_t>(displayId);
    }
    auto ret = inputMethodPanel_->GetDisplayId(displayId);
    jobQueue_.Pop();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed get displayId!");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return static_cast<uint32_t>(displayId);
    }
    if (displayId > UINT32_MAX) {
        IMSA_HILOGE("displayId is too large, displayId: %{public}" PRIu64 "", displayId);
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_WINDOW_MANAGER),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_WINDOW_MANAGER)));
        return static_cast<uint32_t>(displayId);
    }
    IMSA_HILOGI("get displayId success!");
    return static_cast<uint32_t>(displayId);
}

ImmersiveMode_t PanelImpl::GetImmersiveMode()
{
    int64_t id = LineUp();
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return CommonConvert::ConvertMode(ImmersiveMode::NONE_IMMERSIVE);
    }
    auto immersiveMode = inputMethodPanel_->GetImmersiveMode();
    jobQueue_.Pop();
    IMSA_HILOGI("get Immersive mode success!");
    return CommonConvert::ConvertMode(immersiveMode);
}

bool PanelImpl::IsVaildImmersiveMode(ImmersiveMode mode)
{
    if (mode == ImmersiveMode::NONE_IMMERSIVE ||
        mode == ImmersiveMode::LIGHT_IMMERSIVE ||
        mode == ImmersiveMode::DARK_IMMERSIVE) {
        return true;
    }
    return false;
}

void PanelImpl::SetImmersiveMode(ImmersiveMode_t mode)
{
    int64_t id = LineUp();
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return;
    }
    ImmersiveMode immersiveMode = static_cast<ImmersiveMode>(mode.get_value());
    if (!IsVaildImmersiveMode(immersiveMode)) {
        IMSA_HILOGE("immersiveMode type must be ImmersiveMode and can not be IMMERSIVE");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        jobQueue_.Pop();
        return;
    }
    auto ret = inputMethodPanel_->SetImmersiveMode(immersiveMode);
    jobQueue_.Pop();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SetImmersiveMode failed!");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("set Immersive mode success!");
}

void PanelImpl::SetPrivacyMode(bool isPrivacyMode)
{
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        return;
    }
    auto ret = inputMethodPanel_->SetPrivacyMode(isPrivacyMode);
    if (ret == static_cast<int32_t>(WMError::WM_ERROR_INVALID_PERMISSION)) {
        IMSA_HILOGE("permission denied");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_STATUS_PERMISSION_DENIED),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_STATUS_PERMISSION_DENIED)));
        return;
    } else if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to SetPrivacyMode!");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("set Privacy mode success!");
}

void PanelImpl::ChangeFlag(PanelFlag_t flag)
{
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        return;
    }
    auto panelFlag = static_cast<PanelFlag>(flag.get_value());
    auto ret = inputMethodPanel_->ChangePanelFlag(panelFlag);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to ChangePanelFlag!");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return;
    }
    IMSA_HILOGI("change flag success!");
}

void PanelImpl::MoveToAsync(int64_t id, int32_t x, int32_t y)
{
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return;
    }
    auto code = inputMethodPanel_->MoveTo(x, y);
    jobQueue_.Pop();
    if (code == ErrorCode::ERROR_PARAMETER_CHECK_FAILED) {
        IMSA_HILOGE("moveTo failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("moveTo success!");
}

void PanelImpl::ResizeAsync(int64_t id, int64_t width, int64_t height)
{
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return;
    }
    auto code = inputMethodPanel_->Resize(static_cast<uint32_t>(width), static_cast<uint32_t>(height));
    jobQueue_.Pop();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("Resize failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGE("Resize success!");
}

void PanelImpl::SetUiContent(int64_t id, taihe::string_view path, ani_object storage)
{
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return;
    }
    std::string contentInfo = std::string(path);
    auto code = inputMethodPanel_->SetUiContentAni(contentInfo, env, storage);
    jobQueue_.Pop();
    if (code == ErrorCode::ERROR_PARAMETER_CHECK_FAILED) {
        IMSA_HILOGE("path should be a path to specific page.");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    } else if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SetUiContent failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("SetUiContent success!");
}

void PanelImpl::HideAsync(int64_t id)
{
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return;
    }
    auto code = InputMethodAbility::GetInstance().HidePanel(inputMethodPanel_);
    jobQueue_.Pop();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("Hide failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("Hide success!");
}

void PanelImpl::ShowAsync(int64_t id)
{
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return;
    }
    auto code = InputMethodAbility::GetInstance().ShowPanel(inputMethodPanel_);
    jobQueue_.Pop();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("Show failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("Show success!");
}

void PanelImpl::SetKeepScreenOnAsync(bool isKeepScreenOn)
{
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        return;
    }
    auto code = inputMethodPanel_->SetKeepScreenOn(isKeepScreenOn);
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SetKeepScreenOn failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("SetKeepScreenOn success!");
}

void PanelImpl::SetImmersiveEffect(ImmersiveEffect_t const& effect)
{
    int64_t id = LineUp();
    if (!jobQueue_.Wait(static_cast<int64_t>(id))) {
        IMSA_HILOGW("wait timeout id: %{public}" PRId64 "", id);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        jobQueue_.Pop();
        return;
    }
    ImmersiveEffect result = CommonConvert::AniConvertEffectToNative(effect);
    auto code = inputMethodPanel_->SetImmersiveEffect(result);
    jobQueue_.Pop();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SetImmersiveEffect failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("SetImmersiveEffect success!");
}

void PanelImpl::RegisterListener(std::string const &type, callbackTypes &&cb, uintptr_t opq)
{
    IMSA_HILOGD("PanelImpl start.");
    if (!EventChecker::IsValidEventType(EventSubscribeModule::PANEL, type)) {
        IMSA_HILOGE("RegisterListener failed, type: %{public}s!", type.c_str());
        return;
    }
    IMSA_HILOGD("RegisterListener type: %{public}s.", type.c_str());
    if (type == "sizeUpdate") {
        if (!InputMethodAbility::GetInstance().IsSystemApp()) {
            set_business_error(IMFErrorCode::EXCEPTION_SYSTEM_PERMISSION,
                JsUtils::ToMessage(IMFErrorCode::EXCEPTION_SYSTEM_PERMISSION));
            return;
        }
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("inputMethodPanel is nullptr!");
        return;
    }
    std::shared_ptr<InputMethodPanelListener> observer = InputMethodPanelListener::GetInstance();
    observer->Subscribe(inputMethodPanel_->windowId_, type, std::forward<callbackTypes>(cb), opq);
    bool ret = inputMethodPanel_->SetPanelStatusListener(observer, type);
    if (!ret) {
        IMSA_HILOGE("failed to subscribe %{public}s!", type.c_str());
        observer->RemoveInfo(inputMethodPanel_->windowId_, type);
        return;
    }
}

void PanelImpl::UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq)
{
    if (!EventChecker::IsValidEventType(EventSubscribeModule::PANEL, type)) {
        IMSA_HILOGE("RegisterListener failed, type: %{public}s!", type.c_str());
        return;
    }
    IMSA_HILOGD("RegisterListener type: %{public}s.", type.c_str());
    if (type == "sizeUpdate") {
        if (!InputMethodAbility::GetInstance().IsSystemApp()) {
            set_business_error(IMFErrorCode::EXCEPTION_SYSTEM_PERMISSION,
                JsUtils::ToMessage(IMFErrorCode::EXCEPTION_SYSTEM_PERMISSION));
            return;
        }
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("inputMethodPanel is nullptr!");
        return;
    }
    std::shared_ptr<InputMethodPanelListener> observer = InputMethodPanelListener::GetInstance();
    observer->RemoveInfo(inputMethodPanel_->windowId_, type);
    inputMethodPanel_->ClearPanelListener(type);
}

int64_t PanelImpl::LineUp()
{
    uint32_t id = ++jobId_;
    jobQueue_.Push(id);
    return static_cast<int64_t>(id);
}
} // namespace MiscServices
} // namespace OHOS