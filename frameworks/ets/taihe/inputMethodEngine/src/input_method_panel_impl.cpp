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
#include "ani_base_context.h"
#include "event_checker.h"
#include "input_method_panel_listener.h"
#include "js_utils.h"
#include <functional>
#include <memory>
#include <new>
#include <pthread.h>

namespace OHOS {
namespace MiscServices {
using namespace taihe;
using WMError = OHOS::Rosen::WMError;
constexpr int32_t MAX_WAIT_TIME = 10;
BlockQueue<uint32_t> PanelImpl::jobQueue_{ MAX_WAIT_TIME };
std::atomic<uint32_t> PanelImpl::jobId_{ 0 };

namespace {
bool PostPanelAdjustTask(std::function<void()> task)
{
    auto work = new (std::nothrow) std::function<void()>(std::move(task));
    if (work == nullptr) {
        IMSA_HILOGE("Failed to allocate panel adjustment task.");
        return false;
    }
    pthread_attr_t attributes;
    int32_t ret = pthread_attr_init(&attributes);
    if (ret != 0) {
        delete work;
        IMSA_HILOGE("Failed to initialize panel worker attributes: %{public}d", ret);
        return false;
    }
    ret = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    if (ret == 0) {
        pthread_t worker;
        ret = pthread_create(
            &worker, &attributes,
            [](void *data) {
                std::unique_ptr<std::function<void()>> work(static_cast<std::function<void()> *>(data));
                (*work)();
                return static_cast<void *>(nullptr);
            },
            work);
    }
    if (pthread_attr_destroy(&attributes) != 0) {
        IMSA_HILOGW("Failed to release panel worker attributes.");
    }
    if (ret != 0) {
        delete work;
        IMSA_HILOGE("Failed to start panel adjustment worker: %{public}d", ret);
        return false;
    }
    return true;
}
} // namespace

PanelImpl::JobGuard::JobGuard(int64_t id) : id_(id)
{
    ready_ = id >= 0 && id <= UINT32_MAX && jobQueue_.Wait(static_cast<uint32_t>(id));
    if (!ready_) {
        CancelJob(id);
        id_ = -1;
        IMSA_HILOGE("Panel task admission failed or wait timed out, id: %{public}" PRId64, id);
        set_business_error(IMFErrorCode::EXCEPTION_WINDOW_MANAGER,
            "Panel task was not accepted or timed out; the operation was not executed.");
    }
}

PanelImpl::JobGuard::~JobGuard()
{
    CancelJob(id_);
}

void PanelImpl::JobGuard::Finish()
{
    if (ready_) {
        jobQueue_.Pop(static_cast<uint32_t>(id_));
        ready_ = false;
        id_ = -1;
    }
}

PanelImpl::PanelImpl()
{
}

PanelImpl::~PanelImpl()
{
    inputMethodPanel_ = nullptr;
}

void PanelImpl::CreatePanel(uintptr_t ctx, PanelInfo_t const& info, std::shared_ptr<InputMethodPanel> &panel)
{
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr!");
        set_business_error(IMFErrorCode::EXCEPTION_IME,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_IME));
        return;
    }
    ani_object value = reinterpret_cast<ani_object>(ctx);
    if (value == nullptr) {
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        return;
    }
    std::shared_ptr<AbilityRuntime::Context> context = OHOS::AbilityRuntime::GetStageModeContext(env, value);
    if (context == nullptr) {
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        return;
    }
    PanelInfo panelInfo = CommonConvert::AniConvertPanelInfoToNative(info);
    auto ret = InputMethodAbility::GetInstance().CreatePanel(context, panelInfo, panel);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("CreatePanel failed, panelType: %{public}d, ret: %{public}d", panelInfo.panelType, ret);
        set_business_error(IMFErrorCode::EXCEPTION_IME,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_IME) + " Failed to create panel. Reuse or destroy any existing "
                "panel of this type before creating another. Check native logs for the creation failure reason.");
        return;
    }
    if (panel != nullptr) {
        inputMethodPanel_ = panel;
        IMSA_HILOGI("CreatePanel success!");
        return;
    }
    IMSA_HILOGE("CreatePanel failed, panel is nullptr!");
}

SystemPanelInsetsData_t PanelImpl::GetSystemPanelCurrentInsetsAsync(int64_t id, int64_t displayId)
{
    JobGuard job(id);
    if (!job.IsReady()) {
        return SystemPanelInsetsData_t::make_type_null();
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return SystemPanelInsetsData_t::make_type_null();
    }
    uint64_t tmpId = static_cast<uint64_t>(displayId);
    SystemPanelInsets insets = {0, 0, 0};
    auto code = inputMethodPanel_->GetSystemPanelCurrentInsets(tmpId, insets);
    job.Finish();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetSystemPanelCurrentInsets failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return SystemPanelInsetsData_t::make_type_null();
    }
    IMSA_HILOGI("GetSystemPanelCurrentInsets success!");
    SystemPanelInsets_t result = CommonConvert::NativeInsetsToAni(insets);
    return SystemPanelInsetsData_t::make_type_SystemPanelInsets(result);
}

void PanelImpl::SetSystemPanelButtonColorAsync(int64_t id, FillColorData_t const& fillColor,
    BackgroundColorData_t const& backgroundColor)
{
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    std::string tmpFillColor = "";
    std::string tmpBackgroundColor = "";
    auto fillResult = CommonConvert::AniFillColorDataToNative(fillColor, tmpFillColor);
    auto BackgroundResult = CommonConvert::AniBackgroundColorDataToNative(backgroundColor, tmpBackgroundColor);
    if (!fillResult || !BackgroundResult) {
        IMSA_HILOGE("fillColor or backgroundColor is empty!");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        job.Finish();
        return;
    }
    auto code = inputMethodPanel_->SetSystemPanelButtonColor(tmpFillColor, tmpBackgroundColor);
    job.Finish();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SetSystemPanelButtonColor failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("SetSystemPanelButtonColor success!");
}

void PanelImpl::SetShadow(double radius, ::taihe::string_view color, double offsetX, double offsetY)
{
    int64_t id = LineUp();
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    Shadow shadow = CommonConvert::AniConvertShadowToNative(radius, color, offsetX, offsetY);
    auto code = inputMethodPanel_->SetShadow(shadow);
    job.Finish();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("SetShadow failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("SetShadow success!");
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
    IMSA_HILOGD("flag: %{public}d, isEnhanced: %{public}d, isValid: %{public}d", panelFlag, isEnhancedCalled, isValid);
    if (!isEnhancedCalled && !isValid) {
        IMSA_HILOGE("invalid panelFlag!");
        return false;
    } else if (isEnhancedCalled && !isValid) {
        IMSA_HILOGE("invalid panelFlag for enhanced call!");
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
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    std::vector<Rosen::Rect> hotArea;
    if (!ParseUpdateRegionParam(hotArea, inputRegion)) {
        job.Finish();
        return;
    }
    int32_t code = inputMethodPanel_->UpdateRegion(hotArea);
    job.Finish();
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
    auto job = std::make_shared<JobGuard>(id);
    if (!job->IsReady()) {
        return;
    }
    LayoutParams layoutParams;
    if (!PrepareAdjustPanelRect(flag, rect, layoutParams)) {
        job->Finish();
        return;
    }
    std::weak_ptr<PanelImpl> weakThis = shared_from_this();
    auto task = [weakThis, job, panelFlag = static_cast<PanelFlag>(flag.get_value()), layoutParams]() {
        auto self = weakThis.lock();
        if (self == nullptr || self->inputMethodPanel_ == nullptr) {
            IMSA_HILOGW("Panel released before queued adjustment; cancelling this task.");
            return;
        }
        int32_t ret = self->inputMethodPanel_->AdjustPanelRect(panelFlag, layoutParams, true, true, false);
        job->Finish();
        if (ret != ErrorCode::NO_ERROR) {
            // This worker has no ANI environment or synchronous error channel.
            IMSA_HILOGE("Asynchronous panel adjustment failed: %{public}d", ret);
        }
    };
    if (!PostPanelAdjustTask(std::move(task))) {
        set_business_error(IMFErrorCode::EXCEPTION_WINDOW_MANAGER,
            "Failed to start the panel adjustment task; the operation was not executed.");
        return;
    }
    IMSA_HILOGI("AdjustPanelRect task posted to async thread");
}

void PanelImpl::AdjustPanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect)
{
    int64_t id = LineUp();
    auto job = std::make_shared<JobGuard>(id);
    if (!job->IsReady()) {
        return;
    }
    EnhancedLayoutParams enhancedLayoutParams;
    HotAreas hotAreas;
    if (!PrepareAdjustPanelRectEnhanced(flag, rect, enhancedLayoutParams, hotAreas)) {
        job->Finish();
        return;
    }
    std::weak_ptr<PanelImpl> weakThis = shared_from_this();
    auto task = [weakThis, job, panelFlag = static_cast<PanelFlag>(flag.get_value()), enhancedLayoutParams,
                    hotAreas]() {
        auto self = weakThis.lock();
        if (self == nullptr || self->inputMethodPanel_ == nullptr) {
            IMSA_HILOGW("Panel released before queued adjustment; cancelling this task.");
            return;
        }
        int32_t ret = self->inputMethodPanel_->AdjustPanelRect(panelFlag, enhancedLayoutParams, hotAreas,
            false);
        job->Finish();
        if (ret != ErrorCode::NO_ERROR) {
            // This worker has no ANI environment or synchronous error channel.
            IMSA_HILOGE("Asynchronous panel adjustment failed: %{public}d", ret);
        }
    };
    if (!PostPanelAdjustTask(std::move(task))) {
        set_business_error(IMFErrorCode::EXCEPTION_WINDOW_MANAGER,
            "Failed to start the panel adjustment task; the operation was not executed.");
        return;
    }
    IMSA_HILOGI("AdjustPanelRectEnhanced task posted to async thread");
}

void PanelImpl::UpdatePanelRect(PanelFlag_t flag, PanelRect_t const& rect)
{
    int64_t id = LineUp();
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    LayoutParams layoutParams;
    if (!PrepareAdjustPanelRect(flag, rect, layoutParams)) {
        job.Finish();
        return;
    }
    int32_t ret = inputMethodPanel_->AdjustPanelRect(static_cast<PanelFlag>(flag.get_value()), layoutParams, true,
        true, false);
    job.Finish();
    HandleAdjustPanelRectResult(ret);
}

void PanelImpl::UpdatePanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect)
{
    int64_t id = LineUp();
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    EnhancedLayoutParams enhancedLayoutParams;
    HotAreas hotAreas;
    if (!PrepareAdjustPanelRectEnhanced(flag, rect, enhancedLayoutParams, hotAreas)) {
        job.Finish();
        return;
    }
    int32_t ret = inputMethodPanel_->AdjustPanelRect(static_cast<PanelFlag>(flag.get_value()), enhancedLayoutParams,
        hotAreas, false);
    job.Finish();
    HandleAdjustPanelRectResult(ret);
}

bool PanelImpl::PrepareAdjustPanelRect(PanelFlag_t flag, PanelRect_t const& rect, LayoutParams& layoutParams)
{
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        return false;
    }
    PanelFlag panelFlag = static_cast<PanelFlag>(flag.get_value());
    if (!IsPanelFlagValid(panelFlag, false)) {
        IMSA_HILOGE("invalid panelFlag!");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        return false;
    }
    ani_env* env = taihe::get_env();
    if (!CommonConvert::ParsePanelRect(env, rect, layoutParams)) {
        IMSA_HILOGE("ParsePanelRect is failed!");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        return false;
    }
    return true;
}

bool PanelImpl::PrepareAdjustPanelRectEnhanced(PanelFlag_t flag, EnhancedPanelRect_t const& rect,
    EnhancedLayoutParams& enhancedLayoutParams, HotAreas& hotAreas)
{
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        return false;
    }
    PanelFlag panelFlag = static_cast<PanelFlag>(flag.get_value());
    if (!IsPanelFlagValid(panelFlag, true)) {
        IMSA_HILOGE("invalid panelFlag for enhanced call!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_INVALID_PANEL_FLAG),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_INVALID_PANEL_FLAG)));
        return false;
    }
    ani_env* env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr!");
        set_business_error(IMFErrorCode::EXCEPTION_IME, JsUtils::ToMessage(IMFErrorCode::EXCEPTION_IME));
        return false;
    }
    auto ret = CommonConvert::ParseEnhancedPanelRect(env, rect, enhancedLayoutParams, hotAreas);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("parse  EnhancedPanelRect failed");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return false;
    }
    ret = inputMethodPanel_->IsEnhancedParamValid(panelFlag, enhancedLayoutParams);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("IsEnhancedParamValid failed ret:%{public}d", ret);
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return false;
    }
    return true;
}

void PanelImpl::HandleAdjustPanelRectResult(int32_t ret)
{
    if (ret == ErrorCode::NO_ERROR) {
        IMSA_HILOGI("AdjustPanelRect success!");
    } else if (ret == ErrorCode::ERROR_PARAMETER_CHECK_FAILED) {
        IMSA_HILOGE("Invalid param");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
    } else {
        IMSA_HILOGE("AdjustPanelRect failed");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
    }
}

int64_t PanelImpl::GetDisplayIdSync(int64_t id)
{
    JobGuard job(id);
    if (!job.IsReady()) {
        return 0;
    }
    uint64_t displayId = 0;
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return static_cast<int64_t>(displayId);
    }
    auto ret = inputMethodPanel_->GetDisplayId(displayId);
    job.Finish();
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed get displayId!");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return static_cast<int64_t>(displayId);
    }
    if (displayId > UINT32_MAX) {
        IMSA_HILOGE("displayId is too large, displayId: %{public}" PRIu64 "", displayId);
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_WINDOW_MANAGER),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_WINDOW_MANAGER)));
        return static_cast<int64_t>(displayId);
    }
    IMSA_HILOGI("get displayId success!");
    return static_cast<int64_t>(displayId);
}

ImmersiveMode_t PanelImpl::GetImmersiveMode()
{
    int64_t id = LineUp();
    JobGuard job(id);
    if (!job.IsReady()) {
        return CommonConvert::ConvertMode(ImmersiveMode::NONE_IMMERSIVE);
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return CommonConvert::ConvertMode(ImmersiveMode::NONE_IMMERSIVE);
    }
    auto immersiveMode = inputMethodPanel_->GetImmersiveMode();
    job.Finish();
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
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    ImmersiveMode immersiveMode = static_cast<ImmersiveMode>(mode.get_value());
    if (!IsVaildImmersiveMode(immersiveMode)) {
        IMSA_HILOGE("immersiveMode type must be ImmersiveMode and can not be IMMERSIVE");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK,
            JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        job.Finish();
        return;
    }
    auto ret = inputMethodPanel_->SetImmersiveMode(immersiveMode);
    job.Finish();
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
        int32_t code = ret == ErrorCode::ERROR_IME ? ret : ErrorCode::ERROR_WINDOW_MANAGER;
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
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
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    auto code = inputMethodPanel_->MoveTo(x, y);
    job.Finish();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("moveTo failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("moveTo success!");
}

void PanelImpl::ResizeAsync(int64_t id, int64_t width, int64_t height)
{
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    auto code = inputMethodPanel_->Resize(static_cast<uint32_t>(width), static_cast<uint32_t>(height));
    job.Finish();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("Resize failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGE("Resize success!");
}

void PanelImpl::SetUiContent(int64_t id, taihe::string_view path, ani_object storage)
{
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    std::string contentInfo = std::string(path);
    auto code = inputMethodPanel_->SetUiContentAni(contentInfo, env, storage);
    job.Finish();
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
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    auto code = InputMethodAbility::GetInstance().HidePanel(inputMethodPanel_);
    job.Finish();
    if (code != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("Hide failed!");
        set_business_error(JsUtils::Convert(code), JsUtils::ToMessage(JsUtils::Convert(code)));
        return;
    }
    IMSA_HILOGI("Hide success!");
}

void PanelImpl::ShowAsync(int64_t id)
{
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    auto code = InputMethodAbility::GetInstance().ShowPanel(inputMethodPanel_);
    job.Finish();
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
    JobGuard job(id);
    if (!job.IsReady()) {
        return;
    }
    if (inputMethodPanel_ == nullptr) {
        IMSA_HILOGE("panel is nullptr!");
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_IME)));
        job.Finish();
        return;
    }
    ImmersiveEffect result = CommonConvert::AniConvertEffectToNative(effect);
    auto code = inputMethodPanel_->SetImmersiveEffect(result);
    job.Finish();
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
    IMSA_HILOGD("UnRegisterListener type: %{public}s.", type.c_str());
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

void PanelImpl::CancelJob(int64_t id)
{
    if (id >= 0 && id <= UINT32_MAX) {
        jobQueue_.Remove(static_cast<uint32_t>(id));
    }
}

int64_t PanelImpl::LineUp()
{
    uint32_t id = ++jobId_;
    if (!jobQueue_.Push(id)) {
        IMSA_HILOGE("Panel task queue is full; task %{public}u was not enqueued.", id);
        return -1;
    }
    return static_cast<int64_t>(id);
}

IMFPanelImpl::~IMFPanelImpl()
{
    value_ = nullptr;
    panelImpl_ = nullptr;
}

void IMFPanelImpl::ReleaseNative()
{
    value_ = nullptr;
    panelImpl_ = nullptr;
}
} // namespace MiscServices
} // namespace OHOS
