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
#include "input_method_ability_impl.h"
#include "input_method_panel_impl.h"
#include "input_method_keyboard_delegate_impl.h"
#include "input_method_client_impl.h"
#include "input_client_impl.h"
#include "js_utils.h"
#include "event_checker.h"
#include "keyboard_controller_impl.h"

namespace OHOS {
namespace MiscServices {
using namespace taihe;
std::mutex InputMethodAbilityImpl::engineMutex_;
std::shared_ptr<InputMethodAbilityImpl> InputMethodAbilityImpl::inputMethodEngine_ {nullptr};
ani_env* InputMethodAbilityImpl::env_ {nullptr};
ani_vm* InputMethodAbilityImpl::vm_ {nullptr};

ani_vm* InputMethodAbilityImpl::GetAniVm(ani_env* env)
{
    ani_vm* vm = nullptr;
    if (env->GetVM(&vm) != ANI_OK) {
        IMSA_HILOGE("GetVM failed");
        return nullptr;
    }
    return vm;
}

ani_env* InputMethodAbilityImpl::GetAniEnv(ani_vm* vm)
{
    ani_env* env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        IMSA_HILOGE("GetEnv failed");
        return nullptr;
    }
    return env;
}

ani_env* InputMethodAbilityImpl::AttachAniEnv(ani_vm* vm)
{
    ani_env *workerEnv = nullptr;
    ani_options aniArgs {0, nullptr};
    if (vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &workerEnv) != ANI_OK) {
        IMSA_HILOGE("Attach Env failed");
        return nullptr;
    }
    return workerEnv;
}

std::shared_ptr<InputMethodAbilityImpl> InputMethodAbilityImpl::GetInstance()
{
    if (inputMethodEngine_ == nullptr) {
        std::lock_guard<std::mutex> lock(engineMutex_);
        if (inputMethodEngine_ == nullptr) {
            auto engine = std::make_shared<InputMethodAbilityImpl>();
            if (engine == nullptr) {
                IMSA_HILOGE("create engine failed!");
                return nullptr;
            }
            inputMethodEngine_ = engine;
        }
    }
    return inputMethodEngine_;
}

SecurityMode_t InputMethodAbilityImpl::GetSecurityMode()
{
    int32_t security = 0;
    int32_t ret = InputMethodAbility::GetInstance().GetSecurityMode(security);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to get security mode");
        set_business_error(JsUtils::Convert(ret), JsUtils::ToMessage(JsUtils::Convert(ret)));
        return CommonConvert::ConvertSecurityMode(static_cast<SecurityMode>(security));
    }
    IMSA_HILOGI("GetSecurityMode success!");
    return CommonConvert::ConvertSecurityMode(static_cast<SecurityMode>(security));
}

void InputMethodAbilityImpl::DestroyPanelAsync(Panel_t panel)
{
    IMFPanelImpl* panelImpl = reinterpret_cast<IMFPanelImpl*>(panel->GetImplPtr());
    if (panelImpl == nullptr) {
        IMSA_HILOGE("Failed to unwrap IMFPanelImpl");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        return;
    }
    auto panelNative = panelImpl->GetNativePtr();
    if (panelNative == nullptr) {
        IMSA_HILOGE("get panelNative failed");
        set_business_error(IMFErrorCode::EXCEPTION_PARAMCHECK, JsUtils::ToMessage(IMFErrorCode::EXCEPTION_PARAMCHECK));
        return;
    }
    auto errCode = InputMethodAbility::GetInstance().DestroyPanel(panelNative);
    if (errCode != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("DestroyPanel failed, errCode: %{public}d!", errCode);
        set_business_error(JsUtils::Convert(errCode), JsUtils::ToMessage(JsUtils::Convert(errCode)));
        return;
    }
    IMSA_HILOGI("DestroyPanel success!");
}

void InputMethodAbilityImpl::RegisterListener(std::string const &type, callbackTypes &&cb, uintptr_t opq)
{
    if (!EventChecker::IsValidEventType(EventSubscribeModule::INPUT_METHOD_ABILITY, type)) {
        IMSA_HILOGE("subscribe failed, type: %{public}s.", type.c_str());
        return;
    }
    if (type == "privateCommand" && !InputMethodAbility::GetInstance().IsDefaultIme()) {
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_NOT_DEFAULT_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_NOT_DEFAULT_IME)));
        return;
    }
#ifndef SCENE_BOARD_ENABLE
    if (type == "callingDisplayDidChange") {
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_DEVICE_UNSUPPORTED),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_DEVICE_UNSUPPORTED)));
        return;
    }
#endif
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        IMSA_HILOGE("Failed to register %{public}s", type.c_str());
        return;
    }
    env_ = env;
    vm_ = GetAniVm(env);
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    bool isDuplicate =
        std::any_of(cbVec.begin(), cbVec.end(), [env, callbackRef](std::unique_ptr<CallbackObjects> &obj) {
            ani_boolean isEqual = false;
            return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
        });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        IMSA_HILOGD("%{public}s is already registered", type.c_str());
        return;
    }
    cbVec.emplace_back(std::make_unique<CallbackObjects>(cb, callbackRef));
    IMSA_HILOGI("Registered success type: %{public}s", type.c_str());
}

void InputMethodAbilityImpl::UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq)
{
    if (!EventChecker::IsValidEventType(EventSubscribeModule::INPUT_METHOD_ABILITY, type)) {
        IMSA_HILOGE("subscribe failed, type: %{public}s.", type.c_str());
        return;
    }
    if (type == "privateCommand" && !InputMethodAbility::GetInstance().IsDefaultIme()) {
        set_business_error(JsUtils::Convert(ErrorCode::ERROR_NOT_DEFAULT_IME),
            JsUtils::ToMessage(JsUtils::Convert(ErrorCode::ERROR_NOT_DEFAULT_IME)));
        return;
    }

    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        IMSA_HILOGE("Failed to unregister %{public}s, env is nullptr", type.c_str());
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto iter = jsCbMap_.find(type);
    if (iter == jsCbMap_.end()) {
        IMSA_HILOGE("%{public}s is not registered", type.c_str());
        return;
    }

    if (!opq.has_value()) {
        jsCbMap_.erase(iter);
        return;
    }

    GlobalRefGuards guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        IMSA_HILOGE("Failed to unregister %{public}s, GlobalRefGuard is false!", type.c_str());
        return;
    }

    const auto pred = [env, targetRef = guard.get()](std::unique_ptr<CallbackObjects> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        callbacks.erase(it);
    }
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
    }
}

void InputMethodAbilityImpl::OnKeyboardStatus(bool isShow)
{
    std::string type = isShow ? "keyboardShow" : "keyboardHide";
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_[type];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void()>>(cb->callback);
        func();
    }
}

void InputMethodAbilityImpl::OnInputStart()
{
    IMSA_HILOGI("OnInputStart start.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (vm_ == nullptr) {
        IMSA_HILOGE("vm_ is nullptr");
        return;
    }
    ani_env *env = AttachAniEnv(vm_);
    if (env == nullptr) {
        IMSA_HILOGE("get env is nullptr");
        return;
    }
    auto &cbVec = jsCbMap_["inputStart"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(KeyboardController_t, InputClient_t)>>(cb->callback);
        auto keyBoardController = make_holder<KeyboardControllerImpl, ohos::inputMethodEngine::KeyboardController>();
        auto textInput = make_holder<InputClientImpl, ohos::inputMethodEngine::InputClient>();
        func(std::forward<KeyboardController_t>(keyBoardController), std::forward<InputClient_t>(textInput));
    }
    if (vm_->DetachCurrentThread() != ANI_OK) {
        IMSA_HILOGE("DetachCurrentThread failed");
        return;
    }
}

int32_t InputMethodAbilityImpl::OnInputStop()
{
    IMSA_HILOGI("OnInputStop start.");
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["inputStop"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void()>>(cb->callback);
        func();
    }
    return 0;
}

int32_t InputMethodAbilityImpl::OnDiscardTypingText()
{
    IMSA_HILOGI("DiscardTypingText start.");
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["discardTypingText"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void()>>(cb->callback);
        func();
    }
    return 0;
}

void InputMethodAbilityImpl::OnSecurityChange(int32_t security)
{
    IMSA_HILOGI("OnSecurityChange start.");
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["securityModeChange"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(SecurityMode_t)>>(cb->callback);
        SecurityMode_t modeType = CommonConvert::ConvertSecurityMode(static_cast<SecurityMode>(security));
        func(modeType);
    }
}

void InputMethodAbilityImpl::OnSetCallingWindow(uint32_t windowId)
{
    IMSA_HILOGI("OnSetCallingWindow start.");
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["setCallingWindow"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(int32_t)>>(cb->callback);
        int32_t wid = static_cast<int32_t>(windowId);
        func(wid);
    }
}

void InputMethodAbilityImpl::OnSetSubtype(const SubProperty &property)
{
    IMSA_HILOGI("OnSetSubtype start.");
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["setSubtype"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(InputMethodSubtype_t const&)>>(cb->callback);
        func(TaiheConverter::ConvertSubProperty(property));
    }
}

void InputMethodAbilityImpl::OnCallingDisplayIdChanged(uint64_t callingDisplayId)
{
    IMSA_HILOGI("OnCallingDisplayIdChanged start.");
    if (callingDisplayId > UINT32_MAX) {
        IMSA_HILOGE("callingDisplayId over range!");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["callingDisplayDidChange"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(int32_t)>>(cb->callback);
        func(static_cast<int32_t>(callingDisplayId));
    }
}

void InputMethodAbilityImpl::ReceivePrivateCommand(
    const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    IMSA_HILOGD("start.");
    std::lock_guard<std::mutex> lock(mutex_);
    auto &cbVec = jsCbMap_["privateCommand"];
    for (auto &cb : cbVec) {
        auto &func = std::get<taihe::callback<void(taihe::map_view<taihe::string, CommandDataType_t>)>>(cb->callback);
        func(CommonConvert::NativeConvertPCommandToAni(privateCommand));
    }
}

} // namespace MiscServices
} // namespace OHOS