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
#ifndef TAIHE_INPUT_METHOD_ABILITY_IMPL_H
#define TAIHE_INPUT_METHOD_ABILITY_IMPL_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ani_common_engine.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "ohos.inputMethodEngine.InputMethodAbility.ani.1.hpp"
#include "input_method_engine_listener.h"
#include "input_method_panel_impl.h"

namespace OHOS {
namespace MiscServices {
class InputMethodAbilityImpl : public InputMethodEngineListener {
public:
    static std::shared_ptr<InputMethodAbilityImpl> GetInstance();
    SecurityMode_t GetSecurityMode();
    void DestroyPanelAsync(Panel_t panel);
    void RegisterListener(std::string const &type, callbackTypes &&cb, uintptr_t opq);
    void UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq);
    void OnKeyboardStatus(bool isShow) override;
    void OnInputStart() override;
    int32_t OnInputStop() override;
    int32_t OnDiscardTypingText() override;
    void OnSecurityChange(int32_t security) override;
    void OnSetCallingWindow(uint32_t windowId) override;
    void OnSetSubtype(const SubProperty &property) override;
    void OnCallingDisplayIdChanged(uint64_t callingDisplayId) override;
    void ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) override;

private:
    static ani_vm* GetAniVm(ani_env* env);
    static ani_env* GetAniEnv(ani_vm* vm);
    static ani_env* AttachAniEnv(ani_vm* vm);
    std::mutex mutex_;
    std::map<std::string, std::vector<std::unique_ptr<CallbackObjects>>> jsCbMap_;
    static std::mutex engineMutex_;
    static std::shared_ptr<InputMethodAbilityImpl> inputMethodEngine_;
    static ani_env* env_;
    static ani_vm* vm_;
};

class IMFAbilityImpl {
public:
    IMFAbilityImpl()
    {
        InputMethodAbility::GetInstance().SetImeListener(InputMethodAbilityImpl::GetInstance());
    }

    SecurityMode_t GetSecurityMode()
    {
        return InputMethodAbilityImpl::GetInstance()->GetSecurityMode();
    }

    ohos::inputMethodEngine::Panel CreatePanelAsync(uintptr_t ctx, PanelInfo_t const& info)
    {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return taihe::make_holder<IMFPanelImpl, ohos::inputMethodEngine::Panel>(ctx, info);
    }

    void DestroyPanelAsync(ohos::inputMethodEngine::weak::Panel panel)
    {
        InputMethodAbilityImpl::GetInstance()->DestroyPanelAsync(panel);
    }

    void OnInputStart(taihe::callback_view<void(KeyboardController_t, InputClient_t)> callback, uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("inputStart", callback, opq);
    }

    void OffInputStart(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("inputStart", opq);
    }

    void OnInputStop(taihe::callback_view<void(UndefinedType_t const&)> callback, uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("inputStop", callback, opq);
    }

    void OffInputStop(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("inputStop", opq);
    }

    void OnSetCallingWindow(taihe::callback_view<void(int32_t)> callback, uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("setCallingWindow", callback, opq);
    }

    void OffSetCallingWindow(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("setCallingWindow", opq);
    }

    void OnKeyboardShow(taihe::callback_view<void(UndefinedType_t const&)> callback, uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("keyboardShow", callback, opq);
    }

    void OffKeyboardShow(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("keyboardShow", opq);
    }

    void OnKeyboardHide(taihe::callback_view<void(UndefinedType_t const&)> callback, uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("keyboardHide", callback, opq);
    }

    void OffKeyboardHide(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("keyboardHide", opq);
    }

    void OnSetSubtype(taihe::callback_view<void(InputMethodSubtype_t const&)> callback, uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("setSubtype", callback, opq);
    }

    void OffSetSubtype(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("setSubtype", opq);
    }

    void OnSecurityModeChange(taihe::callback_view<void(SecurityMode_t)> callback, uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("securityModeChange", callback, opq);
    }

    void OffSecurityModeChange(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("securityModeChange", opq);
    }

    void OnPrivateCommand(taihe::callback_view<void(taihe::map_view<taihe::string, CommandDataType_t>)> callback,
        uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("privateCommand", callback, opq);
    }

    void OffPrivateCommand(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("privateCommand", opq);
    }

    void OnCallingDisplayDidChange(taihe::callback_view<void(int32_t)> callback, uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("callingDisplayDidChange", callback, opq);
    }

    void OffCallingDisplayDidChange(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("callingDisplayDidChange", opq);
    }

    void OnDiscardTypingText(taihe::callback_view<void(UndefinedType_t const&)> callback, uintptr_t opq)
    {
        InputMethodAbilityImpl::GetInstance()->RegisterListener("discardTypingText", callback, opq);
    }

    void OffDiscardTypingText(taihe::optional_view<uintptr_t> opq)
    {
        InputMethodAbilityImpl::GetInstance()->UnRegisterListener("discardTypingText", opq);
    }
};
class InputClientImpl;
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_INPUT_METHOD_ABILITY_IMPL_H