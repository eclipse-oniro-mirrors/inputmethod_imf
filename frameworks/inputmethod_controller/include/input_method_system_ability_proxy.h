/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_METHOD_SYSTEM_ABILITY_PROXY_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_METHOD_SYSTEM_ABILITY_PROXY_H

#include <cstdint>
#include <functional>
#include <vector>

#include <string>
#include "global.h"
#include "i_input_method_system_ability.h"
#include "input_attribute.h"
#include "input_client_stub.h"
#include "input_data_channel_stub.h"
#include "input_method_property.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "keyboard_type.h"
#include "message_parcel.h"
#include "nocopyable.h"
#include "refbase.h"

namespace OHOS {
namespace MiscServices {
    class InputDataChannelStub;
    class InputMethodSystemAbilityProxy : public IRemoteProxy<IInputMethodSystemAbility> {
    public:
        explicit InputMethodSystemAbilityProxy(const sptr<IRemoteObject> &object);
        ~InputMethodSystemAbilityProxy() = default;
        DISALLOW_COPY_AND_MOVE(InputMethodSystemAbilityProxy);

        void prepareInput(MessageParcel& data) override;
        void releaseInput(MessageParcel& data) override;
        void startInput(MessageParcel& data) override;
        void stopInput(MessageParcel& data) override;
        void SetCoreAndAgent(MessageParcel& data) override;
        int32_t HideCurrentInput(MessageParcel& data) override;
        int32_t ShowCurrentInput(MessageParcel& data) override;

        int32_t Prepare(int32_t displayId, sptr<InputClientStub> &client, sptr<InputDataChannelStub> &channel,
                        InputAttribute &attribute);
        int32_t Release(sptr<InputClientStub> &client);
        int32_t Start(sptr<InputClientStub> &client);
        int32_t Stop(sptr<InputClientStub> &client);

        int32_t displayOptionalInputMethod(MessageParcel& data) override;
        int32_t getDisplayMode(int32_t &retMode) override;
        int32_t getKeyboardWindowHeight(int32_t &retHeight) override;
        int32_t GetCurrentInputMethod(InputMethodProperty *currentInputMethod) override;
        int32_t getCurrentKeyboardType(KeyboardType *retType) override;
        int32_t listInputMethodEnabled(std::vector<InputMethodProperty*> *properties) override;
        int32_t listInputMethod(std::vector<InputMethodProperty*> *properties) override;
        int32_t listKeyboardType(const std::u16string& imeId, std::vector<KeyboardType*> *types) override;
        int32_t SwitchInputMethod(const InputMethodProperty &target);

    private:
        static inline BrokerDelegator<InputMethodSystemAbilityProxy> delegator_;
    };
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_METHOD_SYSTEM_ABILITY_PROXY_H
