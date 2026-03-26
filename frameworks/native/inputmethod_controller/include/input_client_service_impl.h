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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_CLIENT_IMPL_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_CLIENT_IMPL_H

#include "iinput_client.h"
#include "input_client_stub.h"
#include "input_method_utils.h"
#include "input_window_info.h"
#include "iremote_object.h"
#include "notify_service_impl.h"
#include "on_input_stop_notify_proxy.h"

namespace OHOS {
namespace MiscServices {
class InputClientServiceImpl final : public InputClientStub,
    public std::enable_shared_from_this<InputClientServiceImpl> {
    DISALLOW_COPY_AND_MOVE(InputClientServiceImpl);

public:
    InputClientServiceImpl();
    ~InputClientServiceImpl();
    ErrCode OnInputReady(const sptr<IRemoteObject> &agent, const BindImeInfo &imeInfo) override;
    ErrCode OnInputStop(
        bool isStopInactiveClient, const sptr<IRemoteObject> &object, bool isSendKeyboardStatus) override;
    ErrCode OnInputStopAsync(bool isStopInactiveClient, bool isSendKeyboardStatus) override;
    ErrCode OnSwitchInput(const Property& property, const SubProperty& subProperty, int32_t userId) override;
    ErrCode OnPanelStatusChange(const ImeWindowInfo &oldInfo, const ImeWindowInfo &newInfo) override;
    ErrCode NotifyInputStart(const InputStartInfo &inputStartInfo) override;
    ErrCode NotifyInputStop(const InputStopInfo &inputStopInfo) override;
    ErrCode DeactivateClient() override;
    ErrCode OnImeMirrorStop(const sptr<IRemoteObject> &object) override;
};
}  // namespace MiscServices
}  // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_CLIENT_IMPL_H