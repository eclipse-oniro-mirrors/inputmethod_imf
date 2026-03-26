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

#include "input_client_service_impl.h"

#include "input_client_stub.h"
#include "ime_event_monitor_manager_impl.h"
#include "input_method_controller.h"

namespace OHOS {
namespace MiscServices {

InputClientServiceImpl::InputClientServiceImpl() {}

InputClientServiceImpl::~InputClientServiceImpl() {}

ErrCode InputClientServiceImpl::OnInputReady(const sptr<IRemoteObject> &agent, const BindImeInfo &imeInfo)
{
    IMSA_HILOGI("ClientStub start.");
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        instance->OnInputReady(agent, imeInfo);
    } else {
        IMSA_HILOGW("failed to get InputMethodController instance!");
    }
    return ERR_OK;
}
// LCOV_EXCL_START
ErrCode InputClientServiceImpl::OnInputStop(
    bool isStopInactiveClient, const sptr<IRemoteObject> &object, bool isSendKeyboardStatus)
{
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        instance->OnInputStop(isStopInactiveClient, object, isSendKeyboardStatus);
    } else {
        IMSA_HILOGW("failed to get InputMethodController instance!");
    }
    return ERR_OK;
}
// LCOV_EXCL_STOP
ErrCode InputClientServiceImpl::OnInputStopAsync(bool isStopInactiveClient, bool isSendKeyboardStatus)
{
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        instance->OnInputStop(isStopInactiveClient, nullptr, isSendKeyboardStatus);
    } else {
        IMSA_HILOGW("failed to get InputMethodController instance!");
    }
    return ERR_OK;
}
// LCOV_EXCL_START
ErrCode InputClientServiceImpl::OnImeMirrorStop(const sptr<IRemoteObject> &object)
{
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        instance->OnImeMirrorStop(object);
    } else {
        IMSA_HILOGW("[ImeMirrorTag]failed to get InputMethodController instance!");
    }
    return ERR_OK;
}
// LCOV_EXCL_STOP
ErrCode InputClientServiceImpl::OnSwitchInput(const Property &property, const SubProperty &subProperty, int32_t userId)
{
    return ImeEventMonitorManagerImpl::GetInstance().OnImeChange(property, subProperty, userId);
}

ErrCode InputClientServiceImpl::OnPanelStatusChange(const ImeWindowInfo &oldInfo, const ImeWindowInfo &newInfo)
{
    return ImeEventMonitorManagerImpl::GetInstance().OnPanelStatusChange(oldInfo, newInfo);
}

ErrCode InputClientServiceImpl::NotifyInputStart(const InputStartInfo &inputStartInfo)
{
    return ImeEventMonitorManagerImpl::GetInstance().OnInputStart(inputStartInfo);
}

ErrCode InputClientServiceImpl::NotifyInputStop(const InputStopInfo &inputStopInfo)
{
    return ImeEventMonitorManagerImpl::GetInstance().OnInputStop(inputStopInfo);
}

ErrCode InputClientServiceImpl::DeactivateClient()
{
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        instance->DeactivateClient();
    } else {
        IMSA_HILOGW("failed to get InputMethodController instance!");
    }
    return ERR_OK;
}
}  // namespace MiscServices
}  // namespace OHOS