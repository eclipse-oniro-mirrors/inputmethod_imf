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

#include "cj_inputmethod_extension.h"
#include "ability_handler.h"
#include "configuration_utils.h"
#include "display_info.h"
#include "global.h"
#include "inputmethod_extension_ability_service_impl.h"
#include "inputmethod_trace.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "task_manager.h"
#include "tasks/task_ams.h"
#include "tasks/task_imsa.h"
#include "parameters.h"

namespace OHOS {
namespace AbilityRuntime {

CjInputMethodExtension *CjInputMethodExtension::cjInputMethodExtension = nullptr;
using namespace OHOS::AppExecFwk;
using namespace OHOS::MiscServices;

constexpr int32_t SUCCESS_CODE = 0;

extern "C" __attribute__((visibility("default"))) InputMethodExtension *OHOS_ABILITY_CjInputMethodExtension()
{
    return new (std::nothrow) CjInputMethodExtension();
}

CjInputMethodExtension::CjInputMethodExtension() { }

CjInputMethodExtension::~CjInputMethodExtension()
{
    IMSA_HILOGD("~CjInputMethodExtension");
    auto context = GetContext();
    if (context != nullptr) {
        context->Unbind();
    }
    cjObj_.Destroy();
}

void CjInputMethodExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    IMSA_HILOGD("initalize CjInputMethodExtension");
    InputMethodExtension::Init(record, application, handler, token);
    // init and bindContext
    int32_t ret = cjObj_.Init(abilityInfo_->name, this);
    if (ret != SUCCESS_CODE) {
        IMSA_HILOGE("initalization failed");
        return;
    }
    handler_ = handler;
    ListenWindowManager();
    IMSA_HILOGI("initalize success");
}

void CjInputMethodExtension::ListenWindowManager()
{
    IMSA_HILOGD("register window manager service listener.");
    displayListener_ = sptr<InputMethodDisplayAttributeListener>::MakeSptr(GetContext());
    if (displayListener_ == nullptr) {
        IMSA_HILOGE("failed to create display listener!");
        return;
    }
    std::vector<std::string> attributes = {"rotation", "width", "height"};
    Rosen::DisplayManager::GetInstance().RegisterDisplayAttributeListener(attributes, displayListener_);
}

void CjInputMethodExtension::OnStart(const AAFwk::Want &want)
{
    auto task = std::make_shared<TaskAmsInit>();
    TaskManager::GetInstance().PostTask(task);
    InputMethodAbility::GetInstance().InitConnect();
    StartAsync("OnStart", static_cast<int32_t>(TraceTaskId::ONSTART_EXTENSION));
    StartAsync("Extension::OnStart", static_cast<int32_t>(TraceTaskId::ONSTART_MIDDLE_EXTENSION));
    Extension::OnStart(want);
    FinishAsync("Extension::OnStart", static_cast<int32_t>(TraceTaskId::ONSTART_MIDDLE_EXTENSION));
    IMSA_HILOGI("CjInputMethodExtension OnStart begin.");
    StartAsync("onCreate", static_cast<int32_t>(TraceTaskId::ONCREATE_EXTENSION));
    cjObj_.OnCreate(want);
    FinishAsync("onCreate", static_cast<int32_t>(TraceTaskId::ONCREATE_EXTENSION));
    TaskManager::GetInstance().PostTask(std::make_shared<TaskImsaSetCoreAndAgent>());
    IMSA_HILOGI("ime bind imf");
    FinishAsync("OnStart", static_cast<int32_t>(TraceTaskId::ONSTART_EXTENSION));
    TaskManager::GetInstance().Complete(task->GetSeqId());
}

void CjInputMethodExtension::OnStop()
{
    InputMethodExtension::OnStop();
    IMSA_HILOGI("CjInputMethodExtension OnStop start.");
    cjObj_.OnDestroy();
    auto context = GetContext();
    if (context == nullptr) {
        IMSA_HILOGE("context is invalid!");
        return;
    }
    bool ret = ConnectionManager::GetInstance().DisconnectCaller(context->GetToken());
    if (ret) {
        IMSA_HILOGI("the input method extension connection is not disconnected.");
    }
    IMSA_HILOGI("CjInputMethodExtension OnStop end.");
}

sptr<IRemoteObject> CjInputMethodExtension::OnConnect(const AAFwk::Want &want)
{
    IMSA_HILOGI("CjInputMethodExtension OnConnect start.");
    Extension::OnConnect(want);
    auto remoteObj = new (std::nothrow) InputMethodExtensionAbilityServiceImpl();
    if (remoteObj == nullptr) {
        IMSA_HILOGE("failed to create InputMethodExtensionAbilityServiceImpl!");
        return nullptr;
    }
    return remoteObj;
}

void CjInputMethodExtension::OnDisconnect(const AAFwk::Want &want) { }

void CjInputMethodExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId) { }
} // namespace AbilityRuntime
} // namespace OHOS
