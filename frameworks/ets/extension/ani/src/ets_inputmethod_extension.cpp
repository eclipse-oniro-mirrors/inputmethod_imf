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
#include "ets_inputmethod_extension.h"
#include "global.h"
#include "tasks/task_ams.h"
#include "tasks/task_imsa.h"
#include "task_manager.h"
#include "configuration_utils.h"
#include "input_method_ability.h"
#include "inputmethod_extension_ability_service_impl.h"
#include "inputmethod_trace.h"
#include "ets_inputmethod_extension_context.h"
#include "ani_common_configuration.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ets_runtime.h"
#include "ets_extension_context.h"
#include "ets_inputmethod_extension_loader.h"

namespace OHOS {
namespace MiscServices {
using namespace AbilityRuntime;
AbilityRuntime::InputMethodExtension *OHOS_ABILITY_ETSInputMethodExtension(
    const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    if (runtime == nullptr) {
        IMSA_HILOGI("runtime null");
        return nullptr;
    }
    return new ETSInputMethodExtension(static_cast<ETSRuntime &>(*runtime));
}

ETSInputMethodExtension *ETSInputMethodExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    if (runtime == nullptr) {
        IMSA_HILOGI("runtime null");
        return nullptr;
    }
    IMSA_HILOGI("call___%{public}d", runtime->GetLanguage());
    return new ETSInputMethodExtension(static_cast<ETSRuntime &>(*runtime));
}

ETSInputMethodExtension::ETSInputMethodExtension(ETSRuntime &etsRuntime) : etsRuntime_(etsRuntime) {}

ETSInputMethodExtension::~ETSInputMethodExtension()
{
    IMSA_HILOGI("destructor");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        IMSA_HILOGI("env null");
        return;
    }
    if (etsAbilityObj_ == nullptr) {
        IMSA_HILOGI("etsAbilityObj_ null");
        return;
    }
    if (etsAbilityObj_->aniRef) {
        env->GlobalReference_Delete(etsAbilityObj_->aniRef);
    }
}

void ETSInputMethodExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    IMSA_HILOGI("Init call");
    if (record == nullptr) {
        IMSA_HILOGI("null localAbilityRecord");
        return;
    }
    auto abilityInfo = record->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        IMSA_HILOGI("null abilityInfo");
        return;
    }
    AbilityRuntime::InputMethodExtension::Init(record, application, handler, token);

    std::string srcPath;
    GetSrcPath(srcPath);
    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    IMSA_HILOGD("moduleName:%{public}s,srcPath:%{public}s, compileMode :%{public}d",
        moduleName.c_str(), srcPath.c_str(), abilityInfo_->compileMode);

    BindContext(abilityInfo, record->GetWant(), moduleName, srcPath);
    handler_ = handler;
    InitDisplayCache();
    ListenWindowManager();
    IMSA_HILOGI("Init End");
}

void ETSInputMethodExtension::InitDisplayCache()
{
    auto foldStatus = Rosen::DisplayManager::GetInstance().GetFoldStatus();
    auto displayPtr = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    if (displayPtr == nullptr) {
        IMSA_HILOGE("displayPtr is null");
        return;
    }
    cacheDisplay_.SetCacheDisplay(
        displayPtr->GetWidth(), displayPtr->GetHeight(), displayPtr->GetRotation(), foldStatus);
}

void ETSInputMethodExtension::GetSrcPath(std::string &srcPath)
{
    if (!Extension::abilityInfo_->isModuleJson) {
        srcPath.append(Extension::abilityInfo_->package);
        srcPath.append("/assets/js/");
        if (!Extension::abilityInfo_->srcPath.empty()) {
            srcPath.append(Extension::abilityInfo_->srcPath);
        }
        srcPath.append("/").append(Extension::abilityInfo_->name).append(".abc");
        return;
    }

    if (!Extension::abilityInfo_->srcEntrance.empty()) {
        srcPath.append(Extension::abilityInfo_->moduleName + "/");
        srcPath.append(Extension::abilityInfo_->srcEntrance);
        auto pos = srcPath.rfind(".");
        if (pos != std::string::npos) {
            srcPath.erase(pos);
            srcPath.append(".abc");
        }
    }
}

void ETSInputMethodExtension::UpdateInputMethodExtensionObj(
    std::shared_ptr<AbilityRuntime::AbilityInfo> &abilityInfo,
    const std::string &moduleName, const std::string &srcPath)
{
    IMSA_HILOGI("UpdateInputMethodExtensionObj call");
    etsAbilityObj_ = etsRuntime_.LoadModule(moduleName, srcPath, abilityInfo->hapPath,
        abilityInfo->compileMode == AppExecFwk::CompileMode::ES_MODULE, false, abilityInfo_->srcEntrance);
    if (etsAbilityObj_ == nullptr) {
        IMSA_HILOGI("null etsAbilityObj_");
        return;
    }
    IMSA_HILOGI("UpdateInputMethodExtensionObj End");
}

void ETSInputMethodExtension::BindContext(std::shared_ptr<AbilityRuntime::AbilityInfo> &abilityInfo,
    std::shared_ptr<AAFwk::Want> want, const std::string &moduleName, const std::string &srcPath)
{
    IMSA_HILOGI("BindContext call");
    UpdateInputMethodExtensionObj(abilityInfo, moduleName, srcPath);

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        IMSA_HILOGI("env null");
        return;
    }
    if (etsAbilityObj_ == nullptr || want == nullptr) {
        IMSA_HILOGI("etsAbilityObj_ or abilityContext_ or want is null");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        IMSA_HILOGI("get context error");
        return;
    }
    ani_ref contextObj = CreateETSInputMethodExtensionContext(env, context);
    if (contextObj == nullptr) {
        IMSA_HILOGI("Create context obj error");
        return;
    }

    ani_ref contextGlobalRef = nullptr;
    ani_field field = nullptr;
    ani_status status = ANI_ERROR;

    if ((status = env->GlobalReference_Create(contextObj, &contextGlobalRef)) != ANI_OK) {
        IMSA_HILOGI("GlobalReference_Create failed, status : %{public}d", status);
        return;
    }
    if ((status = env->Class_FindField(etsAbilityObj_->aniCls, "context", &field)) != ANI_OK) {
        IMSA_HILOGI("Class_FindField failed, status : %{public}d", status);
        return;
    }

    if ((status = env->Object_SetField_Ref(etsAbilityObj_->aniObj, field, contextGlobalRef)) != ANI_OK) {
        IMSA_HILOGI("Object_SetField_Ref failed, status : %{public}d", status);
        return;
    }

    IMSA_HILOGI("BindContext End");
}

void ETSInputMethodExtension::OnStart(const AAFwk::Want &want)
{
    IMSA_HILOGD("OnStart");
    if (etsAbilityObj_ == nullptr) {
        IMSA_HILOGE("etsAbilityObj_ null");
        return;
    }

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        IMSA_HILOGE("env null");
        return;
    }
    auto task = std::make_shared<TaskAmsInit>();
    TaskManager::GetInstance().PostTask(task);
    InputMethodAbility::GetInstance().InitConnect();
    StartAsync("OnStart", static_cast<int32_t>(TraceTaskId::ONSTART_EXTENSION));
    StartAsync("Extension::OnStart", static_cast<int32_t>(TraceTaskId::ONSTART_MIDDLE_EXTENSION));
    Extension::OnStart(want);
    FinishAsync("Extension::OnStart", static_cast<int32_t>(TraceTaskId::ONSTART_MIDDLE_EXTENSION));
    StartAsync("onCreate", static_cast<int32_t>(TraceTaskId::ONCREATE_EXTENSION));
    ani_ref wantRef = AppExecFwk::WrapWant(env, want);
    CallObjectMethod(false, "onCreate", "C{@ohos.app.ability.Want.Want}:", wantRef);
    FinishAsync("onCreate", static_cast<int32_t>(TraceTaskId::ONCREATE_EXTENSION));
    TaskManager::GetInstance().PostTask(std::make_shared<TaskImsaSetCoreAndAgent>());
    IMSA_HILOGI("ime bind imf");
    FinishAsync("OnStart", static_cast<int32_t>(TraceTaskId::ONSTART_EXTENSION));
    IMSA_HILOGI("OnStart End");
    TaskManager::GetInstance().Complete(task->GetSeqId());
}

void ETSInputMethodExtension::OnStop()
{
    IMSA_HILOGD("OnStop");
    if (etsAbilityObj_ == nullptr) {
        IMSA_HILOGE("etsAbilityObj_ null");
        return;
    }

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        IMSA_HILOGE("env null");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        IMSA_HILOGE("context null");
        return;
    }
    AbilityRuntime::InputMethodExtension::OnStop();
    IMSA_HILOGI("ETSInputMethodExtension OnStop start.");
    CallObjectMethod(false, "onDestroy", nullptr);
    bool ret = ConnectionManager::GetInstance().DisconnectCaller(context->GetToken());
    if (ret) {
        IMSA_HILOGI("the input method extension connection is not disconnected.");
    }
    IMSA_HILOGI("ETSInputMethodExtension %{public}s end.", __func__);
}

sptr<IRemoteObject> ETSInputMethodExtension::OnConnect(const AAFwk::Want &want)
{
    IMSA_HILOGI("ETSInputMethodExtension OnConnect start.");
    Extension::OnConnect(want);
    auto remoteObj = new (std::nothrow) InputMethodExtensionAbilityServiceImpl();
    if (remoteObj == nullptr) {
        IMSA_HILOGE("failed to create InputMethodExtensionAbilityServiceImpl!");
        return nullptr;
    }
    return remoteObj;
}

void ETSInputMethodExtension::OnDisconnect(const AAFwk::Want &want)
{
    IMSA_HILOGI("ETSInputMethodExtension OnDisconnect start.");
    Extension::OnDisconnect(want);
    if (etsAbilityObj_ == nullptr) {
        IMSA_HILOGE("etsAbilityObj_ null");
        return;
    }

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        IMSA_HILOGE("env null");
        return;
    }
    ani_ref wantRef = AppExecFwk::WrapWant(env, want);
    CallObjectMethod(false, "onDisconnect", "C{@ohos.app.ability.Want.Want}:", wantRef);
}

void ETSInputMethodExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    IMSA_HILOGI("ETSInputMethodExtension OnCommand start.");
    Extension::OnCommand(want, restart, startId);
    if (etsAbilityObj_ == nullptr) {
        IMSA_HILOGE("etsAbilityObj_ null");
        return;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        IMSA_HILOGE("env null");
        return;
    }
    ani_ref wantRef = AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        IMSA_HILOGI("null wantRef");
        return;
    }
    ani_int iStartId = static_cast<ani_int>(startId);
    CallObjectMethod(false, "onRequest", "C{@ohos.app.ability.Want.Want}i:", wantRef, iStartId);
}

void ETSInputMethodExtension::OnConfigurationUpdated(const AppExecFwk::Configuration &config)
{
    AbilityRuntime::InputMethodExtension::OnConfigurationUpdated(config);
    IMSA_HILOGD("called.");
    auto context = GetContext();
    if (context == nullptr) {
        IMSA_HILOGE("context is invalid!");
        return;
    }

    auto contextConfig = context->GetConfiguration();
    if (contextConfig != nullptr) {
        std::vector<std::string> changeKeyValue;
        contextConfig->CompareDifferent(changeKeyValue, config);
        if (!changeKeyValue.empty()) {
            contextConfig->Merge(changeKeyValue, config);
        }
        IMSA_HILOGD("config dump merge: %{public}s.", contextConfig->GetName().c_str());
    }
    ConfigurationUpdated();
}

void ETSInputMethodExtension::ConfigurationUpdated()
{
    IMSA_HILOGD("called.");
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        IMSA_HILOGE("env null");
        return;
    }

    // Notify extension context
    auto context = GetContext();
    if (context == nullptr) {
        IMSA_HILOGE("context is nullptr!");
        return;
    }
    auto fullConfig = context->GetConfiguration();
    if (fullConfig == nullptr) {
        IMSA_HILOGE("configuration is nullptr!");
        return;
    }

    AbilityRuntime::EtsExtensionContext::ConfigurationUpdated(env, etsAbilityObj_, fullConfig);
}

ani_ref ETSInputMethodExtension::CallObjectMethod(bool withResult, const char *name, const char *signature, ...)
{
    IMSA_HILOGI("CallObjectMethod %{public}s", name);
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        IMSA_HILOGE("null env");
        return nullptr;
    }
    if (etsAbilityObj_ == nullptr) {
        IMSA_HILOGE("null etsAbilityObj_");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(etsAbilityObj_->aniCls, name, signature, &method)) != ANI_OK) {
        IMSA_HILOGE("Class_FindMethod status : %{public}d", status);
        return nullptr;
    }
    if (method == nullptr) {
        return nullptr;
    }
    ani_ref res = nullptr;
    va_list args;
    if (withResult) {
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Ref_V(etsAbilityObj_->aniObj, method, &res, args)) != ANI_OK) {
            IMSA_HILOGE("Object_CallMethod_Ref_V status : %{public}d", status);
            return nullptr;
        }
        va_end(args);
        return res;
    }
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(etsAbilityObj_->aniObj, method, args)) != ANI_OK) {
        IMSA_HILOGE("Object_CallMethod_Void_V status : %{public}d", status);
    }
    va_end(args);
    return nullptr;
}

void ETSInputMethodExtension::ListenWindowManager()
{
    IMSA_HILOGD("register window manager service listener.");
    auto etsInputMethodExtension = std::static_pointer_cast<ETSInputMethodExtension>(shared_from_this());
    displayListener_ = sptr<EtsInputMethodExtensionDisplayListener>::MakeSptr(etsInputMethodExtension);
    if (displayListener_ == nullptr) {
        IMSA_HILOGE("failed to create display listener!");
        return;
    }

    Rosen::DisplayManager::GetInstance().RegisterDisplayListener(displayListener_);
}

void ETSInputMethodExtension::OnListenerCreate(Rosen::DisplayId displayId)
{
    IMSA_HILOGD("enter");
}

void ETSInputMethodExtension::OnListenerDestroy(Rosen::DisplayId displayId)
{
    IMSA_HILOGD("exit");
}

void ETSInputMethodExtension::ListenerCheckNeedAdjustKeyboard(Rosen::DisplayId displayId)
{
    if (displayId != Rosen::DisplayManager::GetInstance().GetDefaultDisplayId()) {
        return;
    }
    auto foldStatus = Rosen::DisplayManager::GetInstance().GetFoldStatus();
    auto displayPtr = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    if (displayPtr == nullptr) {
        return;
    }
    IMSA_HILOGD("display width: %{public}d, height: %{public}d, rotation: %{public}d, foldStatus: %{public}d",
        displayPtr->GetWidth(),
        displayPtr->GetHeight(),
        displayPtr->GetRotation(),
        foldStatus);
    if (!cacheDisplay_.IsEmpty()) {
        if ((cacheDisplay_.displayWidth != displayPtr->GetWidth() ||
            cacheDisplay_.displayHeight != displayPtr->GetHeight()) &&
            cacheDisplay_.displayFoldStatus == foldStatus &&
            cacheDisplay_.displayRotation == displayPtr->GetRotation()) {
            InputMethodAbility::GetInstance().AdjustKeyboard();
        }
    }
    cacheDisplay_.SetCacheDisplay(
        displayPtr->GetWidth(), displayPtr->GetHeight(), displayPtr->GetRotation(), foldStatus);
}

void ETSInputMethodExtension::OnListenerChange(Rosen::DisplayId displayId)
{
    IMSA_HILOGD("displayId: %{public}" PRIu64 "", displayId);
    auto context = GetContext();
    if (context == nullptr) {
        IMSA_HILOGE("context is invalid!");
        return;
    }

    auto contextConfig = context->GetConfiguration();
    if (contextConfig == nullptr) {
        IMSA_HILOGE("configuration is invalid!");
        return;
    }

    bool isConfigChanged = false;
    auto configUtils = std::make_shared<ConfigurationUtils>();
    configUtils->UpdateDisplayConfig(displayId, contextConfig, context->GetResourceManager(), isConfigChanged);
    IMSA_HILOGD("OnListenerCreate, isConfigChanged: %{public}d, Config after update: %{public}s.", isConfigChanged,
        contextConfig->GetName().c_str());

    if (isConfigChanged) {
        auto inputMethodExtension = std::static_pointer_cast<ETSInputMethodExtension>(shared_from_this());
        auto task = [inputMethodExtension]() {
            if (inputMethodExtension) {
                inputMethodExtension->ConfigurationUpdated();
            }
        };
        if (handler_ != nullptr) {
            handler_->PostTask(task, "ETSInputMethodExtension:OnListenerCreate",
                0, AppExecFwk::EventQueue::Priority::VIP);
        }
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
