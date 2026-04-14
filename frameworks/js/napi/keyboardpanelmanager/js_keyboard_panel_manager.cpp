/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "js_keyboard_panel_manager.h"

#include "event_checker.h"
#include "input_method_utils.h"
#include "js_callback_handler.h"
#include "js_util.h"
#include "js_utils.h"

namespace OHOS {
namespace MiscServices {
constexpr int32_t MAX_WAIT_TIME_PRIVATE_COMMAND = 2000;
BlockQueue<PrivateCommandInfo> JsKeyboardPanelManager::privateCommandQueue_{ MAX_WAIT_TIME_PRIVATE_COMMAND };
std::mutex JsKeyboardPanelManager::managerMutex_;
sptr<JsKeyboardPanelManager> JsKeyboardPanelManager::keyboardPanelManager_{ nullptr };

JsKeyboardPanelManager::JsKeyboardPanelManager()
{
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    handler_ = AppExecFwk::EventHandler::Current();
}

napi_value JsKeyboardPanelManager::Init(napi_env env, napi_value info)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("sendPrivateCommand", SendPrivateCommand),
        DECLARE_NAPI_FUNCTION("connectSystemChannel", ConnectSystemChannel),
        DECLARE_NAPI_FUNCTION("onSystemPrivateCommand", OnSystemPrivateCommand),
        DECLARE_NAPI_FUNCTION("offSystemPrivateCommand", OffSystemPrivateCommand),
        DECLARE_NAPI_FUNCTION("onSystemPanelStatusChange", OnSystemPanelStatusChange),
        DECLARE_NAPI_FUNCTION("offSystemPanelStatusChange", OffSystemPanelStatusChange),
        DECLARE_NAPI_STATIC_PROPERTY("InputMethodInputType", GetJsInputMethodInputType(env)),
    };
    IMF_CALL(
        napi_define_properties(env, info, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));
    return info;
}

sptr<JsKeyboardPanelManager> JsKeyboardPanelManager::GetInstance()
{
    if (keyboardPanelManager_ == nullptr) {
        std::lock_guard<std::mutex> lock(managerMutex_);
        if (keyboardPanelManager_ == nullptr) {
            keyboardPanelManager_ = new (std::nothrow) JsKeyboardPanelManager();
        }
    }
    return keyboardPanelManager_;
}

struct PanelManagerContext : public AsyncCall::Context {
    PanelManagerContext() : Context(nullptr, nullptr){};
    napi_status operator()(napi_env env, napi_value *result) override
    {
        if (status_ != napi_ok) {
            output_ = nullptr;
            return status_;
        }
        return Context::operator()(env, result);
    }
};

napi_value JsKeyboardPanelManager::GetJsInputMethodInputType(napi_env env)
{
    napi_value inputMethodInputType = nullptr;
    IMF_CALL(napi_create_object(env, &inputMethodInputType));
    bool ret = JsUtil::Object::WriteProperty(env, inputMethodInputType, "NONE", static_cast<int32_t>(InputType::NONE));
    ret = ret &&
        JsUtil::Object::WriteProperty(
            env, inputMethodInputType, "CAMERA_INPUT", static_cast<int32_t>(InputType::CAMERA_INPUT));
    ret = ret &&
        JsUtil::Object::WriteProperty(
            env, inputMethodInputType, "SECURITY_INPUT", static_cast<int32_t>(InputType::SECURITY_INPUT));
    ret = ret &&
        JsUtil::Object::WriteProperty(
            env, inputMethodInputType, "VOICE_INPUT", static_cast<int32_t>(InputType::VOICE_INPUT));
    ret = ret &&
        JsUtil::Object::WriteProperty(
            env, inputMethodInputType, "FLOATING_VOICE_INPUT", static_cast<int32_t>(InputType::VOICEKB_INPUT));
    return ret ? inputMethodInputType : JsUtil::Const::Null(env);
}

napi_value JsKeyboardPanelManager::ConnectSystemChannel(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<PanelManagerContext>();
    auto manager = JsKeyboardPanelManager::GetInstance();
    if (manager == nullptr) {
        IMSA_HILOGE("manager is nullptr!");
        return nullptr;
    }
    auto exec = [ctxt, env, manager](AsyncCall::Context *ctx) {
        auto channel = ImeSystemCmdChannel::GetInstance();
        if (channel == nullptr) {
            ctxt->SetErrorCode(ErrorCode::ERROR_NULL_POINTER);
            ctxt->SetState(napi_generic_failure);
            IMSA_HILOGE("channel is nullptr!");
            return;
        }
        auto ret = channel->ConnectSystemCmd(manager);
        if (ret != ErrorCode::NO_ERROR && ret != ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION &&
            ret != ErrorCode::ERROR_STATUS_PERMISSION_DENIED && ret != ErrorCode::ERROR_SYSTEM_PANEL_ERROR) {
            ret = ErrorCode::ERROR_IMSA_NULLPTR;
        }
        ctxt->SetErrorCode(ret);
        CHECK_RETURN_VOID(ret == ErrorCode::NO_ERROR, "ConnectSystemChannel return error!");
        ctxt->SetState(napi_ok);
    };
    // 0 means JsAPI:ConnectSystemChannel has 0 params at most.
    AsyncCall asyncCall(env, info, ctxt, 0);
    return asyncCall.Call(env, exec, "ConnectSystemChannel");
}

napi_value JsKeyboardPanelManager::OnSystemPrivateCommand(napi_env env, napi_callback_info info)
{
    IMSA_HILOGD("OnSystemPrivateCommand start");
    size_t argc = 1; // has 1 param
    napi_value argv[1] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    if (argc < 1 || JsUtil::GetType(env, argv[0]) != napi_function) {
        IMSA_HILOGE("OnSystemPrivateCommand failed, invalid callback!");
        return JsUtil::Const::Null(env);
    }
    auto manager = JsKeyboardPanelManager::GetInstance();
    if (manager == nullptr) {
        IMSA_HILOGE("manager is nullptr!");
        return JsUtil::Const::Null(env);
    }
    std::string type = "systemPrivateCommand";
    IMSA_HILOGD("OnSystemPrivateCommand register type: %{public}s.", type.c_str());
    std::shared_ptr<JSCallbackObject> callback =
        std::make_shared<JSCallbackObject>(env, argv[0], std::this_thread::get_id(),
            AppExecFwk::EventHandler::Current());
    manager->RegisterListener(argv[0], type, callback);
    return JsUtil::Const::Null(env);
}

napi_value JsKeyboardPanelManager::OffSystemPrivateCommand(napi_env env, napi_callback_info info)
{
    IMSA_HILOGD("OffSystemPrivateCommand start");
    size_t argc = 1; // has 1 param
    napi_value argv[1] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    auto manager = JsKeyboardPanelManager::GetInstance();
    if (manager == nullptr) {
        IMSA_HILOGE("manager is nullptr!");
        return JsUtil::Const::Null(env);
    }
    std::string type = "systemPrivateCommand";
    // if the param is not napi_function/napi_null/napi_undefined, return
    auto paramType = JsUtil::GetType(env, argv[0]);
    if (paramType != napi_function && paramType != napi_null && paramType != napi_undefined) {
        return JsUtil::Const::Null(env);
    }
    // if the param is napi_function, delete it, else delete all
    argv[0] = paramType == napi_function ? argv[0] : nullptr;
    IMSA_HILOGD("OffSystemPrivateCommand unregister type: %{public}s.", type.c_str());
    manager->UnRegisterListener(argv[0], type, env);
    return JsUtil::Const::Null(env);
}

napi_value JsKeyboardPanelManager::OnSystemPanelStatusChange(napi_env env, napi_callback_info info)
{
    IMSA_HILOGD("OnSystemPanelStatusChange start");
    size_t argc = 1; // has 1 param
    napi_value argv[1] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    if (argc < 1 || JsUtil::GetType(env, argv[0]) != napi_function) {
        IMSA_HILOGE("OnSystemPanelStatusChange failed, invalid callback!");
        return JsUtil::Const::Null(env);
    }
    auto manager = JsKeyboardPanelManager::GetInstance();
    if (manager == nullptr) {
        IMSA_HILOGE("manager is nullptr!");
        return JsUtil::Const::Null(env);
    }
    std::string type = "systemPanelStatusChange";
    IMSA_HILOGD("OnSystemPanelStatusChange register type: %{public}s.", type.c_str());
    std::shared_ptr<JSCallbackObject> callback =
        std::make_shared<JSCallbackObject>(env, argv[0], std::this_thread::get_id(),
            AppExecFwk::EventHandler::Current());
    manager->RegisterListener(argv[0], type, callback);
    return JsUtil::Const::Null(env);
}

napi_value JsKeyboardPanelManager::OffSystemPanelStatusChange(napi_env env, napi_callback_info info)
{
    IMSA_HILOGD("OffSystemPanelStatusChange start");
    size_t argc = 1; // has 1 param
    napi_value argv[1] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    auto manager = JsKeyboardPanelManager::GetInstance();
    if (manager == nullptr) {
        IMSA_HILOGE("manager is nullptr!");
        return JsUtil::Const::Null(env);
    }
    std::string type = "systemPanelStatusChange";
    // if the param is not napi_function/napi_null/napi_undefined, return
    auto paramType = JsUtil::GetType(env, argv[0]);
    if (paramType != napi_function && paramType != napi_null && paramType != napi_undefined) {
        return JsUtil::Const::Null(env);
    }
    // if the param is napi_function, delete it, else delete all
    argv[0] = paramType == napi_function ? argv[0] : nullptr;
    IMSA_HILOGD("OffSystemPanelStatusChange unregister type: %{public}s.", type.c_str());
    manager->UnRegisterListener(argv[0], type, env);
    return JsUtil::Const::Null(env);
}

void JsKeyboardPanelManager::RegisterListener(napi_value callback, std::string type,
    std::shared_ptr<JSCallbackObject> callbackObj)
{
    IMSA_HILOGD("register listener: %{public}s.", type.c_str());
    auto channel = ImeSystemCmdChannel::GetInstance();
    CHECK_RETURN_VOID(channel != nullptr, "channel is nullptr");
    RESULT_CHECK_RETURN_VOID(callbackObj->env_, channel->IsSystemApp(), EXCEPTION_SYSTEM_PERMISSION, "", TYPE_NONE);

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (jsCbMap_.empty() || jsCbMap_.find(type) == jsCbMap_.end()) {
        IMSA_HILOGD("methodName: %{public}s is not registered!", type.c_str());
    }
    auto callbacks = jsCbMap_[type];
    bool ret = std::any_of(callbacks.begin(), callbacks.end(), [&callback](std::shared_ptr<JSCallbackObject> cb) {
        if (cb == nullptr) {
            return false;
        }
        return JsUtils::Equals(cb->env_, callback, cb->callback_, cb->threadId_);
    });
    if (ret) {
        IMSA_HILOGD("callback already registered!");
        return;
    }

    IMSA_HILOGI("add %{public}s callbackObj into jsCbMap_.", type.c_str());
    jsCbMap_[type].push_back(std::move(callbackObj));
}

void JsKeyboardPanelManager::UnRegisterListener(napi_value callback, std::string type, napi_env env)
{
    IMSA_HILOGI("event: %{public}s.", type.c_str());
    auto channel = ImeSystemCmdChannel::GetInstance();
    CHECK_RETURN_VOID(channel != nullptr, "channel is nullptr");
    RESULT_CHECK_RETURN_VOID(env, channel->IsSystemApp(), EXCEPTION_SYSTEM_PERMISSION, "", TYPE_NONE);

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (jsCbMap_.empty() || jsCbMap_.find(type) == jsCbMap_.end()) {
        IMSA_HILOGE("methodName: %{public}s already unRegistered!", type.c_str());
        return;
    }

    if (callback == nullptr) {
        jsCbMap_.erase(type);
        IMSA_HILOGI("callback is nullptr.");
        return;
    }

    for (auto item = jsCbMap_[type].begin(); item != jsCbMap_[type].end(); item++) {
        if (JsUtils::Equals((*item)->env_, callback, (*item)->callback_, (*item)->threadId_)) {
            jsCbMap_[type].erase(item);
            break;
        }
    }

    if (jsCbMap_[type].empty()) {
        jsCbMap_.erase(type);
    }
}

napi_value JsKeyboardPanelManager::SendPrivateCommand(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<SendPrivateCommandContext>();
    auto input = [ctxt](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        auto channel = ImeSystemCmdChannel::GetInstance();
        CHECK_RETURN(channel != nullptr, "SendPrivateCommand channel is nullptr", napi_generic_failure);
        RESULT_CHECK_RETURN(
            env, channel->IsSystemApp(), EXCEPTION_SYSTEM_PERMISSION, "", TYPE_NONE, napi_generic_failure);
        PARAM_CHECK_RETURN(env, argc > 0, "at least one parameter is required!", TYPE_NONE, napi_generic_failure);
        CHECK_RETURN(JsUtils::GetValue(env, argv[0], ctxt->privateCommand) == napi_ok,
            "commandData covert failed, type must be Record<string, CommandDataType>", napi_generic_failure);
        // Validate user-provided commands BEFORE adding sys_cmd field
        // This ensures user commands comply with spec: max 5 commands, 32KB total size
        if (!ImeSystemCmdChannel::IsUserPrivateCommandValid(ctxt->privateCommand)) {
            PARAM_CHECK_RETURN(env, false, "commandData size limit 32KB, count limit 5.", TYPE_NONE,
                napi_generic_failure);
        }
        ctxt->info = { std::chrono::system_clock::now(), ctxt->privateCommand };
        privateCommandQueue_.Push(ctxt->info);
        return napi_ok;
    };
    auto output = [ctxt](napi_env env, napi_value *result) -> napi_status { return napi_ok; };
    auto exec = [ctxt](AsyncCall::Context *ctx) {
        privateCommandQueue_.Wait(ctxt->info);
        auto channel = ImeSystemCmdChannel::GetInstance();
        if (channel == nullptr) {
            ctxt->SetState(napi_generic_failure);
            privateCommandQueue_.Pop();
            return;
        }
        ctxt->privateCommand["sys_cmd"] = 1;
        int32_t code = channel->SendPrivateCommand(ctxt->privateCommand);
        privateCommandQueue_.Pop();
        if (code == ErrorCode::NO_ERROR) {
            ctxt->SetState(napi_ok);
        } else {
            IMSA_HILOGE("SendPrivateCommand failed, code: %{public}d", code);
            ctxt->SetErrorCode(ErrorCode::ERROR_SYSTEM_PANEL_ERROR);
        }
    };
    ctxt->SetAction(std::move(input), std::move(output));
    // 1 means JsAPI:SendPrivateCommand has 1 params at most.
    AsyncCall asyncCall(env, info, ctxt, 1);
    return asyncCall.Call(env, exec, "SendPrivateCommand");
}

void JsKeyboardPanelManager::ReceivePrivateCommand(
    const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    IMSA_HILOGD("start.");
    std::string type = "systemPrivateCommand";
    auto entry = GetEntry(type, [&privateCommand](UvEntry &entry) { entry.privateCommand = privateCommand; });
    if (entry == nullptr) {
        return;
    }
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        IMSA_HILOGE("eventHandler is nullptr!");
        return;
    }
    InputMethodSyncTrace tracer("ReceivePrivateCommand trace");
    auto task = [entry]() {
        auto paramGetter = [entry](napi_env env, napi_value *args, uint8_t argc) -> bool {
            if (argc < 1) {
                return false;
            }
            napi_value jsObject = JsUtils::GetJsPrivateCommand(env, entry->privateCommand);
            if (jsObject == nullptr) {
                IMSA_HILOGE("jsObject is nullptr");
                return false;
            }
            // 0 means the first param of callback.
            args[0] = { jsObject };
            return true;
        };
        // 1 means callback has 1 params.
        JsCallbackHandler::Traverse(entry->vecCopy, { 1, paramGetter });
    };
    eventHandler->PostTask(task, type, 0, AppExecFwk::EventQueue::Priority::VIP);
}

void JsKeyboardPanelManager::NotifyPanelStatus(const SysPanelStatus &sysPanelStatus)
{
    IMSA_HILOGD("start");
    std::string type = "systemPanelStatusChange";
    auto entry =
        GetEntry(type, [sysPanelStatus](UvEntry &entry) { entry.sysPanelStatus = sysPanelStatus; });
    if (entry == nullptr) {
        return;
    }
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        IMSA_HILOGE("eventHandler is nullptr!");
        return;
    }
    auto task = [entry]() {
        auto paramGetter = [entry](napi_env env, napi_value *args, uint8_t argc) -> bool {
            if (argc < 1) {
                return false;
            }
            napi_value jsObject = JsPanelStatus::Write(env, entry->sysPanelStatus);
            if (jsObject == nullptr) {
                IMSA_HILOGE("jsObject is nullptr!");
                return false;
            }
            // 0 means the first param of callback.
            args[0] = { jsObject };
            return true;
        };
        // 1 means callback has 1 params.
        JsCallbackHandler::Traverse(entry->vecCopy, { 1, paramGetter });
    };
    eventHandler->PostTask(task, type, 0, AppExecFwk::EventQueue::Priority::VIP);
}

std::shared_ptr<AppExecFwk::EventHandler> JsKeyboardPanelManager::GetEventHandler()
{
    if (handler_ == nullptr) {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        if (handler_ == nullptr) {
            handler_ = AppExecFwk::EventHandler::Current();
        }
    }
    return handler_;
}

std::shared_ptr<JsKeyboardPanelManager::UvEntry> JsKeyboardPanelManager::GetEntry(const std::string &type,
    EntrySetter entrySetter)
{
    IMSA_HILOGD("start, type: %{public}s", type.c_str());
    std::shared_ptr<UvEntry> entry = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (jsCbMap_[type].empty()) {
            IMSA_HILOGD("%{public}s cb-vector is empty.", type.c_str());
            return nullptr;
        }
        entry = std::make_shared<UvEntry>(jsCbMap_[type], type);
    }
    if (entrySetter != nullptr) {
        entrySetter(*entry);
    }
    return entry;
}

napi_value JsPanelStatus::Write(napi_env env, const SysPanelStatus &in)
{
    napi_value jsObject = nullptr;
    napi_create_object(env, &jsObject);
    bool ret = JsUtil::Object::WriteProperty(env, jsObject, "inputType", static_cast<int32_t>(in.inputType));
    ret = ret && JsUtil::Object::WriteProperty(env, jsObject, "panelFlag", in.flag);
    ret = ret && JsUtil::Object::WriteProperty(env, jsObject, "isPanelRaised", in.isPanelRaised);
    ret = ret && JsUtil::Object::WriteProperty(env, jsObject, "needFuncButton", in.needFuncButton);
    return ret ? jsObject : JsUtil::Const::Null(env);
}
} // namespace MiscServices
} // namespace OHOS
