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
#include "js_proxy_listener_base.h"

namespace OHOS {
namespace MiscServices {
constexpr size_t ARGC_ONE = 1;
std::vector<std::shared_ptr<JSCallbackObject>> JsProxyListenerBase::GetCallbacks(const std::string &type)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = jsCbMap_.find(type);
    if (it == jsCbMap_.end() || it->second.empty()) {
        return {};
    }
    return it->second;
}

void JsProxyListenerBase::RegisterListener(
    napi_value callback, std::string type, std::shared_ptr<JSCallbackObject> callbackObj)
{
    IMSA_HILOGD("register listener: %{public}s.", type.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (jsCbMap_.empty() || jsCbMap_.find(type) == jsCbMap_.end()) {
        IMSA_HILOGD("methodName: %{public}s not registered!", type.c_str());
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

void JsProxyListenerBase::UnRegisterListener(napi_value callback, std::string type)
{
    IMSA_HILOGI("unregister listener: %{public}s.", type.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (jsCbMap_.empty() || jsCbMap_.find(type) == jsCbMap_.end()) {
        IMSA_HILOGE("methodName: %{public}s already unregistered!", type.c_str());
        return;
    }

    if (callback == nullptr) {
        jsCbMap_.erase(type);
        IMSA_HILOGE("callback is nullptr.");
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

napi_value JsProxyListenerBase::SubscribeByType(napi_env env, napi_callback_info info, const std::string &type)
{
    size_t argc = ARGC_ONE;
    napi_value argv[ARGC_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    if (argc < ARGC_ONE || JsUtil::GetType(env, argv[0]) != napi_function) {
        IMSA_HILOGE("subscribe failed, type: %{public}s.", type.c_str());
        return nullptr;
    }
    IMSA_HILOGD("subscribe type: %{public}s.", type.c_str());
    auto engine = reinterpret_cast<JsProxyListenerBase *>(JsUtils::GetNativeSelf(env, info));
    if (engine == nullptr) {
        return nullptr;
    }
    std::shared_ptr<JSCallbackObject> callback = std::make_shared<JSCallbackObject>(
        env, argv[0], std::this_thread::get_id(), AppExecFwk::EventHandler::Current());
    engine->RegisterListener(argv[0], type, callback);
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value JsProxyListenerBase::UnsubscribeByType(napi_env env, napi_callback_info info, const std::string &type)
{
    size_t argc = ARGC_ONE;
    napi_value argv[ARGC_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    IMF_CALL(napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    auto paramType = JsUtil::GetType(env, argv[0]);
    if (paramType != napi_function && paramType != napi_null && paramType != napi_undefined) {
        return nullptr;
    }
    argv[0] = paramType == napi_function ? argv[0] : nullptr;
    IMSA_HILOGD("unsubscribe type: %{public}s.", type.c_str());
    auto engine = reinterpret_cast<JsProxyListenerBase *>(JsUtils::GetNativeSelf(env, info));
    if (engine == nullptr) {
        return nullptr;
    }
    engine->UnRegisterListener(argv[0], type);
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}
} // namespace MiscServices
} // namespace OHOS
