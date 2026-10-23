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
#ifndef JS_PROXY_LISTENER_BASE_H
#define JS_PROXY_LISTENER_BASE_H

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "event_handler.h"
#include "js_callback_object.h"
#include "js_util.h"
#include "js_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "global.h"

namespace OHOS {
namespace MiscServices {

class JsProxyListenerBase {
public:
    JsProxyListenerBase() = default;
    virtual ~JsProxyListenerBase() = default;

    void RegisterListener(napi_value callback, std::string type, std::shared_ptr<JSCallbackObject> callbackObj);
    void UnRegisterListener(napi_value callback, std::string type);

    static napi_value SubscribeByType(napi_env env, napi_callback_info info, const std::string &type);
    static napi_value UnsubscribeByType(napi_env env, napi_callback_info info, const std::string &type);

protected:
    std::vector<std::shared_ptr<JSCallbackObject>> GetCallbacks(const std::string &type);

private:
    std::recursive_mutex mutex_;
    std::map<std::string, std::vector<std::shared_ptr<JSCallbackObject>>> jsCbMap_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // JS_PROXY_LISTENER_BASE_H
