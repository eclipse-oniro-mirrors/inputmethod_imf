/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef INTERFACE_KITS_JS_INPUT_METHOD_ENGINE_SETTING_H
#define INTERFACE_KITS_JS_INPUT_METHOD_ENGINE_SETTING_H

#include <map>
#include <uv.h>
#include <mutex>
#include "napi/native_api.h"
#include "global.h"
#include "async_call.h"

namespace OHOS {
namespace MiscServices {
class JsInputMethodEngineSetting {
public:
    JsInputMethodEngineSetting() = default;
    ~JsInputMethodEngineSetting() = default;
    static napi_value Init(napi_env env, napi_value info);
    static napi_value GetInputMethodEngine(napi_env env, napi_callback_info info);
    static napi_value Subscribe(napi_env env, napi_callback_info info);
    static napi_value UnSubscribe(napi_env env, napi_callback_info info);
    static napi_value MoveCursor(napi_env env, napi_callback_info info);
    void OnInputStart();
    void OnKeyboardStatus(bool isShow);
    void OnInputStop(std::string imeId);
    void OnSetCallingWindow(uint32_t windowId);
private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
    static JsInputMethodEngineSetting *GetNative(napi_env env, napi_callback_info info);
    static bool Equals(napi_env env, napi_value value, napi_ref copy);
    static napi_value GetJsConstProperty(napi_env env, uint32_t num);
    void RegisterListener(napi_value callback, std::string type,
        std::shared_ptr<JSCallbackObject> JSCallbackObject);
    void UnRegisterListener(napi_value callback, std::string type);
    uv_work_t *GetUVwork(std::string type);
    uv_work_t *GetStopInputUVwork(std::string type, std::string imeId);
    uv_work_t *GetWindowIDUVwork(std::string type, uint32_t windowid);
    static std::string GetStringProperty(napi_env env, napi_value obj);
    static constexpr int32_t MAX_VALUE_LEN = 1024;
    static const std::string IMES_CLASS_NAME;
    static thread_local napi_ref IMESRef_;
    struct UvEntry {
        std::vector<std::shared_ptr<JSCallbackObject>> vecCopy;
        std::string type;
        std::string imeid;
        uint32_t windowid;
        UvEntry(std::vector<std::shared_ptr<JSCallbackObject>> cbVec, std::string type)
            : vecCopy(cbVec), type(type) {}
    };
    uv_loop_s *loop_ = nullptr;
    std::recursive_mutex mutex_;
    std::map<std::string, std::vector<std::shared_ptr<JSCallbackObject>>> jsCbMap_;
};
}
}
#endif // INTERFACE_KITS_JS_INPUT_METHOD_ENGINE_SETTING_H