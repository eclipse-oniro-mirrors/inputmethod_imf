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

#ifndef FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_JS_PROXY_KEYBOARD_DELEGATE_H
#define FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_JS_PROXY_KEYBOARD_DELEGATE_H

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "event_handler.h"
#include "input_attribute.h"
#include "js_callback_object.h"
#include "js_proxy_listener_base.h"
#include "key_event_consumer_proxy.h"
#include "keyboard_listener.h"
#include "napi/native_api.h"
#include "global.h"

namespace OHOS {
namespace MiscServices {
class JsProxyKeyboardDelegate : public JsProxyListenerBase, public KeyboardListener {
public:
    JsProxyKeyboardDelegate() = default;
    ~JsProxyKeyboardDelegate() override = default;
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value JsConstructor(napi_env env, napi_callback_info cbInfo);

    static napi_value SubscribeKeyEvent(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeKeyEvent(napi_env env, napi_callback_info info);
    static napi_value SubscribeCursorContextChange(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeCursorContextChange(napi_env env, napi_callback_info info);
    static napi_value SubscribeSelectionChange(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeSelectionChange(napi_env env, napi_callback_info info);
    static napi_value SubscribeTextChange(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeTextChange(napi_env env, napi_callback_info info);
    static napi_value SubscribeEditorAttributeChanged(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeEditorAttributeChanged(napi_env env, napi_callback_info info);
    static napi_value GetProxyInputMethodKeyboardDelegate(napi_env env, napi_callback_info info);

protected:
    static void DealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent,
        const std::shared_ptr<JSCallbackObject> &callback, uint64_t cbId,
        const sptr<IRemoteObject> &channelObject, bool consumeOwner);
    static void DealCursorUpdate(int32_t positionX, int32_t positionY, int32_t height,
        const std::shared_ptr<JSCallbackObject> &callback);
    static void DealSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd,
        const std::shared_ptr<JSCallbackObject> &callback);
    static void DealTextChange(const std::string &text, const std::shared_ptr<JSCallbackObject> &callback);
    static void DealEditorAttributeChange(const InputAttribute &inputAttribute,
        const std::shared_ptr<JSCallbackObject> &callback);

    void OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height) override;
    void OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd) override;
    void OnTextChange(const std::string &text) override;
    void OnEditorAttributeChange(const InputAttribute &inputAttribute) override;
    bool OnDealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId,
        const sptr<IRemoteObject> &channelObject) override;

private:
    static std::shared_ptr<JsProxyKeyboardDelegate> GetInstance();
    static bool InitProxyKeyboardDelegate();

    static const std::string PKD_CLASS_NAME;
    static thread_local napi_ref PKDRef_;
    static std::mutex instanceMutex_;
    static std::shared_ptr<JsProxyKeyboardDelegate> instance_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_JS_NAPI_INPUTMETHODABILITY_JS_PROXY_KEYBOARD_DELEGATE_H
