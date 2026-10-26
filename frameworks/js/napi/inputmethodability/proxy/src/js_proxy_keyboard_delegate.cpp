/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "js_proxy_keyboard_delegate.h"

#include "input_method_ability.h"
#include "inputmethod_trace.h"
#include "js_callback_handler.h"
#include "js_text_input_client_engine.h"
#include "js_util.h"
#include "js_utils.h"
#include "key_event_napi.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "global.h"

namespace OHOS {
namespace MiscServices {
const std::string JsProxyKeyboardDelegate::PKD_CLASS_NAME = "ProxyKeyboardDelegate";
thread_local napi_ref JsProxyKeyboardDelegate::PKDRef_ = nullptr;
std::mutex JsProxyKeyboardDelegate::instanceMutex_;
std::shared_ptr<JsProxyKeyboardDelegate> JsProxyKeyboardDelegate::instance_ = nullptr;

std::shared_ptr<JsProxyKeyboardDelegate> JsProxyKeyboardDelegate::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<JsProxyKeyboardDelegate>();
        }
    }
    return instance_;
}

napi_value JsProxyKeyboardDelegate::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onKeyEvent", SubscribeKeyEvent),
        DECLARE_NAPI_FUNCTION("offKeyEvent", UnsubscribeKeyEvent),
        DECLARE_NAPI_FUNCTION("onCursorContextChange", SubscribeCursorContextChange),
        DECLARE_NAPI_FUNCTION("offCursorContextChange", UnsubscribeCursorContextChange),
        DECLARE_NAPI_FUNCTION("onSelectionChange", SubscribeSelectionChange),
        DECLARE_NAPI_FUNCTION("offSelectionChange", UnsubscribeSelectionChange),
        DECLARE_NAPI_FUNCTION("onTextChange", SubscribeTextChange),
        DECLARE_NAPI_FUNCTION("offTextChange", UnsubscribeTextChange),
        DECLARE_NAPI_FUNCTION("onEditorAttributeChanged", SubscribeEditorAttributeChanged),
        DECLARE_NAPI_FUNCTION("offEditorAttributeChanged", UnsubscribeEditorAttributeChanged),
    };
    napi_value cons = nullptr;
    IMF_CALL(napi_define_class(env, PKD_CLASS_NAME.c_str(), PKD_CLASS_NAME.size(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));
    IMF_CALL(napi_create_reference(env, cons, 1, &PKDRef_));
    IMF_CALL(napi_set_named_property(env, exports, PKD_CLASS_NAME.c_str(), cons));
    return exports;
}

napi_value JsProxyKeyboardDelegate::JsConstructor(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    napi_get_null(env, &thisVar);
    IMF_CALL(napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr));
    auto listener = GetInstance();
    if (listener == nullptr || !InitProxyKeyboardDelegate()) {
        IMSA_HILOGE("failed to get listener.");
        return thisVar;
    }
    napi_status status = napi_wrap(
        env, thisVar, listener.get(), [](napi_env env, void *nativeObject, void *hint) {}, nullptr, nullptr);
    if (status != napi_ok) {
        IMSA_HILOGE("JsProxyKeyboardDelegate napi_wrap failed: %{public}d", status);
        return thisVar;
    }
    return thisVar;
};

bool JsProxyKeyboardDelegate::InitProxyKeyboardDelegate()
{
    auto listener = GetInstance();
    if (listener == nullptr) {
        return false;
    }
    InputMethodAbility::GetInstance().SetKdListener(listener);
    return true;
}

napi_value JsProxyKeyboardDelegate::SubscribeKeyEvent(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::SubscribeByType(env, info, "keyEvent");
}
napi_value JsProxyKeyboardDelegate::UnsubscribeKeyEvent(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::UnsubscribeByType(env, info, "keyEvent");
}
napi_value JsProxyKeyboardDelegate::SubscribeCursorContextChange(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::SubscribeByType(env, info, "cursorContextChange");
}
napi_value JsProxyKeyboardDelegate::UnsubscribeCursorContextChange(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::UnsubscribeByType(env, info, "cursorContextChange");
}
napi_value JsProxyKeyboardDelegate::SubscribeSelectionChange(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::SubscribeByType(env, info, "selectionChange");
}
napi_value JsProxyKeyboardDelegate::UnsubscribeSelectionChange(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::UnsubscribeByType(env, info, "selectionChange");
}
napi_value JsProxyKeyboardDelegate::SubscribeTextChange(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::SubscribeByType(env, info, "textChange");
}
napi_value JsProxyKeyboardDelegate::UnsubscribeTextChange(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::UnsubscribeByType(env, info, "textChange");
}
napi_value JsProxyKeyboardDelegate::SubscribeEditorAttributeChanged(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::SubscribeByType(env, info, "editorAttributeChanged");
}
napi_value JsProxyKeyboardDelegate::UnsubscribeEditorAttributeChanged(napi_env env, napi_callback_info info)
{
    return JsProxyListenerBase::UnsubscribeByType(env, info, "editorAttributeChanged");
}

napi_value JsProxyKeyboardDelegate::GetProxyKeyboardDelegate(napi_env env, napi_callback_info info)
{
    napi_value instance = nullptr;
    napi_get_null(env, &instance);
    if (InputMethodAbility::GetInstance().IsImeExtension()) {
        IMSA_HILOGE("IME extension not allowed");
        JsUtils::ThrowException(env, IMFErrorCode::EXCEPTION_IME_EXTENSION_NOT_ALLOWED,
            "the caller is an input method extension", TYPE_NONE);
        return instance;
    }

    napi_value cons = nullptr;
    if (napi_get_reference_value(env, PKDRef_, &cons) != napi_ok) {
        IMSA_HILOGE("failed to get proxy keyboard delegate constructor");
        return instance;
    }
    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        IMSA_HILOGE("failed to create proxy keyboard delegate instance");
        return instance;
    }
    return instance;
}

void JsProxyKeyboardDelegate::OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height)
{
    IMSA_HILOGD("the cursor for x: %{public}d, y: %{public}d, height: %{public}d.", positionX, positionY, height);
    auto callbacks = GetCallbacks("cursorContextChange");
    for (auto &cb : callbacks) {
        if (cb == nullptr || cb->jsHandler_ == nullptr) {
            continue;
        }
        auto task = [cb, positionX, positionY, height]() {
            DealCursorUpdate(positionX, positionY, height, cb);
        };
        cb->jsHandler_->PostTask(task, "cursorContextChange", 0, AppExecFwk::EventQueue::Priority::VIP);
    }
}

void JsProxyKeyboardDelegate::DealCursorUpdate(int32_t positionX, int32_t positionY, int32_t height,
    const std::shared_ptr<JSCallbackObject> &callback)
{
    auto paramGetter = [positionX, positionY, height](napi_env env, napi_value *args, uint8_t argc) -> bool {
        if (argc < 3) {
            return false;
        }
        napi_create_int32(env, positionX, &args[0]);
        napi_create_int32(env, positionY, &args[1]);
        napi_create_int32(env, height, &args[2]);
        return true;
    };
    JsCallbackHandler::Traverse({ callback }, { 3, paramGetter });
}

void JsProxyKeyboardDelegate::OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd)
{
    IMSA_HILOGD("the selection for oldBegin: %{public}d, oldEnd: %{public}d, newBegin: %{public}d, newEnd: "
                "%{public}d.",
        oldBegin, oldEnd, newBegin, newEnd);
    auto callbacks = GetCallbacks("selectionChange");
    for (auto &cb : callbacks) {
        if (cb == nullptr || cb->jsHandler_ == nullptr) {
            continue;
        }
        auto task = [cb, oldBegin, oldEnd, newBegin, newEnd]() {
            DealSelectionChange(oldBegin, oldEnd, newBegin, newEnd, cb);
        };
        cb->jsHandler_->PostTask(task, "selectionChange", 0, AppExecFwk::EventQueue::Priority::VIP);
    }
}

void JsProxyKeyboardDelegate::DealSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin,
    int32_t newEnd, const std::shared_ptr<JSCallbackObject> &callback)
{
    auto paramGetter = [oldBegin, oldEnd, newBegin, newEnd](
                           napi_env env, napi_value *args, uint8_t argc) -> bool {
        if (argc < 4) {
            return false;
        }
        napi_create_int32(env, oldBegin, &args[0]);
        napi_create_int32(env, oldEnd, &args[1]);
        napi_create_int32(env, newBegin, &args[2]);
        napi_create_int32(env, newEnd, &args[3]);
        return true;
    };
    JsCallbackHandler::Traverse({ callback }, { 4, paramGetter });
}

void JsProxyKeyboardDelegate::OnTextChange(const std::string &text)
{
    IMSA_HILOGD("run in.");
    auto callbacks = GetCallbacks("textChange");
    for (auto &cb : callbacks) {
        if (cb == nullptr || cb->jsHandler_ == nullptr) {
            continue;
        }
        auto task = [cb, text]() {
            DealTextChange(text, cb);
        };
        cb->jsHandler_->PostTask(task, "textChange", 0, AppExecFwk::EventQueue::Priority::VIP);
    }
}

void JsProxyKeyboardDelegate::DealTextChange(const std::string &text,
    const std::shared_ptr<JSCallbackObject> &callback)
{
    auto paramGetter = [text](napi_env env, napi_value *args, uint8_t argc) -> bool {
        if (argc == 0) {
            return false;
        }
        napi_create_string_utf8(env, text.c_str(), NAPI_AUTO_LENGTH, &args[0]);
        return true;
    };
    JsCallbackHandler::Traverse({ callback }, { 1, paramGetter });
}

void JsProxyKeyboardDelegate::OnEditorAttributeChange(const InputAttribute &inputAttribute)
{
    IMSA_HILOGD("enterKeyType: %{public}d, inputPattern: %{public}d, previewSupport: %{public}d",
        inputAttribute.enterKeyType, inputAttribute.inputPattern, inputAttribute.isTextPreviewSupported);
    auto callbacks = GetCallbacks("editorAttributeChanged");
    for (auto &cb : callbacks) {
        if (cb == nullptr || cb->jsHandler_ == nullptr) {
            continue;
        }
        auto task = [cb, inputAttribute]() {
            DealEditorAttributeChange(inputAttribute, cb);
        };
        cb->jsHandler_->PostTask(task, "editorAttributeChanged", 0, AppExecFwk::EventQueue::Priority::VIP);
    }
}

void JsProxyKeyboardDelegate::DealEditorAttributeChange(const InputAttribute &inputAttribute,
    const std::shared_ptr<JSCallbackObject> &callback)
{
    auto paramGetter = [inputAttribute](napi_env env, napi_value *args, uint8_t argc) -> bool {
        if (argc == 0) {
            return false;
        }
        napi_value jsObject = JsInputAttribute::Write(env, inputAttribute);
        if (jsObject == JsUtil::Const::Null(env)) {
            IMSA_HILOGE("jsObject is nullptr!");
            return false;
        }
        args[0] = jsObject;
        return true;
    };
    JsCallbackHandler::Traverse({ callback }, { 1, paramGetter });
}

bool JsProxyKeyboardDelegate::OnDealKeyEvent(
    const std::shared_ptr<MMI::KeyEvent> &keyEvent, uint64_t cbId, const sptr<IRemoteObject> &channelObject)
{
    if (keyEvent == nullptr) {
        IMSA_HILOGE("keyEvent is nullptr");
        return false;
    }
    auto keyEventCallbacks = GetCallbacks("keyEvent");
    if (keyEventCallbacks.empty()) {
        IMSA_HILOGW("key event callback is not registered.");
        return false;
    }
    IMSA_HILOGD("run in.");
    bool isFirst = true;
    for (const auto &cb : keyEventCallbacks) {
        if (cb == nullptr || cb->jsHandler_ == nullptr) {
            continue;
        }
        bool consumeOwner = isFirst;
        isFirst = false;
        auto task = [cb, keyEvent, cbId, channelObject, consumeOwner]() {
            DealKeyEvent(keyEvent, cb, cbId, channelObject, consumeOwner);
        };
        cb->jsHandler_->PostTask(task, "OnDealKeyEvent", 0, AppExecFwk::EventQueue::Priority::VIP);
    }
    return true;
}

void JsProxyKeyboardDelegate::DealKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent,
    const std::shared_ptr<JSCallbackObject> &callback, uint64_t cbId, const sptr<IRemoteObject> &channelObject,
    bool consumeOwner)
{
    auto getKeyEventProperty = [keyEvent](napi_env env, napi_value *args, uint8_t argc) -> bool {
        if (argc == 0) {
            return false;
        }
        napi_value keyEventObject{};
        auto result = napi_create_object(env, &keyEventObject);
        CHECK_RETURN((result == napi_ok) && (keyEventObject != nullptr), "create object", false);
        result = MMI::KeyEventNapi::CreateKeyEvent(env, keyEvent, keyEventObject);
        CHECK_RETURN((result == napi_ok) && (keyEventObject != nullptr), "create key event object", false);
        args[0] = keyEventObject;
        return true;
    };
    bool consumeResult = false;
    JsCallbackHandler::Traverse({ callback }, { 1, getKeyEventProperty }, consumeResult);
    if (!consumeOwner) {
        return;
    }
    if (!consumeResult) {
        if (keyEvent != nullptr && keyEvent->GetKeyAction() == MMI::KeyEvent::KEY_ACTION_DOWN) {
            IMSA_HILOGW("keyEvent is not consumed by ime");
        }
        consumeResult = InputMethodAbility::GetInstance().HandleUnconsumedKey(keyEvent);
    }
    auto ret = InputMethodAbility::GetInstance().HandleKeyEventResult(cbId, consumeResult, channelObject);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("handle keyEvent failed:%{public}d", ret);
    }
}
} // namespace MiscServices
} // namespace OHOS
