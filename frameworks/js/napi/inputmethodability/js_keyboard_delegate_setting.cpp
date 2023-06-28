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

#include "js_keyboard_delegate_setting.h"

#include "event_checker.h"
#include "input_method_ability.h"
#include "js_keyboard_controller_engine.h"
#include "js_text_input_client_engine.h"
#include "js_util.h"
#include "js_utils.h"
#include "key_event_napi.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
namespace OHOS {
namespace MiscServices {
constexpr size_t ARGC_ZERO = 0;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_THREE = 3;
constexpr size_t ARGC_FOUR = 4;
const std::string JsKeyboardDelegateSetting::KDS_CLASS_NAME = "KeyboardDelegate";
thread_local napi_ref JsKeyboardDelegateSetting::KDSRef_ = nullptr;

std::mutex JsKeyboardDelegateSetting::keyboardMutex_;
std::shared_ptr<JsKeyboardDelegateSetting> JsKeyboardDelegateSetting::keyboardDelegate_{ nullptr };

napi_value JsKeyboardDelegateSetting::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_PROPERTY("OPTION_ASCII", GetJsConstProperty(env, static_cast<uint32_t>(20))),
        DECLARE_NAPI_PROPERTY("OPTION_NONE", GetJsConstProperty(env, static_cast<uint32_t>(0))),
        DECLARE_NAPI_PROPERTY("OPTION_AUTO_CAP_CHARACTERS", GetJsConstProperty(env, static_cast<uint32_t>(2))),
        DECLARE_NAPI_PROPERTY("OPTION_AUTO_CAP_SENTENCES", GetJsConstProperty(env, static_cast<uint32_t>(8))),
        DECLARE_NAPI_PROPERTY("OPTION_AUTO_WORDS", GetJsConstProperty(env, static_cast<uint32_t>(4))),
        DECLARE_NAPI_PROPERTY("OPTION_MULTI_LINE", GetJsConstProperty(env, static_cast<uint32_t>(1))),
        DECLARE_NAPI_PROPERTY("OPTION_NO_FULLSCREEN", GetJsConstProperty(env, static_cast<uint32_t>(10))),
        DECLARE_NAPI_PROPERTY("CURSOR_UP", GetJsConstProperty(env, static_cast<uint32_t>(1))),
        DECLARE_NAPI_PROPERTY("CURSOR_DOWN", GetJsConstProperty(env, static_cast<uint32_t>(2))),
        DECLARE_NAPI_PROPERTY("CURSOR_LEFT", GetJsConstProperty(env, static_cast<uint32_t>(3))),
        DECLARE_NAPI_PROPERTY("CURSOR_RIGHT", GetJsConstProperty(env, static_cast<uint32_t>(4))),

        DECLARE_NAPI_PROPERTY("FLAG_SELECTING", GetJsConstProperty(env, static_cast<uint32_t>(2))),
        DECLARE_NAPI_PROPERTY("FLAG_SINGLE_LINE", GetJsConstProperty(env, static_cast<uint32_t>(1))),

        DECLARE_NAPI_PROPERTY("DISPLAY_MODE_PART", GetJsConstProperty(env, static_cast<uint32_t>(0))),
        DECLARE_NAPI_PROPERTY("DISPLAY_MODE_FULL", GetJsConstProperty(env, static_cast<uint32_t>(1))),
        DECLARE_NAPI_PROPERTY("WINDOW_TYPE_INPUT_METHOD_FLOAT", GetJsConstProperty(env, static_cast<uint32_t>(2105))),

        DECLARE_NAPI_FUNCTION("createKeyboardDelegate", CreateKeyboardDelegate),
        DECLARE_NAPI_FUNCTION("getKeyboardDelegate", GetKeyboardDelegate),
    };
    NAPI_CALL(
        env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("on", Subscribe),
        DECLARE_NAPI_FUNCTION("off", UnSubscribe),
    };
    napi_value cons = nullptr;
    NAPI_CALL(env, napi_define_class(env, KDS_CLASS_NAME.c_str(), KDS_CLASS_NAME.size(), JsConstructor, nullptr,
                       sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &KDSRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, KDS_CLASS_NAME.c_str(), cons));
    return exports;
};

napi_value JsKeyboardDelegateSetting::GetJsConstProperty(napi_env env, uint32_t num)
{
    napi_value jsNumber = nullptr;
    napi_create_int32(env, num, &jsNumber);
    return jsNumber;
};

std::shared_ptr<JsKeyboardDelegateSetting> JsKeyboardDelegateSetting::GetKeyboardDelegateSetting()
{
    if (keyboardDelegate_ == nullptr) {
        std::lock_guard<std::mutex> lock(keyboardMutex_);
        if (keyboardDelegate_ == nullptr) {
            auto delegate = std::make_shared<JsKeyboardDelegateSetting>();
            if (delegate == nullptr) {
                IMSA_HILOGE("keyboard delegate nullptr");
                return nullptr;
            }
            keyboardDelegate_ = delegate;
        }
    }
    return keyboardDelegate_;
}

bool JsKeyboardDelegateSetting::InitKeyboardDelegate()
{
    if (InputMethodAbility::GetInstance()->SetCoreAndAgent() != ErrorCode::NO_ERROR) {
        return false;
    }
    auto delegate = GetKeyboardDelegateSetting();
    if (delegate == nullptr) {
        return false;
    }
    InputMethodAbility::GetInstance()->SetKdListener(delegate);
    return true;
}

napi_value JsKeyboardDelegateSetting::JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    IMSA_HILOGI("run in JsConstructor");
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr));
    auto delegate = GetKeyboardDelegateSetting();
    if (delegate == nullptr || !InitKeyboardDelegate()) {
        IMSA_HILOGE("failed to get delegate");
        napi_value result = nullptr;
        napi_get_null(env, &result);
        return result;
    }
    napi_status status = napi_wrap(
        env, thisVar, delegate.get(), [](napi_env env, void *nativeObject, void *hint) {}, nullptr, nullptr);
    if (status != napi_ok) {
        IMSA_HILOGE("JsKeyboardDelegateSetting napi_wrap failed: %{public}d", status);
        return nullptr;
    }
    if (delegate->loop_ == nullptr) {
        napi_get_uv_event_loop(env, &delegate->loop_);
    }
    return thisVar;
};

napi_value JsKeyboardDelegateSetting::CreateKeyboardDelegate(napi_env env, napi_callback_info info)
{
    return GetKDInstance(env, info);
}

napi_value JsKeyboardDelegateSetting::GetKeyboardDelegate(napi_env env, napi_callback_info info)
{
    return GetKDInstance(env, info);
}

napi_value JsKeyboardDelegateSetting::GetKDInstance(napi_env env, napi_callback_info info)
{
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, KDSRef_, &cons) != napi_ok) {
        IMSA_HILOGE("napi_get_reference_value(env, KDSRef_, &cons) != napi_ok");
        return nullptr;
    }
    IMSA_HILOGE("Get a reference to the global variable appAccountRef_ complete");
    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        IMSA_HILOGE("napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok");
        return nullptr;
    }
    return instance;
}

void JsKeyboardDelegateSetting::RegisterListener(
    napi_value callback, std::string type, std::shared_ptr<JSCallbackObject> callbackObj)
{
    IMSA_HILOGI("RegisterListener %{public}s", type.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (jsCbMap_.empty() || jsCbMap_.find(type) == jsCbMap_.end()) {
        IMSA_HILOGE("methodName %{public}s not registered!", type.c_str());
    }
    auto callbacks = jsCbMap_[type];
    bool ret = std::any_of(callbacks.begin(), callbacks.end(), [&callback](std::shared_ptr<JSCallbackObject> cb) {
        return JsUtils::Equals(cb->env_, callback, cb->callback_, cb->threadId_);
    });
    if (ret) {
        IMSA_HILOGE("JsKeyboardDelegateSetting::RegisterListener callback already registered!");
        return;
    }

    IMSA_HILOGI("Add %{public}s callbackObj into jsCbMap_", type.c_str());
    jsCbMap_[type].push_back(std::move(callbackObj));
}

void JsKeyboardDelegateSetting::UnRegisterListener(napi_value callback, std::string type)
{
    IMSA_HILOGI("UnRegisterListener %{public}s", type.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (jsCbMap_.empty() || jsCbMap_.find(type) == jsCbMap_.end()) {
        IMSA_HILOGE("methodName %{public}s not unRegistered!", type.c_str());
        return;
    }

    if (callback == nullptr) {
        jsCbMap_.erase(type);
        IMSA_HILOGE("callback is nullptr");
        return;
    }

    for (auto item = jsCbMap_[type].begin(); item != jsCbMap_[type].end(); item++) {
        if ((callback != nullptr) &&
            (JsUtils::Equals((*item)->env_, callback, (*item)->callback_, (*item)->threadId_))) {
            jsCbMap_[type].erase(item);
            break;
        }
    }
    if (jsCbMap_[type].empty()) {
        jsCbMap_.erase(type);
    }
}

napi_value JsKeyboardDelegateSetting::Subscribe(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_TWO;
    napi_value argv[ARGC_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    std::string type;
    // 2 means least param num.
    if (argc < 2 || !JsUtil::GetValue(env, argv[0], type)
        || !EventChecker::IsValidEventType(EventSubscribeModule::KEYBOARD_DELEGATE, type)
        || JsUtil::GetType(env, argv[1]) != napi_function) {
        IMSA_HILOGE("Subscribe failed, type:%{public}s", type.c_str());
        return nullptr;
    }
    IMSA_HILOGD("Subscribe type:%{public}s.", type.c_str());
    auto engine = reinterpret_cast<JsKeyboardDelegateSetting *>(JsUtils::GetNativeSelf(env, info));
    if (engine == nullptr) {
        return nullptr;
    }
    std::shared_ptr<JSCallbackObject> callback =
        std::make_shared<JSCallbackObject>(env, argv[1], std::this_thread::get_id());
    engine->RegisterListener(argv[ARGC_ONE], type, callback);

    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value JsKeyboardDelegateSetting::UnSubscribe(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_TWO;
    napi_value argv[ARGC_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    std::string type;
    // 1 means least param num.
    if (argc < 1 || !JsUtil::GetValue(env, argv[0], type)
        || !EventChecker::IsValidEventType(EventSubscribeModule::KEYBOARD_DELEGATE, type)) {
        IMSA_HILOGE("UnSubscribe failed, type:%{public}s", type.c_str());
        return nullptr;
    }
    // If the type of optional parameter is wrong, make it nullptr
    if (JsUtil::GetType(env, argv[1]) != napi_function) {
        argv[1] = nullptr;
    }
    IMSA_HILOGD("UnSubscribe type:%{public}s.", type.c_str());
    auto delegate = reinterpret_cast<JsKeyboardDelegateSetting *>(JsUtils::GetNativeSelf(env, info));
    if (delegate == nullptr) {
        return nullptr;
    }
    delegate->UnRegisterListener(argv[ARGC_ONE], type);
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value JsKeyboardDelegateSetting::GetResultOnKeyEvent(napi_env env, int32_t keyCode, int32_t keyStatus)
{
    napi_value KeyboardDelegate = nullptr;
    napi_create_object(env, &KeyboardDelegate);

    napi_value jsKeyCode = nullptr;
    napi_create_int32(env, keyCode, &jsKeyCode);
    napi_set_named_property(env, KeyboardDelegate, "keyCode", jsKeyCode);

    napi_value jsKeyAction = nullptr;
    napi_create_int32(env, keyStatus, &jsKeyAction);
    napi_set_named_property(env, KeyboardDelegate, "keyAction", jsKeyAction);

    return KeyboardDelegate;
}

bool JsKeyboardDelegateSetting::OnFullKeyEvent(const std::shared_ptr<MMI::KeyEvent> &keyEvent)
{
    IMSA_HILOGD("run in");
    std::string type = "keyEvent";
    auto isDone = std::make_shared<BlockData<bool>>(MAX_TIMEOUT, false);
    uv_work_t *work = GetUVwork(type, [&keyEvent, isDone](UvEntry &entry) {
        entry.pullKeyEventPara = keyEvent;
        entry.isDone = isDone;
    });
    if (work == nullptr) {
        IMSA_HILOGE("failed to get uv work");
        return false;
    }
    uv_queue_work(
        loop_, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            std::shared_ptr<UvEntry> entry(static_cast<UvEntry *>(work->data), [work](UvEntry *data) {
                delete data;
                delete work;
            });
            auto getKeyEventProperty = [entry](napi_value *args, uint8_t argc,
                                           std::shared_ptr<JSCallbackObject> item) -> bool {
                if (argc == 0) {
                    return false;
                }
                napi_value keyEventObject{};
                auto result = napi_create_object(item->env_, &keyEventObject);
                CHECK_RETURN((result == napi_ok) && (keyEventObject != nullptr), "create object", false);
                result = MMI::KeyEventNapi::CreateKeyEvent(item->env_, entry->pullKeyEventPara, keyEventObject);
                CHECK_RETURN((result == napi_ok) && (keyEventObject != nullptr), "create key event object", false);
                args[ARGC_ZERO] = { keyEventObject };
                return true;
            };
            bool isOnKeyEvent = JsUtils::TraverseCallback(entry->vecCopy, ARGC_ONE, getKeyEventProperty);
            entry->isDone->SetValue(isOnKeyEvent);
        });
    bool isConsume = isDone->GetValue();
    IMSA_HILOGI("key event handle result: %{public}d", isConsume);
    return isConsume;
}

bool JsKeyboardDelegateSetting::OnKeyEvent(int32_t keyCode, int32_t keyStatus)
{
    IMSA_HILOGD("run in");
    KeyEventPara para{ keyCode, keyStatus, false };
    std::string type = (keyStatus == ARGC_TWO ? "keyDown" : "keyUp");
    auto isDone = std::make_shared<BlockData<bool>>(MAX_TIMEOUT, false);
    uv_work_t *work = GetUVwork(type, [&para, isDone](UvEntry &entry) {
        entry.keyEventPara = { para.keyCode, para.keyStatus, para.isOnKeyEvent };
        entry.isDone = isDone;
    });
    if (work == nullptr) {
        IMSA_HILOGE("failed to get uv work");
        return false;
    }
    uv_queue_work(
        loop_, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            std::shared_ptr<UvEntry> entry(static_cast<UvEntry *>(work->data), [work](UvEntry *data) {
                delete data;
                delete work;
            });
            auto getKeyEventProperty = [entry](napi_value *args, uint8_t argc,
                                           std::shared_ptr<JSCallbackObject> item) -> bool {
                if (argc == 0) {
                    return false;
                }
                napi_value jsObject =
                    GetResultOnKeyEvent(item->env_, entry->keyEventPara.keyCode, entry->keyEventPara.keyStatus);
                if (jsObject == nullptr) {
                    IMSA_HILOGE("get GetResultOnKeyEvent failed: jsObject is nullptr");
                    return false;
                }
                args[ARGC_ZERO] = { jsObject };
                return true;
            };
            bool isOnKeyEvent = JsUtils::TraverseCallback(entry->vecCopy, ARGC_ONE, getKeyEventProperty);
            entry->isDone->SetValue(isOnKeyEvent);
        });
    bool isConsume = isDone->GetValue();
    IMSA_HILOGI("key event handle result: %{public}d", isConsume);
    return isConsume;
}

void JsKeyboardDelegateSetting::OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height)
{
    IMSA_HILOGD("run in");
    CursorPara para{ positionX, positionY, height };
    std::string type = "cursorContextChange";
    uv_work_t *work = GetUVwork(type, [&para](UvEntry &entry) {
        entry.curPara.positionX = para.positionX;
        entry.curPara.positionY = para.positionY;
        entry.curPara.height = para.height;
    });
    if (work == nullptr) {
        IMSA_HILOGD("failed to get uv entry");
        return;
    }
    uv_queue_work(
        loop_, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            std::shared_ptr<UvEntry> entry(static_cast<UvEntry *>(work->data), [work](UvEntry *data) {
                delete data;
                delete work;
            });

            auto getCursorUpdateProperty = [entry](napi_value *args, uint8_t argc,
                                               std::shared_ptr<JSCallbackObject> item) -> bool {
                if (argc < 3) {
                    return false;
                }
                napi_create_int32(item->env_, entry->curPara.positionX, &args[ARGC_ZERO]);
                napi_create_int32(item->env_, entry->curPara.positionY, &args[ARGC_ONE]);
                napi_create_int32(item->env_, entry->curPara.height, &args[ARGC_TWO]);
                return true;
            };
            JsUtils::TraverseCallback(entry->vecCopy, ARGC_THREE, getCursorUpdateProperty);
        });
}

void JsKeyboardDelegateSetting::OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd)
{
    IMSA_HILOGD("run in");
    SelectionPara para{ oldBegin, oldEnd, newBegin, newEnd };
    std::string type = "selectionChange";
    uv_work_t *work = GetUVwork(type, [&para](UvEntry &entry) {
        entry.selPara.oldBegin = para.oldBegin;
        entry.selPara.oldEnd = para.oldEnd;
        entry.selPara.newBegin = para.newBegin;
        entry.selPara.newEnd = para.newEnd;
    });
    if (work == nullptr) {
        IMSA_HILOGD("failed to get uv entry");
        return;
    }
    uv_queue_work(
        loop_, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            std::shared_ptr<UvEntry> entry(static_cast<UvEntry *>(work->data), [work](UvEntry *data) {
                delete data;
                delete work;
            });

            auto getSelectionChangeProperty = [entry](napi_value *args, uint8_t argc,
                                                  std::shared_ptr<JSCallbackObject> item) -> bool {
                if (argc < 4) {
                    return false;
                }
                napi_create_int32(item->env_, entry->selPara.oldBegin, &args[ARGC_ZERO]);
                napi_create_int32(item->env_, entry->selPara.oldEnd, &args[ARGC_ONE]);
                napi_create_int32(item->env_, entry->selPara.newBegin, &args[ARGC_TWO]);
                napi_create_int32(item->env_, entry->selPara.newEnd, &args[ARGC_THREE]);
                return true;
            };
            JsUtils::TraverseCallback(entry->vecCopy, ARGC_FOUR, getSelectionChangeProperty);
        });
}

void JsKeyboardDelegateSetting::OnTextChange(const std::string &text)
{
    IMSA_HILOGD("run in");
    std::string type = "textChange";
    uv_work_t *work = GetUVwork(type, [&text](UvEntry &entry) { entry.text = text; });
    if (work == nullptr) {
        IMSA_HILOGD("failed to get uv entry");
        return;
    }
    uv_queue_work(
        loop_, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            std::shared_ptr<UvEntry> entry(static_cast<UvEntry *>(work->data), [work](UvEntry *data) {
                delete data;
                delete work;
            });

            auto getTextChangeProperty = [entry](napi_value *args, uint8_t argc,
                                             std::shared_ptr<JSCallbackObject> item) -> bool {
                if (argc == 0) {
                    return false;
                }
                napi_create_string_utf8(item->env_, entry->text.c_str(), NAPI_AUTO_LENGTH, &args[ARGC_ZERO]);
                return true;
            };
            JsUtils::TraverseCallback(entry->vecCopy, ARGC_ONE, getTextChangeProperty);
        });
}

uv_work_t *JsKeyboardDelegateSetting::GetUVwork(const std::string &type, EntrySetter entrySetter)
{
    IMSA_HILOGD("run in, type: %{public}s", type.c_str());
    UvEntry *entry = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        if (jsCbMap_[type].empty()) {
            IMSA_HILOGE("%{public}s cb-vector is empty", type.c_str());
            return nullptr;
        }
        entry = new (std::nothrow) UvEntry(jsCbMap_[type], type);
        if (entry == nullptr) {
            IMSA_HILOGE("entry ptr is nullptr!");
            return nullptr;
        }
        if (entrySetter != nullptr) {
            entrySetter(*entry);
        }
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        IMSA_HILOGE("entry ptr is nullptr!");
        return nullptr;
    }
    work->data = entry;
    return work;
}
} // namespace MiscServices
} // namespace OHOS
