/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef INPUTMETHOD_IMF_INPUT_METHOD_ENGINE_LISTENER_H
#define INPUTMETHOD_IMF_INPUT_METHOD_ENGINE_LISTENER_H

#include "input_method_property.h"
#include "input_method_utils.h"

namespace OHOS {
namespace MiscServices {
class InputMethodEngineListener {
public:
    virtual ~InputMethodEngineListener() = default;
    virtual void OnKeyboardStatus(bool isShow)
    {
    }
    virtual void OnInputStart()
    {
    }
    virtual int32_t OnInputStop()
    {
        return ErrorCode::NO_ERROR;
    }
    virtual int32_t OnDiscardTypingText()
    {
        return ErrorCode::NO_ERROR;
    }
    virtual void OnSecurityChange(int32_t security)
    {
    }
    virtual void OnSetCallingWindow(uint32_t windowId)
    {
    }
    virtual void OnSetSubtype(const SubProperty &property)
    {
    }
    virtual void ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
    {
    }
    virtual void OnInputFinish()
    {
    }
    /**
     * @brief Whether to enable SA Proxy.
     *
     * If the SA has registered a global proxy input method.
     * This function will be invoked during the binding process when the edit box gains focus.
     *
     * @param displayId Indicates the screen whether to enable the SA Proxy
     * @return
     *     Returns true if SA Proxy needs to be enabled.
     *     Returns false if SA Proxy does not need to be enabled.
     */
    virtual bool IsEnable(uint64_t displayId)
    {
        return true;
    }
    virtual bool IsCallbackRegistered(const std::string &type)
    {
        return false;
    }
    virtual bool PostTaskToEventHandler(std::function<void()> task, const std::string &taskName)
    {
        return false;
    }
    virtual void OnCallingDisplayIdChanged(uint64_t callingDisplayId)
    {
    }
    /**
     * @brief Notify the SA Proxy that it has been preempted.
     *
     * If an SA Proxy is already bound to the edit box that gains focus and a new SA Proxy is registered,
     * this function will be invoked.
     */
    virtual void NotifyPreemption()
    {
    }
    virtual void OnUnregister()
    {
    }
};
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_IMF_INPUT_METHOD_ENGINE_LISTENER_H
