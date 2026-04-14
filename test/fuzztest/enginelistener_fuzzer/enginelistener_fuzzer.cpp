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

#include "enginelistener_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "input_method_engine_listener.h"
#include "input_method_property.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace MiscServices {

namespace {
constexpr size_t MIN_INPUT_SIZE = 10;
constexpr size_t MAX_INPUT_SIZE = 1000;
constexpr size_t MAX_CALLBACK_TYPE_LENGTH = 100;
constexpr size_t MAX_STRING_LENGTH = 50;
constexpr size_t MAX_TASK_NAME_LENGTH = 100;
constexpr int LISTENER_COUNT = 3;
} // namespace

class FuzzInputMethodEngineListener : public InputMethodEngineListener {
public:
    FuzzInputMethodEngineListener() = default;
    ~FuzzInputMethodEngineListener() override = default;

    void OnKeyboardStatus(bool isShow) override
    {
        keyboardStatus_ = isShow;
    }

    void OnInputStart() override
    {
        inputStarted_ = true;
    }

    int32_t OnInputStop() override
    {
        inputStarted_ = false;
        return ErrorCode::NO_ERROR;
    }

    void OnSetCallingWindow(uint32_t windowId) override
    {
        callingWindowId_ = windowId;
    }

    void OnSetSubtype(const SubProperty &property) override
    {
        subProperty_ = property;
    }

    void ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) override
    {
        privateCommand_ = privateCommand;
    }

    int32_t OnDiscardTypingText() override
    {
        discardTypingTextCalled_ = true;
        return discardTypingTextResult_;
    }

    void OnSecurityChange(int32_t security) override
    {
        securityLevel_ = security;
    }

    void OnInputFinish() override
    {
        inputFinished_ = true;
    }

    bool IsEnable(uint64_t displayId) override
    {
        return isEnabled_;
    }

    bool IsCallbackRegistered(const std::string &type) override
    {
        auto it = registeredCallbacks_.find(type);
        return it != registeredCallbacks_.end() && it->second;
    }

    bool PostTaskToEventHandler(std::function<void()> task, const std::string &taskName) override
    {
        if (task && postTaskEnabled_) {
            task();
            lastTaskName_ = taskName;
            return true;
        }
        return false;
    }

    void OnCallingDisplayIdChanged(uint64_t callingDisplayId) override
    {
        callingDisplayId_ = callingDisplayId;
    }

    void NotifyPreemption() override
    {
        preemptionNotified_ = true;
    }

    void SetDiscardTypingTextResult(int32_t result)
    {
        discardTypingTextResult_ = result;
    }

    void SetIsEnabled(bool enabled)
    {
        isEnabled_ = enabled;
    }

    void SetPostTaskEnabled(bool enabled)
    {
        postTaskEnabled_ = enabled;
    }

    void RegisterCallback(const std::string &type, bool registered)
    {
        registeredCallbacks_[type] = registered;
    }

private:
    bool keyboardStatus_ = false;
    bool inputStarted_ = false;
    uint32_t callingWindowId_ = 0;
    SubProperty subProperty_;
    std::unordered_map<std::string, PrivateDataValue> privateCommand_;
    int32_t discardTypingTextResult_ = ErrorCode::NO_ERROR;
    bool discardTypingTextCalled_ = false;
    int32_t securityLevel_ = 0;
    bool inputFinished_ = false;
    bool isEnabled_ = true;
    std::unordered_map<std::string, bool> registeredCallbacks_;
    bool postTaskEnabled_ = true;
    std::string lastTaskName_;
    uint64_t callingDisplayId_ = 0;
    bool preemptionNotified_ = false;
};

void FuzzOnDiscardTypingText(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzInputMethodEngineListener>();
    int32_t fuzzedResult = provider.ConsumeIntegral<int32_t>();
    listener->SetDiscardTypingTextResult(fuzzedResult);
    int32_t result = listener->OnDiscardTypingText();
    (void)result;
}

void FuzzOnSecurityChange(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzInputMethodEngineListener>();
    int32_t fuzzedSecurity = provider.ConsumeIntegral<int32_t>();
    listener->OnSecurityChange(fuzzedSecurity);
}

void FuzzOnInputFinish(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzInputMethodEngineListener>();
    listener->OnInputFinish();
}

void FuzzIsEnable(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzInputMethodEngineListener>();
    bool fuzzedEnabled = provider.ConsumeBool();
    uint64_t fuzzedDisplayId = provider.ConsumeIntegral<uint64_t>();
    listener->SetIsEnabled(fuzzedEnabled);
    bool result = listener->IsEnable(fuzzedDisplayId);
    (void)result;
}

void FuzzIsCallbackRegistered(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzInputMethodEngineListener>();
    std::string fuzzedType = provider.ConsumeRandomLengthString(MAX_CALLBACK_TYPE_LENGTH);
    bool fuzzedRegistered = provider.ConsumeBool();
    listener->RegisterCallback(fuzzedType, fuzzedRegistered);
    bool result = listener->IsCallbackRegistered(fuzzedType);
    (void)result;

    std::string anotherType = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    result = listener->IsCallbackRegistered(anotherType);
    (void)result;
}

void FuzzPostTaskToEventHandler(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzInputMethodEngineListener>();
    bool fuzzedPostTaskEnabled = provider.ConsumeBool();
    listener->SetPostTaskEnabled(fuzzedPostTaskEnabled);

    std::string fuzzedTaskName = provider.ConsumeRandomLengthString(MAX_TASK_NAME_LENGTH);
    bool taskExecuted = false;
    std::function<void()> task = [&taskExecuted]() {
        taskExecuted = true;
    };

    bool result = listener->PostTaskToEventHandler(task, fuzzedTaskName);
    (void)result;

    result = listener->PostTaskToEventHandler(nullptr, fuzzedTaskName);
    (void)result;
}

void FuzzOnCallingDisplayIdChanged(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzInputMethodEngineListener>();
    uint64_t fuzzedDisplayId = provider.ConsumeIntegral<uint64_t>();
    listener->OnCallingDisplayIdChanged(fuzzedDisplayId);
}

void FuzzEngineListenerLifecycle(FuzzedDataProvider &provider)
{
    auto engineListener = std::make_shared<FuzzInputMethodEngineListener>();
    engineListener->OnInputStart();
    engineListener->OnSecurityChange(provider.ConsumeIntegral<int32_t>());
    engineListener->OnCallingDisplayIdChanged(provider.ConsumeIntegral<uint64_t>());

    std::string taskName = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    engineListener->PostTaskToEventHandler([]() {}, taskName);

    engineListener->OnDiscardTypingText();
    engineListener->OnInputStop();
}

void FuzzMultipleListeners(FuzzedDataProvider &provider)
{
    for (int i = 0; i < LISTENER_COUNT; i++) {
        auto listener = std::make_shared<FuzzInputMethodEngineListener>();
        listener->SetIsEnabled(provider.ConsumeBool());
        listener->OnSecurityChange(provider.ConsumeIntegral<int32_t>());
    }
}

} // namespace MiscServices
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::MiscServices::MIN_INPUT_SIZE) {
        return 0;
    }

    if (size > OHOS::MiscServices::MAX_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);

    OHOS::MiscServices::FuzzOnDiscardTypingText(provider);
    OHOS::MiscServices::FuzzOnSecurityChange(provider);
    OHOS::MiscServices::FuzzIsEnable(provider);
    OHOS::MiscServices::FuzzIsCallbackRegistered(provider);
    OHOS::MiscServices::FuzzPostTaskToEventHandler(provider);
    OHOS::MiscServices::FuzzOnCallingDisplayIdChanged(provider);
    OHOS::MiscServices::FuzzEngineListenerLifecycle(provider);
    OHOS::MiscServices::FuzzMultipleListeners(provider);

    return 0;
}
