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

#include "imeeventlistener_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "ime_event_listener.h"
#include "input_method_property.h"
#include "input_window_info.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace MiscServices {

namespace {
constexpr size_t MIN_INPUT_SIZE = 10;
constexpr size_t MAX_INPUT_SIZE = 1000;
constexpr size_t MAX_STRING_LENGTH = 50;
constexpr size_t MAX_MODE_LENGTH = 20;
constexpr size_t MAX_LOCALE_LENGTH = 20;
constexpr size_t MAX_LANGUAGE_LENGTH = 20;
constexpr size_t MAX_NAME_LENGTH = 30;
} // namespace

class FuzzImeEventListener : public ImeEventListener {
public:
    FuzzImeEventListener() = default;
    ~FuzzImeEventListener() override = default;

    void OnImeChange(const Property &property, const SubProperty &subProperty) override
    {
        imeChangeProperty_ = property;
        imeChangeSubProperty_ = subProperty;
        imeChangeCalled_ = true;
    }

    void OnImeShow(const ImeWindowInfo &info) override
    {
        imeShowInfo_ = info;
        imeShowCalled_ = true;
    }

    void OnImeHide(const ImeWindowInfo &info) override
    {
        imeHideInfo_ = info;
        imeHideCalled_ = true;
    }

    void OnInputStart(uint32_t callingWndId, int32_t requestKeyboardReason) override
    {
        inputStartCallingWndId_ = callingWndId;
        inputStartKeyboardReason_ = requestKeyboardReason;
        inputStartCalled_ = true;
    }

    void OnInputStop() override
    {
        inputStopCalled_ = true;
    }

    bool GetImeChangeCalled() const
    {
        return imeChangeCalled_;
    }

    bool GetImeShowCalled() const
    {
        return imeShowCalled_;
    }

    bool GetImeHideCalled() const
    {
        return imeHideCalled_;
    }

    bool GetInputStartCalled() const
    {
        return inputStartCalled_;
    }

    bool GetInputStopCalled() const
    {
        return inputStopCalled_;
    }

private:
    Property imeChangeProperty_;
    SubProperty imeChangeSubProperty_;
    bool imeChangeCalled_ = false;
    ImeWindowInfo imeShowInfo_;
    bool imeShowCalled_ = false;
    ImeWindowInfo imeHideInfo_;
    bool imeHideCalled_ = false;
    uint32_t inputStartCallingWndId_ = 0;
    int32_t inputStartKeyboardReason_ = 0;
    bool inputStartCalled_ = false;
    bool inputStopCalled_ = false;
};

void FuzzOnImeChange(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzImeEventListener>();

    Property property;
    property.name = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    property.id = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    property.label = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    property.labelId = provider.ConsumeIntegral<uint32_t>();
    property.icon = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    property.iconId = provider.ConsumeIntegral<uint32_t>();

    SubProperty subProperty;
    subProperty.name = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    subProperty.id = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    subProperty.label = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    subProperty.labelId = provider.ConsumeIntegral<uint32_t>();
    subProperty.icon = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    subProperty.iconId = provider.ConsumeIntegral<uint32_t>();
    subProperty.mode = provider.ConsumeRandomLengthString(MAX_MODE_LENGTH);
    subProperty.locale = provider.ConsumeRandomLengthString(MAX_LOCALE_LENGTH);
    subProperty.language = provider.ConsumeRandomLengthString(MAX_LANGUAGE_LENGTH);

    listener->OnImeChange(property, subProperty);
}

void FuzzOnImeShow(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzImeEventListener>();

    ImeWindowInfo info;
    info.panelInfo.panelType = static_cast<PanelType>(provider.ConsumeIntegral<uint32_t>());
    info.panelInfo.panelFlag = static_cast<PanelFlag>(provider.ConsumeIntegral<uint32_t>());
    info.windowInfo.left = provider.ConsumeIntegral<int32_t>();
    info.windowInfo.top = provider.ConsumeIntegral<int32_t>();
    info.windowInfo.width = provider.ConsumeIntegral<uint32_t>();
    info.windowInfo.height = provider.ConsumeIntegral<uint32_t>();

    listener->OnImeShow(info);
}

void FuzzOnImeHide(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzImeEventListener>();

    ImeWindowInfo info;
    info.panelInfo.panelType = static_cast<PanelType>(provider.ConsumeIntegral<uint32_t>());
    info.panelInfo.panelFlag = static_cast<PanelFlag>(provider.ConsumeIntegral<uint32_t>());
    info.windowInfo.left = provider.ConsumeIntegral<int32_t>();
    info.windowInfo.top = provider.ConsumeIntegral<int32_t>();
    info.windowInfo.width = provider.ConsumeIntegral<uint32_t>();
    info.windowInfo.height = provider.ConsumeIntegral<uint32_t>();

    listener->OnImeHide(info);
}

void FuzzOnInputStart(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<FuzzImeEventListener>();
    uint32_t fuzzedCallingWndId = provider.ConsumeIntegral<uint32_t>();
    int32_t fuzzedKeyboardReason = provider.ConsumeIntegral<int32_t>();
    listener->OnInputStart(fuzzedCallingWndId, fuzzedKeyboardReason);
}

void FuzzImeEventListenerCycle(FuzzedDataProvider &provider)
{
    auto imeListener = std::make_shared<FuzzImeEventListener>();
    Property prop;
    prop.name = provider.ConsumeRandomLengthString(MAX_NAME_LENGTH);
    SubProperty subProp;
    subProp.name = provider.ConsumeRandomLengthString(MAX_NAME_LENGTH);
    imeListener->OnImeChange(prop, subProp);

    ImeWindowInfo windowInfo;
    windowInfo.windowInfo.width = provider.ConsumeIntegral<uint32_t>();
    windowInfo.windowInfo.height = provider.ConsumeIntegral<uint32_t>();

    imeListener->OnInputStart(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<int32_t>());
    imeListener->OnImeShow(windowInfo);
    imeListener->OnImeHide(windowInfo);
    imeListener->OnInputStop();
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

    OHOS::MiscServices::FuzzOnImeChange(provider);
    OHOS::MiscServices::FuzzOnImeShow(provider);
    OHOS::MiscServices::FuzzOnImeHide(provider);
    OHOS::MiscServices::FuzzOnInputStart(provider);
    OHOS::MiscServices::FuzzImeEventListenerCycle(provider);

    return 0;
}
