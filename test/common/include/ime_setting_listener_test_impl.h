/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INPUTMETHOD_IMF_IME_SETTING_LISTENER_TEST_IMPL_H
#define INPUTMETHOD_IMF_IME_SETTING_LISTENER_TEST_IMPL_H

#include <condition_variable>

#include "ime_event_listener.h"

namespace OHOS {
namespace MiscServices {
class ImeSettingListenerTestImpl : public ImeEventListener {
public:
    ImeSettingListenerTestImpl(){};
    ~ImeSettingListenerTestImpl(){};
    void OnImeChange(const Property &property, const SubProperty &subProperty) override;
    void OnImeShow(const ImeWindowInfo &info) override;
    void OnImeHide(const ImeWindowInfo &info) override;
    static void ResetParam();
    static bool WaitPanelHide();
    static bool WaitPanelShow();
    static bool WaitImeChange(const SubProperty &subProperty);
    static bool WaitImeChange();
    static bool WaitTargetImeChange(const std::string &bundleName);

private:
    static InputWindowStatus status_;
    static SubProperty subProperty_;
    static bool isImeChange_;
    static std::mutex imeSettingListenerLock_;
    static std::condition_variable imeSettingListenerCv_;
    static Property property_;
}; // namespace MiscServices
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_IMF_IME_SETTING_LISTENER_TEST_IMPL_H
