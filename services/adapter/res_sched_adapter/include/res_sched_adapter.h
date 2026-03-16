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

#ifndef INPUTMETHOD_IMF_RES_SCHED_ADAPTER_H
#define INPUTMETHOD_IMF_RES_SCHED_ADAPTER_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace OHOS {
namespace MiscServices {
class ResSchedAdapter final {
public:
    static void NotifyPanelStatus(bool isPanelShow);
    static void ResetPanelStatusFlag(uint32_t pid);
    
private:
    static std::mutex lastPanelStatusMapLock_;
    static std::map<uint32_t, bool> lastPanelStatusMap_;
};
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_IMF_RES_SCHED_ADAPTER_H