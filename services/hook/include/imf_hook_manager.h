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

#ifndef IMF_HOOK_MGR_H
#define IMF_HOOK_MGR_H

#include <atomic>
#include <mutex>
#include <string>

#include "imf_hook.h"
#include "nocopyable.h"
namespace OHOS {
namespace MiscServices {
class ImfHookMgr {
public:
    static ImfHookMgr &GetInstance();
    int32_t ExecuteCurrentImeInfoReportHook(int32_t userId, const std::string &bundleName, int64_t timeStampMs);
    void OnHaServiceStart();

private:
    DISALLOW_COPY_AND_MOVE(ImfHookMgr);
    ImfHookMgr() = default;
    ~ImfHookMgr() = default;
    int32_t ExecuteHook(ImfHookStage stage, void *executionContext, const HOOK_EXEC_OPTIONS *options = nullptr);
    ImeReportedInfo GenerateImeReportedInfo(int32_t userId, const std::string &bundleName, int64_t timeStampMs);
    bool NeedReport(const ImeReportedInfo &info);
    void UpdateImeReportedInfo(const ImeReportedInfo &info);
    std::mutex imeReportedInfoLock_;
    ImeReportedInfo imeReportedInfo_;
    std::atomic<bool> needSetConfig_{ true };
};
} // namespace MiscServices
} // namespace OHOS

#endif // IMF_HOOK_MGR_H