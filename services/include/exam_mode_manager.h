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

#ifndef SERVICES_INCLUDE_EXAM_MODE_MANAGER_H
#define SERVICES_INCLUDE_EXAM_MODE_MANAGER_H

#include <atomic>
#include <mutex>
#include <string>
#include <utility>

#include "global.h"

namespace OHOS {
namespace MiscServices {
class ExamModeManager {
public:
    static constexpr const char *EXAM_MODE_KEY = "settings.inputmethod.exam_mode";
    static ExamModeManager &GetInstance();
    void InitFromPersistedData();
    bool IsExamMode();
    void SetExamMode(bool isExamMode);
    void SavePreviousIme(const std::string &bundleName, const std::string &subName);
    void GetPreviousIme(std::string &bundleName, std::string &subName);
    std::string GetPreviousImeBundleName();
    std::string GetPreviousImeSubName();
    void ClearPreviousIme();

private:
    ExamModeManager() = default;
    ~ExamModeManager() = default;
    void Persist();
    bool LoadFromPersistedData();
    std::atomic<bool> isExamMode_ { false };
    std::mutex previousImeMutex_;
    std::string previousImeBundleName_;
    std::string previousImeSubName_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_EXAM_MODE_MANAGER_H
