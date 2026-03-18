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

#ifndef IMF_WINDOW_OBSERVERS_MANAGER_H
#define IMF_WINDOW_OBSERVERS_MANAGER_H

#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace OHOS {
namespace MiscServices {
class WindowMonitorsManager {
public:
    static WindowMonitorsManager &GetInstance();
    void SetInited(int32_t userId);
    bool IsInited(int32_t userId);
    void UpdateForegroundUser(int32_t userId, int32_t screenId);
    int32_t GetForegroundUser(int32_t screenId);
    void Reset();

private:
    WindowMonitorsManager() = default;
    ~WindowMonitorsManager() = default;
    std::mutex initedListMtx_;
    std::unordered_set<int32_t> initedUserList_;
    std::mutex foregroundUserMtx_;
    std::unordered_map<int32_t, int32_t> foregroundUsers_; // { key: screenId, value: userId }
};
} // namespace MiscServices
} // namespace OHOS

#endif // IMF_WINDOW_OBSERVERS_MANAGER_H
