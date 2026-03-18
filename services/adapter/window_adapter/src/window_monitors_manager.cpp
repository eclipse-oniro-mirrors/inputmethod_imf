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

#include "window_monitors_manager.h"

#include "global.h"
#include <cinttypes>

namespace OHOS {
namespace MiscServices {
WindowMonitorsManager &WindowMonitorsManager::GetInstance()
{
    static WindowMonitorsManager windowMonitorsManager;
    return windowMonitorsManager;
}

void WindowMonitorsManager::Reset()
{
    {
        std::lock_guard<std::mutex> lock(initedListMtx_);
        initedUserList_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(foregroundUserMtx_);
        foregroundUsers_.clear();
    }
    IMSA_HILOGI("end");
}

void WindowMonitorsManager::SetInited(int32_t userId)
{
    std::lock_guard<std::mutex> lock(initedListMtx_);
    initedUserList_.insert(userId);
    IMSA_HILOGD("userId: %{public}d", userId);
}

bool WindowMonitorsManager::IsInited(int32_t userId)
{
    std::lock_guard<std::mutex> lock(initedListMtx_);
    bool isInited = initedUserList_.find(userId) != initedUserList_.end();
    IMSA_HILOGD("userId %{public}d, isInited: %{public}d", userId, isInited);
    return isInited;
}

void WindowMonitorsManager::UpdateForegroundUser(int32_t userId, int32_t screenId)
{
    std::lock_guard<std::mutex> lock(foregroundUserMtx_);
    foregroundUsers_[screenId] = userId;
    IMSA_HILOGI("userId %{public}d, screenId: %{public}d", userId, screenId);
}

int32_t WindowMonitorsManager::GetForegroundUser(int32_t screenId)
{
    std::lock_guard<std::mutex> lock(foregroundUserMtx_);
    auto iter = foregroundUsers_.find(screenId);
    if (iter == foregroundUsers_.end()) {
        IMSA_HILOGE("display %{public}d user not found", screenId);
        return -1;
    }
    auto userId = iter->second;
    IMSA_HILOGD("screenId: %{public}d, userId: %{public}d", screenId, userId);
    return userId;
}
} // namespace MiscServices
} // namespace OHOS