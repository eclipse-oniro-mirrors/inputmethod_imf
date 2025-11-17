/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "window_adapter.h"

#include <cinttypes>
#include <ranges>

#include "global.h"
#include "window.h"
#include "wm_common.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::Rosen;
using WMError = OHOS::Rosen::WMError;
#ifdef SCENE_BOARD_ENABLE
constexpr int32_t MAX_TIMEOUT = 5000; //5ms
#endif
// LCOV_EXCL_START
WindowAdapter::~WindowAdapter()
{
}

WindowAdapter &WindowAdapter::GetInstance()
{
    static WindowAdapter windowAdapter;
    return windowAdapter;
}
// LCOV_EXCL_STOP
void WindowAdapter::GetFocusInfo(OHOS::Rosen::FocusChangeInfo &focusInfo, uint64_t displayId)
{
#ifdef SCENE_BOARD_ENABLE
    WindowManagerLite::GetInstance().GetFocusWindowInfo(focusInfo, displayId);
#else
    WindowManager::GetInstance().GetFocusWindowInfo(focusInfo, displayId);
#endif
}

bool WindowAdapter::GetCallingWindowInfo(
    const uint32_t windId, const int32_t userId, CallingWindowInfo &callingWindowInfo)
{
#ifdef SCENE_BOARD_ENABLE
    IMSA_HILOGD("[%{public}d,%{public}d] run in.", userId, windId);
    callingWindowInfo.windowId_ = static_cast<int32_t>(windId);
    callingWindowInfo.userId_ = userId;
    int64_t start =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    auto wmErr = WindowManagerLite::GetInstance().GetCallingWindowInfo(callingWindowInfo);
    int64_t end =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    int64_t durTime = end - start;
    if (durTime > MAX_TIMEOUT) {
        IMSA_HILOGW("GetCallingWindowInfo cost [%{public}d]us", durTime);
    }
    if (wmErr != WMError::WM_OK) {
        IMSA_HILOGE("[%{public}d,%{public}d,%{public}d] failed to get calling window info.", userId, windId, wmErr);
        return false;
    }
    IMSA_HILOGD("callingWindowInfo:%{public}s",
        WindowDisplayChangeListener::CallingWindowInfoToString(callingWindowInfo).c_str());
    return true;
#else
    IMSA_HILOGE("capability not supported");
    return false;
#endif
}
// LCOV_EXCL_START
void WindowAdapter::RegisterCallingWindowInfoChangedListener(const WindowDisplayChangeHandler &handle)
{
#ifdef SCENE_BOARD_ENABLE
    sptr<WindowDisplayChangeListener> listener = new (std::nothrow) WindowDisplayChangeListener(handle);
    if (listener == nullptr) {
        IMSA_HILOGE("failed to create listener");
        return;
    }
    auto wmErr = WindowManagerLite::GetInstance().RegisterCallingWindowDisplayChangedListener(listener);
    IMSA_HILOGI("register focus changed listener ret: %{public}d", wmErr);
#endif
}
// LCOV_EXCL_STOP
bool WindowAdapter::ListWindowInfo(std::vector<sptr<OHOS::Rosen::WindowInfo>> &windowInfos)
{
#ifdef SCENE_BOARD_ENABLE
    WindowInfoOption option;
    WMError ret = WindowManagerLite::GetInstance().ListWindowInfo(option, windowInfos);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("ListWindowInfo failed, ret: %{public}d", ret);
        return false;
    }
    return true;
#else
    IMSA_HILOGE("capability not supported");
    return false;
#endif
}

uint64_t WindowAdapter::GetDisplayIdByToken(sptr<IRemoteObject> abilityToken)
{
#ifdef SCENE_BOARD_ENABLE
    OHOS::Rosen::MainWindowInfo info;
    WMError ret = WindowManagerLite::GetInstance().GetMainWindowInfoByToken(abilityToken, info);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("GetMainWindowInfoByToken failed, ret: %{public}d", ret);
        return DEFAULT_DISPLAY_ID;
    }
    IMSA_HILOGI("GetMainWindowInfoByToken, displayId: %{public}" PRIu64 "", info.displayId_);
    return info.displayId_;
#else
    IMSA_HILOGE("capability not supported");
    return DEFAULT_DISPLAY_ID;
#endif
}

uint64_t WindowAdapter::GetDisplayIdByWindowId(int32_t callingWindowId)
{
#ifdef SCENE_BOARD_ENABLE
    if (callingWindowId == DEFAULT_DISPLAY_ID) {
        FocusChangeInfo info;
        WindowManagerLite::GetInstance().GetFocusWindowInfo(info);
        callingWindowId = info.windowId_;
    }
    std::vector<sptr<WindowInfo>> windowInfos;
    if (!ListWindowInfo(windowInfos)) {
        return DEFAULT_DISPLAY_ID;
    }
    auto iter = std::find_if(windowInfos.begin(), windowInfos.end(), [&callingWindowId](const auto &windowInfo) {
        if (windowInfo == nullptr) {
            return false;
        }
        return windowInfo->windowMetaInfo.windowId == callingWindowId;
    });
    if (iter == windowInfos.end()) {
        IMSA_HILOGE("not found window info with windowId: %{public}d", callingWindowId);
        return DEFAULT_DISPLAY_ID;
    }
    auto callingDisplayId = (*iter)->windowDisplayInfo.displayId;
    IMSA_HILOGD("window windowId: %{public}d, displayId: %{public}" PRIu64 "", callingWindowId, callingDisplayId);
    return callingDisplayId;
#else
    IMSA_HILOGI("capability not supported");
    return DEFAULT_DISPLAY_ID;
#endif
}

uint64_t WindowAdapter::GetDisplayIdByPid(int64_t callingPid)
{
#ifdef SCENE_BOARD_ENABLE
    std::vector<sptr<WindowInfo>> windowInfos;
    if (!ListWindowInfo(windowInfos)) {
        return DEFAULT_DISPLAY_ID;
    }
    auto iter = std::find_if(windowInfos.begin(), windowInfos.end(), [&callingPid](const auto &windowInfo) {
        if (windowInfo == nullptr) {
            return false;
        }
        return windowInfo->windowMetaInfo.pid == callingPid;
    });
    if (iter == windowInfos.end()) {
        IMSA_HILOGE("not found window info with pid: %{public}" PRId64 "", callingPid);
        return DEFAULT_DISPLAY_ID;
    }
    auto callingDisplayId = (*iter)->windowDisplayInfo.displayId;
    IMSA_HILOGD("window pid: %{public}" PRId64 ", displayId: %{public}" PRIu64 "", callingPid, callingDisplayId);
    return callingDisplayId;
#else
    IMSA_HILOGI("capability not supported");
    return DEFAULT_DISPLAY_ID;
#endif
}

bool WindowAdapter::GetDisplayId(int64_t callingPid, uint64_t &displayId)
{
    displayId = DEFAULT_DISPLAY_ID;
#ifdef SCENE_BOARD_ENABLE
    std::vector<sptr<WindowInfo>> windowInfos;
    if (!ListWindowInfo(windowInfos)) {
        return false;
    }
    auto iter = std::find_if(windowInfos.begin(), windowInfos.end(), [&callingPid](const auto &windowInfo) {
        if (windowInfo == nullptr) {
            return false;
        }
        return windowInfo->windowMetaInfo.pid == callingPid;
    });
    if (iter == windowInfos.end()) {
        IMSA_HILOGE("not found window info with pid: %{public}" PRId64 "", callingPid);
        return false;
    }
    auto callingDisplayId = (*iter)->windowDisplayInfo.displayId;
    IMSA_HILOGD("window pid: %{public}" PRId64 ", displayId: %{public}" PRIu64 "", callingPid, callingDisplayId);
    displayId = callingDisplayId;
    return true;
#else
    IMSA_HILOGI("capability not supported");
    return true;
#endif
}

int32_t WindowAdapter::StoreAllDisplayGroupInfos()
{
#ifdef SCENE_BOARD_ENABLE
    std::map<uint64_t, uint64_t> displayGroupIds;
    std::vector<FocusChangeInfo> focusWindowInfos;
    auto ret = GetAllDisplayGroupInfos(displayGroupIds, focusWindowInfos);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("GetAllGroupInfo failed, ret: %{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
        displayGroupIds_ = displayGroupIds;
    }
    {
        std::lock_guard<std::mutex> lock(focusWindowInfosLock_);
        focusWindowInfos_ = focusWindowInfos;
    }
#else
    IMSA_HILOGI("capability not supported");
#endif
    return ErrorCode::NO_ERROR;
}

int32_t WindowAdapter::GetAllFocusWindowInfos(std::vector<FocusChangeInfo> &focusWindowInfos)
{
    std::map<uint64_t, uint64_t> displayGroupIds;
    auto ret = GetAllDisplayGroupInfos(displayGroupIds, focusWindowInfos);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("GetAllGroupInfo failed, ret: %{public}d", ret);
        return ret;
    }
    return ErrorCode::NO_ERROR;
}

uint64_t WindowAdapter::GetDisplayGroupId(uint64_t displayId)
{
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    auto iter = displayGroupIds_.find(displayId);
    if (iter != displayGroupIds_.end()) {
        return iter->second;
    }
    return DEFAULT_DISPLAY_GROUP_ID;
}

uint64_t WindowAdapter::GetDisplayGroupId(uint32_t windowId)
{
    auto displayId = GetDisplayIdByWindowId(windowId);
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    auto iter = displayGroupIds_.find(displayId);
    if (iter != displayGroupIds_.end()) {
        return iter->second;
    }
    return DEFAULT_DISPLAY_GROUP_ID;
}

int32_t WindowAdapter::GetAllDisplayGroupInfos(
    std::map<uint64_t, uint64_t> &displayGroupIds, std::vector<FocusChangeInfo> &focusWindowInfos)
{
    WMError ret = WindowManagerLite::GetInstance().GetAllGroupInfo(displayGroupIds, focusWindowInfos);
    if (ret != WMError::WM_OK) {
        IMSA_HILOGE("GetAllGroupInfo failed, ret: %{public}d", ret);
        return ret;
    }
    std::sort(focusWindowInfos.begin(), focusWindowInfos.end(),
        [](const FocusChangeInfo &a, const FocusChangeInfo &b) { return a.displayId_ < b.displayId_; });
    return ErrorCode::NO_ERROR;
}

void WindowAdapter::OnDisplayGroupInfoChanged(uint64_t displayId, uint64_t displayGroupId, bool isAdd)
{
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
        if (isAdd) {
            displayGroupIds_[displayId] = displayGroupId;
            return;
        }
        auto iter = displayGroupIds_.find(displayId);
        if (iter == displayGroupIds_.end()) {
            return;
        }
        displayGroupIds_.erase(displayId);
        for (const auto &pair : displayGroupIds_) {
            if (pair.second == displayGroupId) {
                ++count;
            }
        }
    }
    if (count != 0) {
        return;
    }
    RemoveFocusInfo(displayGroupId);
}

void WindowAdapter::OnAllDisplayGroupFocusChanged(const FocusChangeInfo &focusWindowInfo)
{
    std::lock_guard<std::mutex> lock(focusWindowInfosLock_);
    auto iter =
        std::find_if(focusWindowInfos_.begin(), focusWindowInfos_.end(), [&focusWindowInfo](const auto &focusInfo) {
            return focusWindowInfo.displayGroupId_ == focusInfo.displayGroupId_;
        });
    if (iter != focusWindowInfos_.end()) {
        focusWindowInfos_.erase(iter);
    }
    auto insertPos = std::lower_bound(focusWindowInfos_.begin(), focusWindowInfos_.end(), focusWindowInfo,
        [](const FocusChangeInfo &a, const FocusChangeInfo &b) { return a.displayId_ < b.displayId_; });
    focusWindowInfos_.insert(insertPos, focusWindowInfo);
}

void WindowAdapter::RemoveFocusInfo(uint64_t displayGroupId)
{
    std::lock_guard<std::mutex> lock(focusWindowInfosLock_);
    auto iter = std::find_if(focusWindowInfos_.begin(), focusWindowInfos_.end(),
        [&displayGroupId](const auto &focusInfo) { return displayGroupId == focusInfo.displayGroupId_; });
    if (iter == focusWindowInfos_.end()) {
        return;
    }
    focusWindowInfos_.erase(iter);
}

void WindowAdapter::RegisterAllGroupInfoChangedListener()
{
#ifdef SCENE_BOARD_ENABLE
    sptr<AllGroupInfoChangedListenerImpl> listener = new (std::nothrow) AllGroupInfoChangedListenerImpl();
    if (listener == nullptr) {
        IMSA_HILOGE("failed to create listener");
        return;
    }
    auto wmErr = WindowManagerLite::GetInstance().RegisterAllGroupInfoChangedListener(listener);
    IMSA_HILOGI("register focus changed listener ret: %{public}d", wmErr);
#endif
}
} // namespace MiscServices
} // namespace OHOS
