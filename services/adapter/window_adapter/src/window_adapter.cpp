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

#include <chrono>
#include <cinttypes>
#include <ranges>
#include <thread>

#include "global.h"
#include "window.h"
#include "wm_common.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::Rosen;
using WMError = OHOS::Rosen::WMError;
using namespace std::chrono_literals;
// LCOV_EXCL_START
WindowAdapter::~WindowAdapter()
{
}

WindowAdapter &WindowAdapter::GetInstance()
{
    static WindowAdapter windowAdapter;
    return windowAdapter;
}

void WindowAdapter::GetFocusInfo(OHOS::Rosen::FocusChangeInfo &focusInfo, uint64_t displayId)
{
#ifdef SCENE_BOARD_ENABLE
    WindowManagerLite::GetInstance().GetFocusWindowInfo(focusInfo, displayId);
#else
    WindowManager::GetInstance().GetFocusWindowInfo(focusInfo, displayId);
#endif
}

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
// LCOV_EXCL_START
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

uint64_t WindowAdapter::GetDisplayIdWithCorrect(int32_t windowId, uint64_t displayId)
{
    uint64_t displayIdOut = DEFAULT_DISPLAY_ID;
#ifdef SCENE_BOARD_ENABLE
    if (windowId == DEFAULT_WINDOW_ID) {
        return displayIdOut;
    }
    std::vector<sptr<WindowInfo>> windowInfos;
    if (!ListWindowInfo(windowInfos)) {
        return displayIdOut;
    }
    auto iter = std::find_if(windowInfos.begin(), windowInfos.end(), [&windowId](const auto &windowInfo) {
        return windowInfo != nullptr && windowInfo->windowMetaInfo.windowId == windowId;
    });
    if (iter == windowInfos.end()) {
        IMSA_HILOGE("not found windowId:%{public}d, displayId:%{public}" PRIu64 ".", windowId, displayId);
        if (windowId == SCB_ROOT_WINDOW_ID) {
            displayIdOut = displayId;
        }
        return displayIdOut;
    }
    displayIdOut = (*iter)->windowDisplayInfo.displayId;
    IMSA_HILOGD("find windowId:%{public}d, displayId:%{public}" PRIu64 ".", windowId, displayIdOut);
    return displayIdOut;
#else
    IMSA_HILOGI("capability not supported");
    return displayIdOut;
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
    std::unordered_map<uint64_t, uint64_t> displayGroupIds;
    std::vector<FocusChangeInfo> focusWindowInfos;
    auto ret = GetAllDisplayGroupInfos(displayGroupIds, focusWindowInfos);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetAllGroupInfo failed, ret: %{public}d", ret);
        return ret;
    }
#else
    IMSA_HILOGI("capability not supported");
#endif
    return ErrorCode::NO_ERROR;
}
// LCOV_EXCL_STOP
int32_t WindowAdapter::GetAllFocusWindowInfos(std::vector<FocusChangeInfo> &focusWindowInfos)
{
    std::unordered_map<uint64_t, uint64_t> displayGroupIds;
    auto ret = GetAllDisplayGroupInfos(displayGroupIds, focusWindowInfos);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetAllGroupInfo failed, ret: %{public}d", ret);
        return ret;
    }
    for (const auto &[key, value] : displayGroupIds) {
        IMSA_HILOGD("display:%{public}" PRIu64 "/%{public}" PRIu64 ".", key, value);
    }
    for (const auto &info : focusWindowInfos) {
        IMSA_HILOGD("focus:%{public}d/%{public}" PRIu64 "/%{public}" PRIu64 "/%{public}d", info.windowId_,
            info.displayGroupId_, info.realDisplayId_, info.pid_);
    }
    return ErrorCode::NO_ERROR;
}

uint64_t WindowAdapter::GetDisplayGroupId(uint64_t displayId)
{
    IMSA_HILOGD("by displayId run in:%{public}" PRIu64 ".", displayId);
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    auto iter = displayGroupIds_.find(displayId);
    if (iter != displayGroupIds_.end()) {
        IMSA_HILOGD("by displayId:%{public}" PRIu64 "/%{public}" PRIu64 ".", displayId, iter->second);
        return iter->second;
    }
    return DEFAULT_DISPLAY_GROUP_ID;
}

bool WindowAdapter::IsDisplayGroupIdExist(uint64_t displayGroupId)
{
    if (displayGroupId == DEFAULT_DISPLAY_GROUP_ID) {
        return true;
    }
    IMSA_HILOGD("displayGroupId:%{public}" PRIu64 ".", displayGroupId);
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    auto iter = std::find_if(displayGroupIds_.begin(), displayGroupIds_.end(),
        [displayGroupId](const std::pair<uint64_t, uint64_t> &pair) { return pair.second == displayGroupId; });
    return iter != displayGroupIds_.end();
}
// LCOV_EXCL_START
bool WindowAdapter::IsDisplayIdExist(uint64_t displayId)
{
    if (displayId == DEFAULT_DISPLAY_ID) {
        return true;
    }
    IMSA_HILOGD("displayId:%{public}" PRIu64 ".", displayId);
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    return displayGroupIds_.find(displayId) != displayGroupIds_.end();
}

bool WindowAdapter::IsDefaultDisplayGroup(uint64_t displayId)
{
    return GetDisplayGroupId(displayId) == DEFAULT_DISPLAY_GROUP_ID;
}

uint64_t WindowAdapter::GetDisplayGroupId(uint32_t windowId)
{
    IMSA_HILOGD("by windowId run in:%{public}d.", windowId);
    auto displayId = GetDisplayIdByWindowId(windowId);
    return GetDisplayGroupId(displayId);
}
// LCOV_EXCL_STOP
int32_t WindowAdapter::GetAllDisplayGroupInfos(
    std::unordered_map<uint64_t, uint64_t> &displayGroupIds, std::vector<FocusChangeInfo> &focusWindowInfos)
{
#ifdef SCENE_BOARD_ENABLE
    std::vector<sptr<FocusChangeInfo>> focusWindowInfoPtr;
    WindowManagerLite::GetInstance().GetAllGroupInfo(displayGroupIds, focusWindowInfoPtr);
    for (const auto &info : focusWindowInfoPtr) {
        if (info != nullptr) {
            focusWindowInfos.push_back(*info);
        }
    }
    std::sort(focusWindowInfos.begin(), focusWindowInfos.end(),
        [](const FocusChangeInfo &a, const FocusChangeInfo &b) { return a.displayId_ < b.displayId_; });

    GetInstance().SetDisplayGroupIds(displayGroupIds);
    GetInstance().SetFocusWindowInfos(focusWindowInfos);
    return ErrorCode::NO_ERROR;
#else
    return ErrorCode::NO_ERROR;
#endif
}

void WindowAdapter::SetDisplayGroupIds(const std::unordered_map<uint64_t, uint64_t> &displayGroupIds)
{
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    displayGroupIds_ = displayGroupIds;
}

void WindowAdapter::SetFocusWindowInfos(const std::vector<Rosen::FocusChangeInfo> &focusWindowInfos)
{
    std::lock_guard<std::mutex> lock(focusWindowInfosLock_);
    focusWindowInfos_ = focusWindowInfos;
}
// LCOV_EXCL_START
void WindowAdapter::OnDisplayGroupInfoChanged(uint64_t displayId, uint64_t displayGroupId, bool isAdd)
{
    IMSA_HILOGI("display change:%{public}" PRIu64 "/%{public}" PRIu64 "/%{public}d.", displayId,
        displayGroupId, isAdd);
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
}

void WindowAdapter::OnFocused(const FocusChangeInfo &focusWindowInfo)
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

void WindowAdapter::OnUnFocused(const FocusChangeInfo &focusWindowInfo)
{
    std::lock_guard<std::mutex> lock(focusWindowInfosLock_);
    auto iter = std::find_if(focusWindowInfos_.begin(), focusWindowInfos_.end(),
        [&focusWindowInfo](const auto &focusInfo) { return focusWindowInfo.windowId_ == focusInfo.windowId_; });
    if (iter == focusWindowInfos_.end()) {
        return;
    }
    focusWindowInfos_.erase(iter);
}

int32_t WindowAdapter::RegisterAllGroupInfoChangedListener()
{
#ifdef SCENE_BOARD_ENABLE
    sptr<AllGroupInfoChangedListenerImpl> listener = new (std::nothrow) AllGroupInfoChangedListenerImpl();
    if (listener == nullptr) {
        IMSA_HILOGE("failed to create listener");
        return ErrorCode::ERROR_IMSA_MALLOC_FAILED;
    }
    auto wmErr = WindowManagerLite::GetInstance().RegisterAllGroupInfoChangedListener(listener);
    IMSA_HILOGI("register AllGroupInfoChangedListener ret: %{public}d", wmErr);
    if (wmErr != WMError::WM_OK) {
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    return ErrorCode::NO_ERROR;
#else
    return ErrorCode::NO_ERROR;
#endif
}
} // namespace MiscServices
} // namespace OHOS
