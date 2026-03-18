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
#include "ipc_skeleton.h"
#include "os_account_adapter.h"
#include "variant_util.h"
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

void WindowAdapter::GetFocusInfo(OHOS::Rosen::FocusChangeInfo &focusInfo, int32_t userId, uint64_t displayId)
{
#ifdef SCENE_BOARD_ENABLE
    WindowManagerLite::GetInstance(userId).GetFocusWindowInfo(focusInfo, displayId);
#else
    WindowManager::GetInstance(userId).GetFocusWindowInfo(focusInfo, displayId);
#endif
}
// LCOV_EXCL_STOP
bool WindowAdapter::ListWindowInfo(std::vector<sptr<OHOS::Rosen::WindowInfo>> &windowInfos, int32_t userId)
{
#ifdef SCENE_BOARD_ENABLE
    WindowInfoOption option;
    WMError ret = WindowManagerLite::GetInstance(userId).ListWindowInfo(option, windowInfos);
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
uint64_t WindowAdapter::GetDisplayIdByToken(sptr<IRemoteObject> abilityToken, int32_t userId)
{
#ifdef SCENE_BOARD_ENABLE
    OHOS::Rosen::MainWindowInfo info;
    WMError ret = WindowManagerLite::GetInstance(userId).GetMainWindowInfoByToken(abilityToken, info);
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

uint64_t WindowAdapter::GetDisplayIdByWindowId(int32_t callingWindowId, int32_t userId)
{
#ifdef SCENE_BOARD_ENABLE
    if (callingWindowId == DEFAULT_DISPLAY_ID) {
        FocusChangeInfo info;
        WindowManagerLite::GetInstance(userId).GetFocusWindowInfo(info);
        callingWindowId = info.windowId_;
    }
    std::vector<sptr<WindowInfo>> windowInfos;
    if (!ListWindowInfo(windowInfos, userId)) {
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

uint64_t WindowAdapter::GetDisplayIdWithCorrect(int32_t windowId, uint64_t displayId, int32_t userId)
{
    uint64_t displayIdOut = DEFAULT_DISPLAY_ID;
#ifdef SCENE_BOARD_ENABLE
    if (windowId == DEFAULT_WINDOW_ID) {
        return displayIdOut;
    }
    std::vector<sptr<WindowInfo>> windowInfos;
    if (!ListWindowInfo(windowInfos, userId)) {
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

uint64_t WindowAdapter::GetDisplayIdByPid(int64_t callingPid, int32_t userId)
{
#ifdef SCENE_BOARD_ENABLE
    std::vector<sptr<WindowInfo>> windowInfos;
    if (!ListWindowInfo(windowInfos, userId)) {
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

bool WindowAdapter::GetDisplayId(int64_t callingPid, uint64_t &displayId, int32_t userId)
{
    displayId = DEFAULT_DISPLAY_ID;
#ifdef SCENE_BOARD_ENABLE
    std::vector<sptr<WindowInfo>> windowInfos;
    if (!ListWindowInfo(windowInfos, userId)) {
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

int32_t WindowAdapter::StoreAllDisplayGroupInfos(int32_t userId)
{
#ifdef SCENE_BOARD_ENABLE
    std::unordered_map<uint64_t, uint64_t> displayGroupIds;
    std::vector<FocusChangeInfo> focusWindowInfos;
    auto ret = GetAllDisplayGroupInfos(displayGroupIds, focusWindowInfos, userId);
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
int32_t WindowAdapter::GetAllFocusWindowInfos(std::vector<FocusChangeInfo> &focusWindowInfos, int32_t userId)
{
    std::unordered_map<uint64_t, uint64_t> displayGroupIds;
    auto ret = GetAllDisplayGroupInfos(displayGroupIds, focusWindowInfos, userId);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetAllGroupInfo failed, ret: %{public}d", ret);
        return ret;
    }
    for (const auto &[key, value] : displayGroupIds) {
        IMSA_HILOGD("display:%{public}" PRIu64 "/%{public}" PRIu64 ".", key, value);
    }
    for (const auto &info : focusWindowInfos) {
        IMSA_HILOGD("user: %{public}d, focus:%{public}d/%{public}" PRIu64 "/%{public}" PRIu64 "/%{public}d", userId,
            info.windowId_, info.displayGroupId_, info.realDisplayId_, info.pid_);
    }
    return ErrorCode::NO_ERROR;
}

uint64_t WindowAdapter::GetDisplayGroupId(uint64_t displayId, int32_t userId)
{
    IMSA_HILOGD("userId %{public}d, by displayId run in:%{public}" PRIu64 ".", userId, displayId);
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    auto userIter = displayGroupIds_.find(userId);
    if (userIter == displayGroupIds_.end()) {
        IMSA_HILOGE("user %{public}d not found", userId);
        return DEFAULT_DISPLAY_GROUP_ID;
    }
    auto userDisplayGroupIds = userIter->second;
    auto groupIter = userDisplayGroupIds.find(displayId);
    if (groupIter == userDisplayGroupIds.end()) {
        IMSA_HILOGE("display %{public}" PRIu64 " not found", displayId);
        return DEFAULT_DISPLAY_GROUP_ID;
    }
    uint64_t displayGroupId = groupIter->second;
    IMSA_HILOGD(
        "userId %{public}d, by displayId:%{public}" PRIu64 "/%{public}" PRIu64 ".", userId, displayId, displayGroupId);
    return displayGroupId;
}
// LCOV_EXCL_START
bool WindowAdapter::IsDisplayGroupIdExist(uint64_t displayGroupId, int32_t userId)
{
    if (displayGroupId == DEFAULT_DISPLAY_GROUP_ID) {
        return true;
    }
    IMSA_HILOGD("displayGroupId:%{public}" PRIu64 ".", displayGroupId);
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    auto userIter = displayGroupIds_.find(userId);
    if (userIter == displayGroupIds_.end()) {
        IMSA_HILOGE("user %{public}d not found", userId);
        return false;
    }
    auto displayGroupIds = userIter->second;
    auto iter = std::find_if(displayGroupIds.begin(), displayGroupIds.end(),
        [displayGroupId](const std::pair<uint64_t, uint64_t> &pair) { return pair.second == displayGroupId; });
    return iter != displayGroupIds.end();
}

bool WindowAdapter::IsDisplayIdExist(uint64_t displayId, int32_t userId)
{
    if (displayId == DEFAULT_DISPLAY_ID) {
        return true;
    }
    IMSA_HILOGD("displayId:%{public}" PRIu64 ".", displayId);
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    auto iter = displayGroupIds_.find(userId);
    if (iter == displayGroupIds_.end()) {
        IMSA_HILOGE("user %{public}d not found", userId);
        return false;
    }
    auto displayGroupIds = iter->second;
    return displayGroupIds.find(displayId) != displayGroupIds.end();
}

bool WindowAdapter::IsDefaultDisplayGroup(uint64_t displayId, int32_t userId)
{
    return GetDisplayGroupId(displayId, userId) == DEFAULT_DISPLAY_GROUP_ID;
}

uint64_t WindowAdapter::GetDisplayGroupId(uint32_t windowId, int32_t userId)
{
    IMSA_HILOGD("by windowId run in:%{public}d.", windowId);
    auto displayId = GetDisplayIdByWindowId(windowId, userId);
    return GetDisplayGroupId(displayId, userId);
}
// LCOV_EXCL_STOP
int32_t WindowAdapter::GetAllDisplayGroupInfos(std::unordered_map<uint64_t, uint64_t> &displayGroupIds,
    std::vector<FocusChangeInfo> &focusWindowInfos, int32_t userId)
{
#ifdef SCENE_BOARD_ENABLE
    std::vector<sptr<FocusChangeInfo>> focusWindowInfoPtr;
    WindowManagerLite::GetInstance(userId).GetAllGroupInfo(displayGroupIds, focusWindowInfoPtr);
    for (const auto &info : focusWindowInfoPtr) {
        if (info != nullptr) {
            focusWindowInfos.push_back(*info);
        }
    }
    std::sort(focusWindowInfos.begin(), focusWindowInfos.end(),
        [](const FocusChangeInfo &a, const FocusChangeInfo &b) { return a.displayId_ < b.displayId_; });

    GetInstance().SetDisplayGroupIds(displayGroupIds, userId);
    return ErrorCode::NO_ERROR;
#else
    return ErrorCode::NO_ERROR;
#endif
}

void WindowAdapter::SetDisplayGroupIds(const std::unordered_map<uint64_t, uint64_t> &displayGroupIds, int32_t userId)
{
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    displayGroupIds_[userId] = displayGroupIds;
}

// LCOV_EXCL_START
void WindowAdapter::OnDisplayGroupInfoChanged(uint64_t displayId, uint64_t displayGroupId, bool isAdd, int32_t userId)
{
    IMSA_HILOGI("display change:%{public}" PRIu64 "/%{public}" PRIu64 "/%{public}d.", displayId,
        displayGroupId, isAdd);
    std::lock_guard<std::mutex> lock(displayGroupIdsLock_);
    if (isAdd) {
        displayGroupIds_[userId][displayId] = displayGroupId;
        return;
    }
    auto userIter = displayGroupIds_.find(userId);
    if (userIter == displayGroupIds_.end()) {
        IMSA_HILOGE("user %{public}d not found", userId);
        return;
    }
    auto &displayGroupIds = userIter->second;
    displayGroupIds.erase(displayId);
}

int32_t WindowAdapter::RegisterAllGroupInfoChangedListener(int32_t userId)
{
#ifdef SCENE_BOARD_ENABLE
    sptr<IAllGroupInfoChangedListener> listener = new (std::nothrow) AllGroupInfoChangedListenerImpl(userId);
    if (listener == nullptr) {
        IMSA_HILOGE("failed to create listener");
        return ErrorCode::ERROR_IMSA_MALLOC_FAILED;
    }
    auto wmErr = WindowManagerLite::GetInstance(userId).RegisterAllGroupInfoChangedListener(listener);
    IMSA_HILOGI("register AllGroupInfoChangedListener ret: %{public}d", wmErr);
    if (wmErr != WMError::WM_OK) {
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    return ErrorCode::NO_ERROR;
#else
    return ErrorCode::NO_ERROR;
#endif
}

int32_t WindowAdapter::RegisterWindowDisplayIdChangedListener(const WindowDisplayChangeHandler &handler, int32_t userId)
{
#ifdef SCENE_BOARD_ENABLE
    sptr<IWindowInfoChangedListener> listener = new (std::nothrow) WindowDisplayChangedListenerImpl(handler);
    if (listener == nullptr) {
        IMSA_HILOGE("failed to create listener");
        return ErrorCode::ERROR_IMSA_MALLOC_FAILED;
    }
    std::unordered_set<WindowInfoKey> observedInfo;
    observedInfo.insert(WindowInfoKey::DISPLAY_ID);
    listener->AddInterestInfo(WindowInfoKey::WINDOW_ID);
    auto wmErr = WindowManagerLite::GetInstance(userId).RegisterWindowInfoChangeCallback(observedInfo, listener);
    IMSA_HILOGI("register WindowInfoChangeListener ret: %{public}d", wmErr);
    if (wmErr != WMError::WM_OK) {
        return ErrorCode::ERROR_WINDOW_MANAGER;
    }
    return ErrorCode::NO_ERROR;
#else
    return ErrorCode::NO_ERROR;
#endif
}

void WindowAdapter::WindowDisplayChangedListenerImpl::OnWindowInfoChanged(const WindowInfoList &windowInfoList)
{
#ifdef SCENE_BOARD_ENABLE
    if (windowInfoList.empty()) {
        IMSA_HILOGE("windowInfoList is empty");
        return;
    }
    auto userId = OsAccountAdapter::GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid());
    IMSA_HILOGI("user:%{public}d windowInfoList size is:%{public}zu.", userId, windowInfoList.size());
    uint64_t displayId = 0;
    uint32_t windowId = 0;
    for (const auto &infoMap : windowInfoList) {
        auto displayIdIter = infoMap.find(WindowInfoKey::DISPLAY_ID);
        if (displayIdIter == infoMap.end()) {
            IMSA_HILOGE("displayId not find.");
            continue;
        }
        auto windowIdIter = infoMap.find(WindowInfoKey::WINDOW_ID);
        if (windowIdIter == infoMap.end()) {
            IMSA_HILOGE("windowId not find.");
            continue;
        }
        if (!VariantUtil::GetValue(displayIdIter->second, displayId)) {
            IMSA_HILOGE("displayId type is error.");
            continue;
        }
        if (!VariantUtil::GetValue(windowIdIter->second, windowId)) {
            IMSA_HILOGE("windowId type is error.");
            continue;
        }
        if (handler_ != nullptr) {
            handler_(userId, windowId, displayId);
        }
    }
#endif
}
} // namespace MiscServices
} // namespace OHOS