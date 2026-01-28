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

#ifndef INPUTMETHOD_IMF_WINDOW_ADAPTER_H
#define INPUTMETHOD_IMF_WINDOW_ADAPTER_H

#include <functional>
#include <mutex>
#include <set>
#include <tuple>
#include "window.h"
#include "window_display_changed_listener.h"
namespace OHOS {
namespace MiscServices {
class WindowAdapter final {
public:
    static constexpr uint64_t DEFAULT_DISPLAY_ID = 0;
    static constexpr uint32_t DEFAULT_WINDOW_ID = 0;
    static constexpr uint32_t SCB_ROOT_WINDOW_ID = 1;
    static constexpr uint32_t DEFAULT_DISPLAY_GROUP_ID = 0;
    ~WindowAdapter();
    static WindowAdapter &GetInstance();
    static void GetFocusInfo(OHOS::Rosen::FocusChangeInfo &focusInfo, uint64_t displayId = DEFAULT_DISPLAY_ID);
    static uint64_t GetDisplayIdByPid(int64_t callingPid);
    static uint64_t GetDisplayIdByWindowId(int32_t callingWindowId);
    static bool GetDisplayId(int64_t callingWindowId, uint64_t &displayId);
    static uint64_t GetDisplayIdWithCorrect(int32_t windowId, uint64_t displayId);
    static uint64_t GetDisplayIdByToken(sptr<IRemoteObject> abilityToken);
    static bool ListWindowInfo(std::vector<sptr<OHOS::Rosen::WindowInfo>> &windowInfos);
    void RegisterCallingWindowInfoChangedListener(const WindowDisplayChangeHandler &handle);
    static int32_t GetAllFocusWindowInfos(std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
    uint64_t GetDisplayGroupId(uint64_t displayId);
    bool IsDefaultDisplayGroup(uint64_t displayId);
    uint64_t GetDisplayGroupId(uint32_t windowId);
    bool IsDisplayGroupIdExist(uint64_t displayGroupId);
    bool IsDisplayIdExist(uint64_t displayId);
    int32_t StoreAllDisplayGroupInfos();
    void OnDisplayGroupInfoChanged(uint64_t displayId, uint64_t displayGroupId, bool isAdd);
    void OnFocused(const Rosen::FocusChangeInfo &focusWindowInfo);
    void OnUnFocused(const Rosen::FocusChangeInfo &focusWindowInfo);
    int32_t RegisterAllGroupInfoChangedListener();

    class AllGroupInfoChangedListenerImpl : public OHOS::Rosen::IAllGroupInfoChangedListener {
    public:
        AllGroupInfoChangedListenerImpl() = default;
        ~AllGroupInfoChangedListenerImpl() = default;
        void OnDisplayGroupInfoChange(
            Rosen::DisplayGroupId displayGroupId, Rosen::DisplayId displayId, bool isAdd) override
        {
            WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId, displayGroupId, isAdd);
        }
    };

private:
    WindowAdapter() = default;
    static int32_t GetAllDisplayGroupInfos(std::unordered_map<uint64_t, uint64_t> &displayGroupIds,
        std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
    void SetDisplayGroupIds(const std::unordered_map<uint64_t, uint64_t> &displayGroupIds);
    void SetFocusWindowInfos(const std::vector<Rosen::FocusChangeInfo> &focusWindowInfos);
    std::mutex displayGroupIdsLock_;
    std::unordered_map<uint64_t, uint64_t> displayGroupIds_; // key:displayId, value:displayGroupId
    std::mutex focusWindowInfosLock_;
    std::vector<Rosen::FocusChangeInfo> focusWindowInfos_;
};
} // namespace MiscServices
} // namespace OHOS
#endif //INPUTMETHOD_IMF_WINDOW_ADAPTER_H
