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
#ifdef SCENE_BOARD_ENABLE
#include "window_manager_lite.h"
#else
#include "window_manager.h"
#endif

namespace OHOS {
namespace MiscServices {
using WindowDisplayChangeHandler = std::function<void(int32_t, int32_t, uint64_t)>;
class WindowAdapter final {
public:
    static constexpr uint64_t DEFAULT_DISPLAY_ID = 0;
    static constexpr uint32_t DEFAULT_WINDOW_ID = 0;
    static constexpr uint32_t SCB_ROOT_WINDOW_ID = 1;
    static constexpr uint32_t DEFAULT_DISPLAY_GROUP_ID = 0;
    ~WindowAdapter();
    static WindowAdapter &GetInstance();
    static void GetFocusInfo(
        OHOS::Rosen::FocusChangeInfo &focusInfo, int32_t userId, uint64_t displayId = DEFAULT_DISPLAY_ID);
    static uint64_t GetDisplayIdByPid(int64_t callingPid, int32_t userId);
    static uint64_t GetDisplayIdByWindowId(int32_t callingWindowId, int32_t userId);
    static bool GetDisplayId(int64_t callingWindowId, uint64_t &displayId, int32_t userId);
    static uint64_t GetDisplayIdWithCorrect(int32_t windowId, uint64_t displayId, int32_t userId);
    static uint64_t GetDisplayIdByToken(sptr<IRemoteObject> abilityToken, int32_t userId);
    static bool ListWindowInfo(std::vector<sptr<OHOS::Rosen::WindowInfo>> &windowInfos, int32_t userId);
    static int32_t GetAllFocusWindowInfos(std::vector<Rosen::FocusChangeInfo> &focusWindowInfos, int32_t userId);
    uint64_t GetDisplayGroupId(uint64_t displayId, int32_t userId);
    bool IsDefaultDisplayGroup(uint64_t displayId, int32_t userId);
    uint64_t GetDisplayGroupId(uint32_t windowId, int32_t userId);
    bool IsDisplayGroupIdExist(uint64_t displayGroupId, int32_t userId);
    bool IsDisplayIdExist(uint64_t displayId, int32_t userId);
    int32_t StoreAllDisplayGroupInfos(int32_t userId);
    void OnDisplayGroupInfoChanged(uint64_t displayId, uint64_t displayGroupId, bool isAdd, int32_t userId);
    int32_t RegisterAllGroupInfoChangedListener(int32_t userId);
    int32_t RegisterWindowDisplayIdChangedListener(const WindowDisplayChangeHandler &handler, int32_t userId);

    class WindowDisplayChangedListenerImpl : public OHOS::Rosen::IWindowInfoChangedListener {
    public:
        explicit WindowDisplayChangedListenerImpl(const WindowDisplayChangeHandler &handler) : handler_(handler){};
        ~WindowDisplayChangedListenerImpl() = default;
        void OnWindowInfoChanged(const OHOS::Rosen::WindowInfoList &windowInfoList) override;

    private:
        WindowDisplayChangeHandler handler_;
    };

    class AllGroupInfoChangedListenerImpl : public OHOS::Rosen::IAllGroupInfoChangedListener {
    public:
        explicit AllGroupInfoChangedListenerImpl(int32_t userId) : userId_(userId)
        {
        }
        ~AllGroupInfoChangedListenerImpl() = default;
        void OnDisplayGroupInfoChange(
            Rosen::DisplayGroupId displayGroupId, Rosen::DisplayId displayId, bool isAdd) override
        {
            WindowAdapter::GetInstance().OnDisplayGroupInfoChanged(displayId, displayGroupId, isAdd, userId_);
        }

    private:
        int32_t userId_;
    };

private:
    WindowAdapter() = default;
    static int32_t GetAllDisplayGroupInfos(std::unordered_map<uint64_t, uint64_t> &displayGroupIds,
        std::vector<Rosen::FocusChangeInfo> &focusWindowInfos, int32_t userId);
    void SetDisplayGroupIds(const std::unordered_map<uint64_t, uint64_t> &displayGroupIds, int32_t userId);

    // { key: userId, value: { key: displayId, value: displayGroupId }}
    std::mutex displayGroupIdsLock_;
    std::unordered_map<int32_t, std::unordered_map<uint64_t, uint64_t>> displayGroupIds_;
};
} // namespace MiscServices
} // namespace OHOS
#endif //INPUTMETHOD_IMF_WINDOW_ADAPTER_H
