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

#ifndef INPUTMETHOD_IMF_PUSH_TO_TALK_MANAGER_H
#define INPUTMETHOD_IMF_PUSH_TO_TALK_MANAGER_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>

#include "event_handler.h"
#include "peruser_session.h"
#include "ptt_controller.h"

namespace OHOS {
namespace MiscServices {
// Owned by IMSA for its entire lifetime; gesture actions run on the existing service handler.
class PushToTalkManager : public std::enable_shared_from_this<PushToTalkManager> {
public:
    using ServiceHandlerProvider = std::function<std::shared_ptr<AppExecFwk::EventHandler>()>;
    using StartInputTypeHandler = std::function<int32_t(int32_t)>;

    PushToTalkManager(ServiceHandlerProvider serviceHandlerProvider, StartInputTypeHandler startInputTypeHandler);
    ~PushToTalkManager() = default;

    PushToTalkManager(const PushToTalkManager &) = delete;
    PushToTalkManager &operator=(const PushToTalkManager &) = delete;
    PushToTalkManager(PushToTalkManager &&) = delete;
    PushToTalkManager &operator=(PushToTalkManager &&) = delete;

    void HandleKeyEvent(const KeyboardEventInfo &eventInfo);
    void SetKeyEventMonitorReady(bool isReady);
    bool IsReady() const;
    // The IPC entry must validate the calling IME before querying the focused client's channel.
    bool IsGestureAvailable(int32_t userId, const sptr<IRemoteObject> &channel);
    void StartDialogAbility(int32_t userId);

private:
    std::shared_ptr<AppExecFwk::EventHandler> GetServiceHandler() const;
    void ApplyAction(PttAction action, int32_t eventUserId);
    void HandleStartTimer(int32_t eventUserId);
    void ScheduleLongPressTimer();
    void HandleTimerStartFailure(const char *reason);
    void HandleCancelTimer();
    void HandleStartVoice();
    bool EnableSpaceKeyEventBlock(int32_t userId);
    void HandleStopVoice();
    int32_t RestoreCurrentIme(int32_t userId);
    void HandleNoAction();
    bool BindGestureContext(int32_t userId);
    bool IsGestureContextValid(int32_t userId);
    bool GetEligibleClient(int32_t userId, FocusedRealImeClientSnapshot &snapshot);
    void NotifyGestureCancelled(int32_t userId);
    void ClearGestureContext();
    static bool IsSameInputClient(
        const FocusedRealImeClientSnapshot &left, const FocusedRealImeClientSnapshot &right);
    int32_t NotifyRollbackSpace(int32_t userId);

    // Resolve the handler at use time so OnStop cannot leave a cached handler usable by PTT.
    const ServiceHandlerProvider serviceHandlerProvider_;
    const StartInputTypeHandler startInputTypeHandler_;
    static constexpr int32_t INVALID_USER_ID = -1;
    static constexpr const char *KEY_EVENT_TASK = "PushToTalkKeyEventTask";
    static constexpr const char *TIMEOUT_TASK = "PushToTalkTimeoutTask";
    PttController controller_;
    std::atomic_bool isKeyEventMonitorReady_ { false };
    int32_t gestureUserId_ { INVALID_USER_ID };
    std::mutex gestureClientSnapshotMutex_;
    FocusedRealImeClientSnapshot gestureClientSnapshot_;
};
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_IMF_PUSH_TO_TALK_MANAGER_H
