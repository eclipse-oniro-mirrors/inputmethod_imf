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

#ifndef OHOS_INPUTMETHOD_PANEL_DEAL_QUEUE_H
#define OHOS_INPUTMETHOD_PANEL_DEAL_QUEUE_H

#include "ffrt_block_queue.h"

namespace OHOS {
namespace MiscServices {
enum class JsEvent : uint32_t {
    RESIZE = 0,
    MOVE_TO,
    ADJUST_PANEL_RECT,
    UPDATE_REGION,
    SHOW,
    HIDE,
    SET_UI_CONTENT,
    GET_DISPLAYID,
    SET_IMMERSIVE_MODE,
    GET_IMMERSIVE_MODE,
    SET_IMMERSIVE_EFFECT,
    SET_SYSTEM_PANEL_BUTTON_COLOR,
    GET_SYSTEM_PANEL_CURRENT_INSETS,
    SET_SHADOW,
    ADD_ADJUST_PANEL_RECT,
    CHANGE_PANEL_FLAG,
    UPDATE_PANEL_RECT_SYNC,
    EVENT_END,
};

struct JsEventInfo {
    std::chrono::system_clock::time_point timestamp{};
    JsEvent event{ JsEvent::EVENT_END };
    bool operator==(const JsEventInfo &info) const
    {
        return (timestamp == info.timestamp && event == info.event);
    }
};

class PanelDealQueue {
public:
    static constexpr int32_t MAX_WAIT_TIME = 10;    //ms
    static void Pop();

    static void Push(const JsEventInfo &info);

    static void Wait(const JsEventInfo &info);

    static void PrintIfTimeout(int64_t start, const JsEventInfo &currentInfo);

private:
    static FFRTBlockQueue<JsEventInfo> panelDealQueue_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // OHOS_INPUTMETHOD_PANEL_DEAL_QUEUE_H
