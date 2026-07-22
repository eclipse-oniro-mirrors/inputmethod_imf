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
#include <cinttypes>
#include "global.h"
#include "panel_deal_queue.h"

namespace OHOS {
namespace MiscServices {
using namespace std::chrono;
FFRTBlockQueue<JsEventInfo> PanelDealQueue::panelDealQueue_{ MAX_WAIT_TIME };
void PanelDealQueue::Pop()
{
    panelDealQueue_.Pop();
}

void PanelDealQueue::Push(const JsEventInfo &info)
{
    panelDealQueue_.Push(info);
}

void PanelDealQueue::Wait(const JsEventInfo &info)
{
    panelDealQueue_.Wait(info);
}

void PanelDealQueue::PrintIfTimeout(int64_t start, const JsEventInfo &currentInfo)
{
    int64_t end = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    if (end - start >= MAX_WAIT_TIME) {
        JsEventInfo frontInfo;
        auto ret = panelDealQueue_.GetFront(frontInfo);
        int64_t frontTime = duration_cast<microseconds>(frontInfo.timestamp.time_since_epoch()).count();
        int64_t currentTime = duration_cast<microseconds>(currentInfo.timestamp.time_since_epoch()).count();
        IMSA_HILOGI("ret:%{public}d,front[%{public}" PRId64 ",%{public}d],current[%{public}" PRId64 ",%{public}d]",
            ret, frontTime, static_cast<int32_t>(frontInfo.event),
                currentTime, static_cast<int32_t>(currentInfo.event));
    }
}
} // namespace MiscServices
} // namespace OHOS
