/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IMF_WMS_CONNECTION_MONITOR_MANAGER_H
#define IMF_WMS_CONNECTION_MONITOR_MANAGER_H
#include <functional>
namespace OHOS {
namespace MiscServices {
using ChangeHandler = std::function<void(int32_t userId, int32_t screenId, bool isConnected)>;
class WmsConnectionMonitorManager {
public:
    static WmsConnectionMonitorManager &GetInstance();
    void RegisterWMSConnectionChangedListener(const ChangeHandler &handler);

private:
    WmsConnectionMonitorManager() = default;
};
} // namespace MiscServices
} // namespace OHOS

#endif // IMF_WMS_CONNECTION_MONITOR_MANAGER_H
