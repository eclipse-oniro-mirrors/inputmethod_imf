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

#ifndef INPUTMETHOD_IMF_APP_MGR_ADAPTER_H
#define INPUTMETHOD_IMF_APP_MGR_ADAPTER_H

#include <cstdint>
#include <string>

#include "image_process_state_observer_stub.h"
#include "running_process_info.h"

namespace OHOS {
namespace MiscServices {
class AppMgrAdapter final {
public:
    static bool HasBundleName(pid_t pid, const std::string &bundleName);
    static int32_t RegisterImageProcessStateObserver();
    static void ResetImageProcessStateObserver();
    static int32_t GetRunningProcessInfoByPid(pid_t pid, OHOS::AppExecFwk::RunningProcessInfo &info);
    static int32_t GetRunningProcessInfosByUserId(
        int32_t userId, std::vector<OHOS::AppExecFwk::RunningProcessInfo> &infos);
    class ImageProcessStateObserverImpl : public AppExecFwk::ImageProcessStateObserverStub {
    public:
        ImageProcessStateObserverImpl() = default;
        ~ImageProcessStateObserverImpl() = default;
        void OnImageProcessStateChanged(const AppExecFwk::ImageProcessStateData &imageProcessStateData) override;
        void OnForkAllWorkProcessFailed(
            const AppExecFwk::ImageProcessStateData &imageProcessStateData, int32_t errCode) override
        {
        }

    private:
        void NotifySysImeImageCreated(int32_t uid);
    };

private:
    static std::mutex imageStateObserverLock_;
    static sptr<AppExecFwk::IImageProcessStateObserver> imageStateObserver_;
};
} // namespace MiscServices
} // namespace OHOS

#endif //INPUTMETHOD_IMF_APP_MGR_ADAPTER_H