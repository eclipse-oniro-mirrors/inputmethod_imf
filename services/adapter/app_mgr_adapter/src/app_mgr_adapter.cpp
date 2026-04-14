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

#include "app_mgr_adapter.h"

#include <cinttypes>

#include "app_mgr_client.h"
#include "global.h"
#include "ime_info_inquirer.h"
#include "inputmethod_message_handler.h"
#include "itypes_util.h"
#include "singleton.h"
namespace OHOS {
namespace MiscServices {
using namespace OHOS::AppExecFwk;
std::mutex AppMgrAdapter::imageStateObserverLock_;
sptr<AppExecFwk::IImageProcessStateObserver> AppMgrAdapter::imageStateObserver_{ nullptr };
bool AppMgrAdapter::HasBundleName(pid_t pid, const std::string &bundleName)
{
    if (bundleName.empty()) {
        return false;
    }
    RunningProcessInfo info;
    auto ret = GetRunningProcessInfoByPid(pid, info);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetRunningProcessInfoByPid:%{public}d failed:%{public}d.", pid, ret);
        return false;
    }
    auto bundleNames = info.bundleNames;
    auto iter = std::find_if(bundleNames.begin(), bundleNames.end(),
        [&bundleName](const std::string &bundleNameTmp) { return bundleNameTmp == bundleName; });
    return iter != bundleNames.end();
}

int32_t AppMgrAdapter::GetRunningProcessInfoByPid(pid_t pid, RunningProcessInfo &info)
{
    auto appMgrClient = DelayedSingleton<AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        IMSA_HILOGE("appMgrClient is nullptr.");
        return ErrorCode::ERROR_IMSA_APP_MGR_ERROR;
    }
    auto ret = appMgrClient->GetRunningProcessInfoByPid(pid, info);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetRunningProcessInfoByPid:%{public}d failed:%{public}d.", pid, ret);
        return ErrorCode::ERROR_IMSA_APP_MGR_ERROR;
    }
    return ErrorCode::NO_ERROR;
}

int32_t AppMgrAdapter::GetRunningProcessInfosByUserId(
    int32_t userId, std::vector<OHOS::AppExecFwk::RunningProcessInfo> &infos)
{
    auto appMgrClient = DelayedSingleton<AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        IMSA_HILOGE("appMgrClient is nullptr.");
        return ErrorCode::ERROR_IMSA_APP_MGR_ERROR;
    }
    auto ret = appMgrClient->GetProcessRunningInfosByUserId(infos, userId);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("GetRunningProcessInfosByUserId:%{public}d failed:%{public}d.", userId, ret);
        return ErrorCode::ERROR_IMSA_APP_MGR_ERROR;
    }
    return ErrorCode::NO_ERROR;
}

int32_t AppMgrAdapter::RegisterImageProcessStateObserver()
{
    std::lock_guard<std::mutex> lock(imageStateObserverLock_);
    if (imageStateObserver_ != nullptr) {
        IMSA_HILOGD("has register!");
        return ErrorCode::NO_ERROR;
    }
    sptr<IImageProcessStateObserver> observer = new (std::nothrow) ImageProcessStateObserverImpl();
    if (observer == nullptr) {
        IMSA_HILOGE("failed to create listener");
        return ErrorCode::ERROR_IMSA_MALLOC_FAILED;
    }
    auto appMgrClient = DelayedSingleton<AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        IMSA_HILOGE("appMgrClient is nullptr.");
        return ErrorCode::ERROR_IMSA_APP_MGR_ERROR;
    }
    auto ret = appMgrClient->RegisterImageProcessStateObserver(observer);
    IMSA_HILOGI("register imageProcessStateObserver ret: %{public}d", ret);
    if (ret != ErrorCode::NO_ERROR) {
        return ErrorCode::ERROR_IMSA_APP_MGR_ERROR;
    }
    imageStateObserver_ = observer;
    return ErrorCode::NO_ERROR;
}

void AppMgrAdapter::ResetImageProcessStateObserver()
{
    IMSA_HILOGW("app mgr sa died, reset!");
    std::lock_guard<std::mutex> lock(imageStateObserverLock_);
    imageStateObserver_ = nullptr;
}

void AppMgrAdapter::ImageProcessStateObserverImpl::OnImageProcessStateChanged(
    const ImageProcessStateData &imageProcessStateData)
{
    IMSA_HILOGD("bundle:%{public}s image changed, state:%{public}d.", imageProcessStateData.bundleName.c_str(),
        imageProcessStateData.state);
    if (imageProcessStateData.state != static_cast<int32_t>(ImageProcessState::IMAGE_PROCESS_CREATE)) {
        return;
    }
    if (!ImeInfoInquirer::GetInstance().IsSysIme(imageProcessStateData.bundleName)) {
        return;
    }
    IMSA_HILOGI(
        "sys ime image created:%{public}d/%{public}d.", imageProcessStateData.uid, imageProcessStateData.imagePid);
    NotifySysImeImageCreated(imageProcessStateData.uid);
}

void AppMgrAdapter::ImageProcessStateObserverImpl::NotifySysImeImageCreated(int32_t uid)
{
    MessageParcel *parcel = new (std::nothrow) MessageParcel();
    if (parcel == nullptr) {
        IMSA_HILOGE("Parcel is nullptr!");
        return;
    }
    if (!ITypesUtil::Marshal(*parcel, uid)) {
        IMSA_HILOGE("Failed to write message parcel!");
        delete parcel;
        return;
    }
    MiscServices::Message *msg = new (std::nothrow)
        MiscServices::Message(MessageID::MSG_ID_SYS_IME_IMAGE_CREATED, parcel);
    if (msg == nullptr) {
        IMSA_HILOGE("Failed to create Message!");
        delete parcel;
        return;
    }
    MessageHandler *msgHandle = MessageHandler::Instance();
    if (msgHandle == nullptr) {
        IMSA_HILOGE("MessageHandler is nullptr!");
        delete msg;
        return;
    }
    msgHandle->SendMessage(msg);
}
} // namespace MiscServices
} // namespace OHOS