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
#include <cstdio>
#include <iostream>

#include "accesstoken_kit.h"
#include "app_mgr_client.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "global.h"
#include "input_method_controller.h"
#include "nativetoken_kit.h"
#include "running_process_info.h"
#include "singleton.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AAFwk;
using namespace OHOS::EventFwk;
using namespace OHOS::MiscServices;
using namespace OHOS::AppExecFwk;

constexpr const char *COMMON_EVENT_NOTIFY_SA_MAKE_IMAGE = "NOTIFY_SA_MAKE_IMAGE";
const int32_t PERMISSION_NUM = 1;
constexpr int32_t FIRST_PARAM_INDEX = 0;

void GrantNativePermission()
{
    const char **perms = new const char *[PERMISSION_NUM];
    perms[FIRST_PARAM_INDEX] = "ohos.permission.GET_RUNNING_INFO";
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = PERMISSION_NUM,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "imf_test",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    int32_t ret = SetSelfTokenID(tokenId);
    if (ret == 0) {
        IMSA_HILOGI("SetSelfTokenID success!");
    } else {
        IMSA_HILOGE("SetSelfTokenID fail!");
    }
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

void NotifySaMakeImage(const std::string &bundleName)
{
    Want want;
    want.SetAction(COMMON_EVENT_NOTIFY_SA_MAKE_IMAGE);
    want.SetBundle(bundleName.data());
    CommonEventData data;
    data.SetWant(want);
    auto ret = CommonEventManager::PublishCommonEvent(data);
    printf("=====NotifySaMakeImage:bundleName/ret:%s/%d.=====\n", ret, bundleName.c_str());
}

void GetRunningProcessInfosByUserId(int32_t userId, std::vector<RunningProcessInfo> &infos)
{
    auto appMgrClient = DelayedSingleton<AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        printf("appMgrClient is nullptr.");
        return;
    }
    auto ret = appMgrClient->GetProcessRunningInfosByUserId(infos, userId);
    if (ret != ErrorCode::NO_ERROR || infos.empty()) {
        printf("GetRunningProcessInfosByUserId:%d failed:%d.", userId, ret);
        return;
    }
}

void NotifySaMakeAppImage()
{
    std::vector<RunningProcessInfo> infos;
    GetRunningProcessInfosByUserId(ImfCommonConst::START_USER_ID, infos);
    for (const auto &info : infos) {
        if (info.extensionType_ != ExtensionAbilityType::INPUTMETHOD && !info.bundleNames.empty()) {
            NotifySaMakeImage(info.bundleNames[0]);
            break;
        }
    }
}

void NotifySaMakeSysImeImage()
{
    std::shared_ptr<Property> property = nullptr;
    auto ret = InputMethodController::GetInstance()->GetDefaultInputMethod(property);
    if (ret != ErrorCode::NO_ERROR || property == nullptr) {
        printf("=====GetDefaultInputMethod failed, ret:%d.=====\n", ret);
        return;
    }
    NotifySaMakeImage(property->name);
}

void NotifySaMakeOtherImeImage()
{
    const int32_t minImeNum = 2;
    std::vector<Property> props;
    auto ret = InputMethodController::GetInstance()->ListInputMethod(props);
    if (ret != ErrorCode::NO_ERROR || props.size() < minImeNum) {
        printf("=====ListInputMethod failed, ret/size:%d/%zu.=====\n", ret, props.size());
        return;
    }
    std::shared_ptr<Property> sysProp = nullptr;
    ret = InputMethodController::GetInstance()->GetDefaultInputMethod(sysProp);
    if (ret != ErrorCode::NO_ERROR || sysProp == nullptr) {
        printf("=====GetDefaultInputMethod failed, ret:%d.=====\n", ret);
        return;
    }
    auto iter = std::find_if(
        props.begin(), props.end(), [sysProp](const Property &prop) { return sysProp->name != prop.name; });
    if (iter == props.end()) {
        return;
    }
    NotifySaMakeImage(iter->name);
}

int main()
{
    GrantNativePermission();
    int32_t input = 0;
    // 4: input 4
    while (input != 4) {
        printf("=====1:MakeSysImeImage  2:MakeOtherImeImage  3:MakeAppImage  4:exit=====\n");
        printf("input: ");
        cin >> input;
        switch (input) {
            // 1: input 1
            case 1:
                NotifySaMakeSysImeImage();
                break;
            // 2: input 2
            case 2:
                NotifySaMakeOtherImeImage();
                break;
            // 3: input 3
            case 3:
                NotifySaMakeAppImage();
                break;
            // 4: input 4
            case 4:
                printf("=====EXIT=====\n");
                break;
            default:
                printf("=====input error!=====\n");
        }
    }
    return 0;
}