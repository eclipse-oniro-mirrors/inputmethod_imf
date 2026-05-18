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
#include <cstdio>
#include <iostream>

#include "accesstoken_kit.h"
#include "global.h"
#include "ime_event_listener.h"
#include "ime_event_monitor_manager.h"
#include "input_method_controller.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
using namespace std;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::MiscServices;
std::vector<std::shared_ptr<ImeEventListener>> inputStatusChangedListeners_;
std::vector<std::shared_ptr<ImeEventListener>> softKeyboardInfoChangedListeners_;
const int32_t PERMISSION_NUM = 1;

void GrantNativePermission()
{
    const char **perms = new const char *[PERMISSION_NUM];
    perms[0] = "ohos.permission.MANAGE_SECURE_SETTINGS";
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = PERMISSION_NUM,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "imf_imc_inner_test",
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

BoundImeInfo GetSoftKeyboardInfo()
{
    auto userId = 100;
    BoundImeInfo imeInfo;
    auto ret = InputMethodController::GetInstance()->GetSoftKeyboardInfo(userId, imeInfo);
    printf("=====GetSoftKeyboardInfo ret/imeInfo:%d/%s.=====\n", ret, imeInfo.ToString().c_str());
    return imeInfo;
}

void GetSoftKeyboardWithInvalidUserId()
{
    int32_t userId = 1000;
    BoundImeInfo imeInfo;
    auto ret = InputMethodController::GetInstance()->GetSoftKeyboardInfo(userId, imeInfo);
    printf("=====GetSoftKeyboardWithInvalidUserId ret/imeInfo:%d/%s.=====\n", ret, imeInfo.ToString().c_str());
}

class ImeEventListenerImplListener : public ImeEventListener {
public:
    void OnInputStart(uint32_t callingWndId, int32_t requestKeyboardReason) override
    {
        printf(
            "=====OnInputStart callingWndId/requestKeyboardReason:%u/%d.=====\n", callingWndId, requestKeyboardReason);
    }
    void OnInputStop() override
    {
        printf("=====OnInputStop run in.=====\n.");
    }
    void OnInputStart(const InputStartInfo &inputStartInfo) override
    {
        printf("=====inputStartInfo:%s.=====\n", inputStartInfo.ToString().c_str());
    }
    void OnInputStop(const InputStopInfo &inputStopInfo) override
    {
        printf("=====inputStopInfo:%s.=====\n", inputStopInfo.ToString().c_str());
    }
    void OnSoftKeyboardInfoChanged(
        int32_t userId, const BoundImeInfo &oldImeInfo, const BoundImeInfo &newImeInfo) override
    {
        printf("=====oldInfo/newInfo:%d/%s/%s.=====\n", userId, oldImeInfo.ToString().c_str(),
            newImeInfo.ToString().c_str());
        auto imeInfo = GetSoftKeyboardInfo();
        if (imeInfo == newImeInfo) {
            printf("=====get boundImeInfo same with cb.=====\n");
        }
    }
};

void RegisterSoftKeyboardInfoChangedListener()
{
    auto listener = std::make_shared<ImeEventListenerImplListener>();
    auto ret = ImeEventMonitorManager::GetInstance().RegisterImeEventListener(
        EVENT_SOFT_KEYBOARD_INFO_CHANGED_MASK, listener);
    if (ret != ErrorCode::NO_ERROR) {
        printf("=====Register soft keyboard changed changed listener failed:%d.=====\n", ret);
        return;
    }
    softKeyboardInfoChangedListeners_.push_back(listener);
    printf("=====Register soft keyboard changed listener succeed, current listener nums:%zu.=====\n",
        softKeyboardInfoChangedListeners_.size());
}

void RegisterSameSoftKeyboardInfoChangedListener()
{
    if (softKeyboardInfoChangedListeners_.empty()) {
        printf("=====has no soft keyboard changed listener.=====\n");
        return;
    }
    auto listener = softKeyboardInfoChangedListeners_.back();
    auto ret = ImeEventMonitorManager::GetInstance().RegisterImeEventListener(
        EVENT_SOFT_KEYBOARD_INFO_CHANGED_MASK, listener);
    if (ret != ErrorCode::NO_ERROR) {
        printf("=====Register same soft keyboard changed listener failed:%d.=====\n", ret);
        return;
    }
    printf("=====Register same soft keyboard changed succeed, current listener nums:%zu.=====\n",
        softKeyboardInfoChangedListeners_.size());
}

void UnRegisterSoftKeyboardInfoChangedListener()
{
    if (softKeyboardInfoChangedListeners_.empty()) {
        printf("=====has no soft keyboard listener.=====\n");
        return;
    }
    auto listener = softKeyboardInfoChangedListeners_.back();
    auto ret = ImeEventMonitorManager::GetInstance().UnRegisterImeEventListener(
        EVENT_SOFT_KEYBOARD_INFO_CHANGED_MASK, listener);
    if (ret != ErrorCode::NO_ERROR) {
        printf("=====Register soft keyboard changed listener failed:%d.=====\n", ret);
        return;
    }
    softKeyboardInfoChangedListeners_.pop_back();
    printf("=====UnRegister soft keyboard changed listener succeed, current listener nums:%zu.=====\n",
        softKeyboardInfoChangedListeners_.size());
}

void RegisterInputStatusChangedListener()
{
    auto listener = std::make_shared<ImeEventListenerImplListener>();
    auto ret =
        ImeEventMonitorManager::GetInstance().RegisterImeEventListener(EVENT_INPUT_STATUS_CHANGED_MASK, listener);
    if (ret != ErrorCode::NO_ERROR) {
        printf("=====Register input status changed listener failed:%d.=====\n", ret);
        return;
    }
    inputStatusChangedListeners_.push_back(listener);
    printf("=====Register input status changed listener succeed, current listener nums:%zu.=====\n",
        inputStatusChangedListeners_.size());
}

void RegisterSameInputStatusChangedListener()
{
    if (inputStatusChangedListeners_.empty()) {
        printf("=====has no input status changed listener.=====\n");
        return;
    }
    auto listener = inputStatusChangedListeners_.back();
    auto ret =
        ImeEventMonitorManager::GetInstance().RegisterImeEventListener(EVENT_INPUT_STATUS_CHANGED_MASK, listener);
    if (ret != ErrorCode::NO_ERROR) {
        printf("=====Register same input status changed listener failed:%d.=====\n", ret);
        return;
    }
    printf("=====Register same input status changed succeed, current listener nums:%zu.=====\n",
        inputStatusChangedListeners_.size());
}

void UnRegisterInputStatusChangedListener()
{
    if (inputStatusChangedListeners_.empty()) {
        printf("=====has no listener.=====\n");
        return;
    }
    auto listener = inputStatusChangedListeners_.back();
    auto ret =
        ImeEventMonitorManager::GetInstance().UnRegisterImeEventListener(EVENT_INPUT_STATUS_CHANGED_MASK, listener);
    if (ret != ErrorCode::NO_ERROR) {
        printf("=====UnRegister input status changed listener failed:%d.=====\n", ret);
        return;
    }
    inputStatusChangedListeners_.pop_back();
    printf("=====UnRegister input status changed succeed, current listener nums:%zu.=====\n",
        inputStatusChangedListeners_.size());
}

int main()
{
    GrantNativePermission();
    int32_t input = 0;
    // 100: input 100
    while (input != 100) {
        printf("=====1:RegisterInputStatusChangedListener  2:RegisterSameInputStatusChangedListener  "
               "3:UnRegisterInputStatusChangedListener  4.RegisterSoftKeyboardInfoChangedListener,  5. "
               "RegisterSameSoftKeyboardInfoChangedListener  6:UnRegisterSoftKeyboardInfoChangedListener   "
               "7.GetSoftKeyboardInfo  8.GetSoftKeyboardWithInvalidUserId  100.EXIT=====\n");
        printf("input: ");
        cin >> input;
        switch (input) {
            // 1: input 1
            case 1:
                RegisterInputStatusChangedListener();
                break;
            // 2: input 2
            case 2:
                RegisterSameInputStatusChangedListener();
                break;
            // 3: input 3
            case 3:
                UnRegisterInputStatusChangedListener();
                break;
            // 4: input 4
            case 4:
                RegisterSoftKeyboardInfoChangedListener();
                break;
            // 5: input 5
            case 5:
                RegisterSameSoftKeyboardInfoChangedListener();
                break;
            // 6: input 6
            case 6:
                UnRegisterSoftKeyboardInfoChangedListener();
                break;
            // 7: input 7
            case 7:
                GetSoftKeyboardInfo();
                break;
            // 8: input 8
            case 8:
                GetSoftKeyboardWithInvalidUserId();
                break;
            // 100: input 100
            case 100:
                printf("=====EXIT=====\n");
                break;
            default:
                printf("=====input error!=====\n");
        }
    }
    return 0;
}