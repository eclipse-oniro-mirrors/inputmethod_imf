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

#include "numkey_apps_manager.h"

#include "global.h"
#include "ime_info_inquirer.h"

namespace OHOS {
namespace MiscServices {
#define CHECK_FEATURE_DISABLED_RETURN(retVal)   \
    do {                                        \
        if (!isFeatureEnabled_) {               \
            IMSA_HILOGD("feature not enabled"); \
            return retVal;                      \
        }                                       \
    } while (0)

NumkeyAppsManager &NumkeyAppsManager::GetInstance()
{
    static NumkeyAppsManager numkeyAppsManager;
    return numkeyAppsManager;
}
// LCOV_EXCL_START
void NumkeyAppsManager::Release()
{
    if (observers_.empty()) {
        return;
    }
    std::map<int32_t, sptr<SettingsDataObserver>> observers;
    {
        std::lock_guard<std::mutex> lock(observersLock_);
        observers = observers_;
        observers_.clear();
    }
    for (auto &observer : observers) {
        SettingsDataUtils::GetInstance().UnregisterObserver(observer.second);
    }
}

NumkeyAppsManager::~NumkeyAppsManager() { }

int32_t NumkeyAppsManager::Init(int32_t userId)
{
    IMSA_HILOGI("start, userId: %{public}d", userId);
    isFeatureEnabled_ = ImeInfoInquirer::GetInstance().IsEnableNumKey();
    {
        std::lock_guard<std::mutex> lock(appDeviceTypeLock_);
        disableNumKeyAppDeviceTypes_ = ImeInfoInquirer::GetInstance().GetDisableNumKeyAppDeviceTypes();
    }
    CHECK_FEATURE_DISABLED_RETURN(ErrorCode::NO_ERROR);

    int32_t ret = InitWhiteList();
    IMSA_HILOGI("InitWhiteList ret: %{public}d", ret);

    ret = RegisterUserBlockListData(userId);
    IMSA_HILOGI("RegisterUserBlockListData ret: %{public}d", ret);

    ret = UpdateUserBlockList(userId);
    IMSA_HILOGI("UpdateUserBlockList ret: %{public}d", ret);
    return ret;
}

bool NumkeyAppsManager::NeedAutoNumKeyInput(int32_t userId, const std::string &bundleName)
{
    CHECK_FEATURE_DISABLED_RETURN(false);
    if (IsInNumkeyBlockList(userId, bundleName)) {
        return false;
    }
    if (IsInNumKeyWhiteList(bundleName)) {
        return true;
    }
    {
        std::lock_guard<std::mutex> lock(appDeviceTypeLock_);
        if (disableNumKeyAppDeviceTypes_.empty()) {
            IMSA_HILOGE("disableNumKeyAppDeviceTypes empty.");
            return false;
        }
    }
    std::string compatibleDeviceType;
    bool ret = ImeInfoInquirer::GetInstance().GetCompatibleDeviceType(bundleName, compatibleDeviceType);
    if (!ret || compatibleDeviceType.empty()) {
        IMSA_HILOGE("getCompatibleDeviceType failed.");
        return false;
    }
    std::transform(compatibleDeviceType.begin(), compatibleDeviceType.end(), compatibleDeviceType.begin(),
        [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
    {
        std::lock_guard<std::mutex> lock(appDeviceTypeLock_);
        if (disableNumKeyAppDeviceTypes_.find(compatibleDeviceType) != disableNumKeyAppDeviceTypes_.end()) {
            IMSA_HILOGE("bundleName: %{public}s, compatibleDeviceType not supported.", bundleName.c_str());
            return false;
        }
    }
    IMSA_HILOGD("bundleName: %{public}s, support auto numkey input.", bundleName.c_str());
    return true;
}

int32_t NumkeyAppsManager::OnUserSwitched(int32_t userId)
{
    CHECK_FEATURE_DISABLED_RETURN(ErrorCode::NO_ERROR);
    IMSA_HILOGI("userId %{public}d", userId);
    RegisterUserBlockListData(userId);
    int32_t ret = UpdateUserBlockList(userId);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("UpdateUserBlockList failed, ret: %{public}d", ret);
        return ret;
    }
    return ErrorCode::NO_ERROR;
}

int32_t NumkeyAppsManager::OnUserRemoved(int32_t userId)
{
    CHECK_FEATURE_DISABLED_RETURN(ErrorCode::NO_ERROR);
    IMSA_HILOGI("userId %{public}d", userId);
    sptr<SettingsDataObserver> observer = nullptr;
    {
        std::lock_guard<std::mutex> lock(observersLock_);
        auto iter = observers_.find(userId);
        if (iter == observers_.end()) {
            IMSA_HILOGD("observer not found");
            return ErrorCode::NO_ERROR;
        }
        observer = iter->second;
    }
    int32_t ret = SettingsDataUtils::GetInstance().UnregisterObserver(observer);
    {
        std::lock_guard<std::mutex> lock(observersLock_);
        observers_.erase(userId);
    }
    return ret;
}

int32_t NumkeyAppsManager::InitWhiteList()
{
    if (isListInited_.load()) {
        return ErrorCode::NO_ERROR;
    }
    std::unordered_set<std::string> whiteList;
    int32_t ret = ParseWhiteList(whiteList);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGI("ParseWhiteList failed, ret: %{public}d", ret);
        return ret;
    }
    std::lock_guard<std::mutex> lock(appListLock_);
    numKeyAppList_ = whiteList;
    IMSA_HILOGI("success, list size: %{public}zu", numKeyAppList_.size());
    return ErrorCode::NO_ERROR;
}

int32_t NumkeyAppsManager::UpdateUserBlockList(int32_t userId)
{
    std::unordered_set<std::string> blockList;
    int32_t ret = ParseBlockList(userId, blockList);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("ParseBlockList failed, ret: %{public}d", ret);
        return ret;
    }
    std::lock_guard<std::mutex> lock(blockListLock_);
    usersBlockList_.insert_or_assign(userId, blockList);
    IMSA_HILOGI("success, list size: %{public}zu", blockList.size());
    return ErrorCode::NO_ERROR;
}

int32_t NumkeyAppsManager::ParseWhiteList(std::unordered_set<std::string> &list)
{
    std::string valueStr;
    int32_t ret = SettingsDataUtils::GetInstance().GetStringValue(SETTING_URI_PROXY, COMPATIBLE_APP_STRATEGY, valueStr);
    if (ret != ErrorCode::NO_ERROR && ret != ErrorCode::ERROR_KEYWORD_NOT_FOUND) {
        IMSA_HILOGE("failed to get white list from settings data, ret: %{public}d", ret);
        return ret;
    }
    if (ret == ErrorCode::ERROR_KEYWORD_NOT_FOUND) {
        IMSA_HILOGD("key not found");
        return ErrorCode::NO_ERROR;
    }
    NumkeyAppListCfg whiteListCfg;
    if (!whiteListCfg.Unmarshall(valueStr)) {
        IMSA_HILOGE("unmarshall failed");
        return ErrorCode::ERROR_PARSE_CONFIG_FILE;
    }
    for (const auto &app : whiteListCfg.numkeyApps) {
        list.insert(app.name);
    }
    return ErrorCode::NO_ERROR;
}

int32_t NumkeyAppsManager::ParseBlockList(int32_t userId, std::unordered_set<std::string> &list)
{
    std::string valueStr;
    int32_t ret = SettingsDataUtils::GetInstance().GetStringValue(
        SETTINGS_USER_DATA_URI + std::to_string(userId) + "?Proxy=true", COMPATIBLE_SETTING_STRATEGY, valueStr);
    if (ret != ErrorCode::NO_ERROR && ret != ErrorCode::ERROR_KEYWORD_NOT_FOUND) {
        IMSA_HILOGE("failed to get white list from settings data, ret: %{public}d", ret);
        return ret;
    }
    if (ret == ErrorCode::ERROR_KEYWORD_NOT_FOUND) {
        IMSA_HILOGD("key not found");
        return ErrorCode::NO_ERROR;
    }
    UserBlockListCfg blockListCfg;
    if (!blockListCfg.Unmarshall(valueStr)) {
        IMSA_HILOGE("unmarshall failed");
        return ErrorCode::ERROR_PARSE_CONFIG_FILE;
    }
    for (const auto &app : blockListCfg.blockApps) {
        list.insert(app);
    }
    return ErrorCode::NO_ERROR;
}

int32_t NumkeyAppsManager::RegisterUserBlockListData(int32_t userId)
{
    {
        std::lock_guard<std::mutex> lock(observersLock_);
        auto iter = observers_.find(userId);
        if (iter != observers_.end() && iter->second != nullptr) {
            IMSA_HILOGI("already registered, userId: %{public}d", userId);
            return ErrorCode::NO_ERROR;
        }
    }
    auto func = [this, userId]() {
        IMSA_HILOGI("on block list change, userId: %{public}d", userId);
        UpdateUserBlockList(userId);
    };
    std::string uriProxy = SETTINGS_USER_DATA_URI + std::to_string(userId) + "?Proxy=true";
    sptr<SettingsDataObserver> observer = nullptr;
    int32_t ret =
        SettingsDataUtils::GetInstance().RegisterObserver(uriProxy, COMPATIBLE_SETTING_STRATEGY, func, observer);
    if (ret != ErrorCode::NO_ERROR || observer == nullptr) {
        IMSA_HILOGE("RegisterObserver failed or observer nullptr, ret: %{public}d", ret);
        return ret;
    }
    IMSA_HILOGI("end, userId: %{public}d ", userId);
    std::lock_guard<std::mutex> lock(observersLock_);
    observers_.insert_or_assign(userId, observer);
    return ErrorCode::NO_ERROR;
}

bool NumkeyAppsManager::IsInNumKeyWhiteList(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(appListLock_);
    if (numKeyAppList_.find(bundleName) == numKeyAppList_.end()) {
        return false;
    }
    IMSA_HILOGD("%{public}s in white list.", bundleName.c_str());
    return true;
}

bool NumkeyAppsManager::IsInNumkeyBlockList(int32_t userId, const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(blockListLock_);
    auto iter = usersBlockList_.find(userId);
    if (iter == usersBlockList_.end()) {
        IMSA_HILOGD("user %{public}d block list is empty.", userId);
        return false;
    }
    auto blockList = iter->second;
    if (blockList.find(bundleName) == blockList.end()) {
        return false;
    }
    IMSA_HILOGD("%{public}s in block list.", bundleName.c_str());
    return true;
}
// LCOV_EXCL_STOP
} // namespace MiscServices
} // namespace OHOS