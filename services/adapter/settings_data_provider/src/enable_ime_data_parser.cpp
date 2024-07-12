/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "enable_ime_data_parser.h"

#include "ime_info_inquirer.h"
#include "iservice_registry.h"
#include "serializable.h"
#include "settings_data_utils.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace MiscServices {
std::mutex EnableImeDataParser::instanceMutex_;
sptr<EnableImeDataParser> EnableImeDataParser::instance_ = nullptr;
EnableImeDataParser::~EnableImeDataParser()
{
}

sptr<EnableImeDataParser> EnableImeDataParser::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceMutex_);
        if (instance_ == nullptr) {
            IMSA_HILOGI("need to create instance.");
            instance_ = new (std::nothrow) EnableImeDataParser();
            if (instance_ == nullptr) {
                IMSA_HILOGE("instance is nullptr!");
                return instance_;
            }
        }
    }
    return instance_;
}

int32_t EnableImeDataParser::Initialize(const int32_t userId)
{
    currentUserId_ = userId;
    enableList_.insert({ std::string(ENABLE_IME), {} });
    enableList_.insert({ std::string(ENABLE_KEYBOARD), {} });

    if (GetEnableData(ENABLE_IME, enableList_[std::string(ENABLE_IME)], userId) != ErrorCode::NO_ERROR) {
        IMSA_HILOGW("get enable ime list failed.");
    }
    if (GetEnableData(ENABLE_KEYBOARD, enableList_[std::string(ENABLE_KEYBOARD)], userId) != ErrorCode::NO_ERROR) {
        IMSA_HILOGW("get enable keyboard list failed.");
    }
    return ErrorCode::NO_ERROR;
}

void EnableImeDataParser::OnUserChanged(const int32_t targetUserId)
{
    std::lock_guard<std::mutex> autoLock(listMutex_);
    IMSA_HILOGD("current userId: %{public}d, switch to: %{public}d", currentUserId_, targetUserId);
    currentUserId_ = targetUserId;
    if (GetEnableData(ENABLE_IME, enableList_[std::string(ENABLE_IME)], targetUserId) != ErrorCode::NO_ERROR ||
        GetEnableData(ENABLE_KEYBOARD, enableList_[std::string(ENABLE_KEYBOARD)], targetUserId) !=
        ErrorCode::NO_ERROR) {
        IMSA_HILOGE("get enable list failed!");
        return;
    }
}

bool EnableImeDataParser::CheckNeedSwitch(const std::string &key, SwitchInfo &switchInfo, const int32_t userId)
{
    IMSA_HILOGD("start, data changed.");
    auto currentIme = ImeCfgManager::GetInstance().GetCurrentImeCfg(userId);
    auto defaultIme = ImeInfoInquirer::GetInstance().GetDefaultIme();
    switchInfo.bundleName = defaultIme.bundleName;
    switchInfo.subName = "";
    if (currentIme == nullptr) {
        IMSA_HILOGE("currentIme is nullptr!");
        return true;
    }
    if (key == std::string(ENABLE_IME)) {
        if (currentIme->bundleName == defaultIme.bundleName) {
            std::lock_guard<std::mutex> autoLock(listMutex_);
            GetEnableData(key, enableList_[key], userId);
            IMSA_HILOGD("current ime is default, do not need switch ime.");
            return false;
        }
        return CheckTargetEnableName(key, currentIme->bundleName, switchInfo.bundleName, userId);
    } else if (key == std::string(ENABLE_KEYBOARD)) {
        if (currentIme->bundleName != defaultIme.bundleName || currentIme->subName == defaultIme.subName) {
            IMSA_HILOGD("current ime is not default or id is default.");
            std::lock_guard<std::mutex> autoLock(listMutex_);
            GetEnableData(key, enableList_[key], userId);
            return false;
        }
        switchInfo.subName = defaultIme.subName;
        return CheckTargetEnableName(key, currentIme->subName, switchInfo.subName, userId);
    }
    IMSA_HILOGW("invalid key: %{public}s.", key.c_str());
    return false;
}

bool EnableImeDataParser::CheckNeedSwitch(const SwitchInfo &info, const int32_t userId)
{
    IMSA_HILOGD("current userId: %{public}d, target userId: %{public}d, check bundleName: %{public}s", currentUserId_,
        userId, info.bundleName.c_str());
    if (info.bundleName == ImeInfoInquirer::GetInstance().GetDefaultIme().bundleName) {
        IMSA_HILOGD("default ime, permit to switch");
        return true;
    }
    IMSA_HILOGD("check ime.");
    std::vector<std::string> enableVec;
    int32_t ret = GetEnableData(ENABLE_IME, enableVec, userId);
    if (ret != ErrorCode::NO_ERROR || enableVec.empty()) {
        IMSA_HILOGD("get enable list failed, or enable list is empty.");
        return false;
    }

    auto iter = std::find_if(enableVec.begin(), enableVec.end(),
        [&info](const std::string &ime) { return info.bundleName == ime; });
    if (iter != enableVec.end()) {
        IMSA_HILOGD("in enable list.");
        return true;
    }
    return false;
}

bool EnableImeDataParser::CheckTargetEnableName(const std::string &key, const std::string &targetName,
    std::string &nextIme, const int32_t userId)
{
    IMSA_HILOGD("start.");
    std::vector<std::string> enableVec;
    int32_t ret = GetEnableData(key, enableVec, userId);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("get enable list abnormal.");
        return false;
    }

    if (enableVec.empty()) {
        IMSA_HILOGE("enable empty, switch default ime.");
        return true;
    }
    std::lock_guard<std::mutex> autoLock(listMutex_);
    auto iter = std::find_if(enableVec.begin(), enableVec.end(),
        [&targetName](const std::string &ime) { return ime == targetName; });
    if (iter != enableVec.end()) {
        IMSA_HILOGD("enable list has current ime, do not need switch.");
        enableList_[key].assign(enableVec.begin(), enableVec.end());
        return false;
    }

    auto it = std::find_if(enableList_[key].begin(), enableList_[key].end(),
        [&targetName](const std::string &ime) { return ime == targetName; });
    if (it == enableList_[key].end()) {
        enableList_[key].assign(enableVec.begin(), enableVec.end());
        return true;
    }

    std::rotate(enableList_[key].begin(), it, enableList_[key].end());
    auto result =
        std::find_first_of(enableList_[key].begin(), enableList_[key].end(), enableVec.begin(), enableVec.end());
    if (result != enableList_[key].end()) {
        IMSA_HILOGD("found the next cached ime in enable ime list.");
        nextIme = *result;
    }
    enableList_[key].assign(enableVec.begin(), enableVec.end());
    return true;
}

int32_t EnableImeDataParser::GetEnableData(const std::string &key, std::vector<std::string> &enableVec,
    const int32_t userId)
{
    if (key != std::string(ENABLE_IME) && key != std::string(ENABLE_KEYBOARD)) {
        IMSA_HILOGD("invalid key: %{public}s.", key.c_str());
        return ErrorCode::ERROR_ENABLE_IME;
    }

    IMSA_HILOGD("userId: %{public}d, key: %{public}s.", userId, key.c_str());
    std::string valueStr;
    int32_t ret = SettingsDataUtils::GetInstance()->GetStringValue(key, valueStr);
    if (ret == ErrorCode::ERROR_KEYWORD_NOT_FOUND) {
        IMSA_HILOGW("no keyword exist");
        enableVec.clear();
        return ErrorCode::NO_ERROR;
    }
    if (ret != ErrorCode::NO_ERROR || valueStr.empty()) {
        IMSA_HILOGW("get value failed, or valueStr is empty.");
        return ErrorCode::ERROR_ENABLE_IME;
    }
    auto parseRet = false;
    if (key == ENABLE_IME) {
        parseRet = ParseEnableIme(valueStr, userId, enableVec);
    }
    if (key == ENABLE_KEYBOARD) {
        parseRet = ParseEnableKeyboard(valueStr, userId, enableVec);
    }
    return parseRet ? ErrorCode::NO_ERROR : ErrorCode::ERROR_ENABLE_IME;
}

bool EnableImeDataParser::ParseEnableIme(const std::string &valueStr, int32_t userId,
    std::vector<std::string> &enableVec)
{
    EnableImeCfg enableIme;
    enableIme.userImeCfg.userId = std::to_string(userId);
    auto ret = enableIme.Unmarshall(valueStr);
    if (!ret) {
        return ret;
    }
    enableVec = enableIme.userImeCfg.identities;
    return true;
}

bool EnableImeDataParser::ParseEnableKeyboard(const std::string &valueStr, int32_t userId,
    std::vector<std::string> &enableVec)
{
    EnableKeyBoardCfg enableKeyboard;
    enableKeyboard.userImeCfg.userId = std::to_string(userId);
    auto ret = enableKeyboard.Unmarshall(valueStr);
    if (!ret) {
        return ret;
    }
    enableVec = enableKeyboard.userImeCfg.identities;
    return true;
}
} // namespace MiscServices
} // namespace OHOS