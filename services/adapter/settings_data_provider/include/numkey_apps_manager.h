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

#ifndef INPUTMETHOD_IMF_AUTO_NUMBER_INPUT_APPS_MANAGER_H
#define INPUTMETHOD_IMF_AUTO_NUMBER_INPUT_APPS_MANAGER_H

#include "global.h"
#include "settings_data_utils.h"
#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
#include "comp_config_dl_loader.h"
#endif

namespace OHOS {
namespace MiscServices {
static constexpr int32_t BLOCK_MODE = 8;
// Developer config key from compatibility config center: multi modal input options
static constexpr const char *COMP_CONFIG_KEY_NUM_KEY = "numKeyOptions";
#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
enum class DevConfigState : int32_t {
    NO_CONFIG = -1,
    DISABLED = 0,
    ENABLED = 1,
};

struct NumKeyOptions : public Serializable {
    bool autoConsumeNumKeysAndInsert{ false };
    bool hasAutoConsumeNumKeysAndInsert{ false };
    bool Unmarshal(cJSON *node) override
    {
        hasAutoConsumeNumKeysAndInsert =
            GetValue(node, GET_NAME(autoConsumeNumKeysAndInsert), autoConsumeNumKeysAndInsert);
        IMSA_HILOGD("autoConsumeNumKeysAndInsert: %{public}d, has: %{public}d",
            autoConsumeNumKeysAndInsert, hasAutoConsumeNumKeysAndInsert);
        return true;
    }
};
#endif // COMPATIBILITY_CONFIG_CENTER_ENABLE

struct UserBlockListCfg : public Serializable {
    std::vector<std::string> blockApps;
    bool Unmarshal(cJSON *node) override
    {
        std::function<bool(int32_t)> filter = [](const int32_t &mode) { return mode == BLOCK_MODE; };
        GetKeys(node, blockApps, filter);
        return true;
    }
};

class NumkeyAppsManager {
public:
    static NumkeyAppsManager &GetInstance();
    int32_t Init(int32_t userId);
    void Release();
    bool NeedAutoNumKeyInput(int32_t userId, const std::string &bundleName);
    int32_t OnUserSwitched(int32_t userId);
    int32_t OnUserRemoved(int32_t userId);
    int32_t RegisterUserBlockListData(int32_t userId);
    static constexpr const char *COMPATIBLE_SETTING_STRATEGY = "COMPATIBLE_SETTING_STRATEGY";

private:
    NumkeyAppsManager() = default;
    ~NumkeyAppsManager();
    NumkeyAppsManager(const NumkeyAppsManager &) = delete;
    NumkeyAppsManager(NumkeyAppsManager &&) = delete;
    NumkeyAppsManager &operator=(const NumkeyAppsManager &) = delete;
    NumkeyAppsManager &operator=(NumkeyAppsManager &&) = delete;

    int32_t InitCompConfigReader();
    int32_t UpdateUserBlockList(int32_t userId);
    static int32_t ParseBlockList(int32_t userId, std::unordered_set<std::string> &list);
    bool IsInNumkeyBlockList(int32_t userId, const std::string &bundleName);
#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    DevConfigState QueryDevCompConfig(const std::string &bundleName);
#endif // COMPATIBILITY_CONFIG_CENTER_ENABLE

    bool isFeatureEnabled_{ false };
    std::mutex appDeviceTypeLock_;
    std::unordered_set<std::string> disableNumKeyAppDeviceTypes_;

#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    std::mutex compConfigLock_;
    CompConfigDlLoader compConfigLoader_;
    bool compConfigInited_{ false };
#endif // COMPATIBILITY_CONFIG_CENTER_ENABLE

    std::mutex blockListLock_;
    std::map<int32_t, std::unordered_set<std::string>> usersBlockList_;
    std::mutex observersLock_;
    std::map<int32_t, sptr<SettingsDataObserver>> observers_;
};
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_IMF_AUTO_NUMBER_INPUT_APPS_MANAGER_H
