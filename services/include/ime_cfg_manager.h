/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SERVICES_INCLUDE_IME_CFG_MANAGER_H
#define SERVICES_INCLUDE_IME_CFG_MANAGER_H

#include <sys/types.h>

#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "serializable.h"
namespace OHOS {
namespace MiscServices {
struct ImePersistCfg : public Serializable {
    ImePersistCfg()= default;
    ImePersistCfg(int32_t userId, std::string currentIme, std::string currentSubName)
        : userId(userId), currentIme(std::move(currentIme)), currentSubName(std::move(currentSubName)){};
    static constexpr int32_t INVALID_USERID = -1;
    int32_t userId{ INVALID_USERID };
    std::string currentIme;
    std::string currentSubName;

    bool Marshal(cJSON *node) const override
    {
        Serializable::SetValue(node, GET_NAME(userId), userId);
        Serializable::SetValue(node, GET_NAME(currentIme), currentIme);
        Serializable::SetValue(node, GET_NAME(currentSubName), currentSubName);
        return true;
    }
    bool Unmarshal(cJSON *node) override
    {
        Serializable::GetValue(node, GET_NAME(userId), userId);
        Serializable::GetValue(node, GET_NAME(userId), currentIme);
        Serializable::GetValue(node, GET_NAME(userId), currentSubName);
        return true;
    }
};

struct ImePersistInfo : public Serializable {
    std::vector<ImePersistCfg> imePersistCfg;
    bool Marshal(cJSON *node) const override
    {
        return Serializable::SetValue(node, GET_NAME(imeCfglist), imePersistCfg);
    }
    bool Unmarshal(cJSON *node) override
    {
        return Serializable::GetValue(node, GET_NAME(imeCfglist), imePersistCfg);
    }
};

struct ImeNativeCfg {
    std::string imeId;
    std::string bundleName;
    std::string subName;
    std::string extName;
};

class ImeCfgManager {
public:
    static ImeCfgManager &GetInstance();
    void Init();
    void AddImeCfg(const ImePersistCfg &cfg);
    void ModifyImeCfg(const ImePersistCfg &cfg);
    void DeleteImeCfg(int32_t userId);
    std::shared_ptr<ImeNativeCfg> GetCurrentImeCfg(int32_t userId);

private:
    ImeCfgManager() = default;
    ~ImeCfgManager() = default;
    void ReadImeCfg();
    void WriteImeCfg();
    ImePersistCfg GetImeCfg(int32_t userId);
    bool ParseImeCfg(const std::string &content);
    std::string PackageImeCfg();
    std::recursive_mutex imeCfgLock_;
    std::vector<ImePersistCfg> imeConfigs_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_IME_CFG_MANAGER_H
