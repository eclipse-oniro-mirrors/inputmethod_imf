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

#include "full_ime_info_manager.h"

#include <algorithm>

#include "ime_info_inquirer.h"
#include "os_account_info.h"
#include "os_account_manager.h"
namespace OHOS {
namespace MiscServices {
using namespace AccountSA;
FullImeInfoManager &FullImeInfoManager::GetInstance()
{
    static FullImeInfoManager instance;
    // 此处是否起定时器，过一段时间调用Init()自动更新下
    return instance;
}

int32_t FullImeInfoManager::Init()
{
    lock_.Lock();
    std::vector<OsAccountInfo> accountInfos;
    auto ret = OsAccountManager::QueryAllCreatedOsAccounts(accountInfos);
    if (ret != 0) {
        return ErrorCode::NO_ERROR;
    }
    for (auto &acInfo : accountInfos) {
        auto userId = acInfo.GetLocalId();
        auto infos = ImeInfoInquirer::GetInstance().QueryFullImeInfo(userId);
        if (infos.empty()) {
            continue;
        }
        fullImeInfos_.insert_or_assign(userId, infos);
    }
    Print();
    lock_.UnLock();
    return ErrorCode::NO_ERROR;
}

int32_t FullImeInfoManager::Delete(int32_t userId)
{
    lock_.Lock();
    fullImeInfos_.erase(userId);
    lock_.UnLock();
    return ErrorCode::NO_ERROR;
}

int32_t FullImeInfoManager::Add(int32_t userId, const std::string &bundleName)
{
    lock_.Lock();
    auto imeInfo = ImeInfoInquirer::GetInstance().GetFullImeInfo(userId, bundleName);
    if (imeInfo == nullptr) {
        return ErrorCode::ERROR_PACKAGE_MANAGER;
    }
    auto it = fullImeInfos_.find(userId);
    if (it == fullImeInfos_.end()) {
        fullImeInfos_.insert({ userId, { imeInfo } });
        return ErrorCode::NO_ERROR;
    }
    auto iter = std::find_if(it->second.begin(), it->second.end(),
        [bundleName](const std::shared_ptr<FullImeInfo> &info) { return bundleName == info->prop.name; });
    if (iter != it->second.end()) {
        return ErrorCode::NO_ERROR;
    }
    it->second.push_back(imeInfo);
    lock_.UnLock();
    return ErrorCode::NO_ERROR;
}

int32_t FullImeInfoManager::Delete(int32_t userId, const std::string &bundleName)
{
    lock_.Lock();
    auto it = fullImeInfos_.find(userId);
    if (it == fullImeInfos_.end()) {
        return ErrorCode::NO_ERROR;
    }
    auto iter = std::find_if(it->second.begin(), it->second.end(),
        [bundleName](const std::shared_ptr<FullImeInfo> &info) { return bundleName == info->prop.name; });
    if (iter == it->second.end()) {
        return ErrorCode::NO_ERROR;
    }
    it->second.erase(iter);
    lock_.UnLock();
    return ErrorCode::NO_ERROR;
}

int32_t FullImeInfoManager::update(int32_t userId, const std::string &bundleName)
{
    lock_.Lock();
    auto imeInfo = ImeInfoInquirer::GetInstance().GetFullImeInfo(userId, bundleName);
    if (imeInfo == nullptr) {
        return ErrorCode::ERROR_PACKAGE_MANAGER;
    }
    auto it = fullImeInfos_.find(userId);
    if (it == fullImeInfos_.end()) {
        fullImeInfos_.insert({ userId, { imeInfo } });
        return ErrorCode::NO_ERROR;
    }
    auto iter = std::find_if(it->second.begin(), it->second.end(),
        [bundleName](const std::shared_ptr<FullImeInfo> &info) { return bundleName == info->prop.name; });
    if (iter != it->second.end()) {
        it->second.erase(iter);
    }
    it->second.push_back(imeInfo);
    lock_.UnLock();
    return ErrorCode::NO_ERROR;
}

int32_t FullImeInfoManager::UpdateAllLabel(int32_t userId)
{
    lock_.Lock();
    auto it = fullImeInfos_.find(userId);
    if (it == fullImeInfos_.end()) {
        auto infos = ImeInfoInquirer::GetInstance().QueryFullImeInfo(userId);
        if (!infos.empty()) {
            fullImeInfos_.insert_or_assign(userId, infos);
        }
        return ErrorCode::NO_ERROR;
    }
    for (auto &imeInfo : it->second) {
        ImeInfoInquirer::GetInstance().UpdateLabel(userId, imeInfo);
    }
    fullImeInfos_.insert_or_assign(userId, it->second);
    lock_.UnLock();
    return ErrorCode::NO_ERROR;
}

std::vector<FullImeInfo> FullImeInfoManager::Get(int32_t userId)
{
    lock_.Lock();
    std::vector<FullImeInfo> imeInfos;
    auto it = fullImeInfos_.find(userId);
    if (it == fullImeInfos_.end()) {
        return imeInfos;
    }
    for (auto &info : it->second) {
        imeInfos.push_back(*info);
    }
    lock_.UnLock();
    return imeInfos;
}

void FullImeInfoManager::Print()
{
    for (const auto &info : fullImeInfos_) {
        IMSA_HILOGI("userId:%{public}d.", info.first);
        for (const auto &fullInfo : info.second) {
            IMSA_HILOGI("prop:[name:%{public}s,id:%{public}s,labelId:%{public}d,label:%{public}s,iconId:%{public}d].",
                fullInfo->prop.name.c_str(), fullInfo->prop.id.c_str(), fullInfo->prop.labelId,
                fullInfo->prop.label.c_str(), fullInfo->prop.iconId);
            PrintSubProp(fullInfo->subProps);
        }
    }
}
void FullImeInfoManager::PrintSubProp(const std::vector<SubProperty> &subProps)
{
    for (const auto &subProp : subProps) {
        IMSA_HILOGI("subProp:[name:%{public}s,id:%{public}s,labelId:%{public}d,label:%{public}s,iconId:%{public}d,"
                    "locale:%{public}s,language:%{public}s,mode:%{public}s].",
            subProp.name.c_str(), subProp.id.c_str(), subProp.labelId, subProp.label.c_str(), subProp.iconId,
            subProp.locale.c_str(), subProp.language.c_str(), subProp.mode.c_str());
    }
}
} // namespace MiscServices
} // namespace OHOS