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
#include "settings_data_utils.h"

#include <sstream>
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace MiscServices {
SettingsDataUtils::~SettingsDataUtils()
{
    {
        std::lock_guard<std::mutex> autoLock(remoteObjMutex_);
        remoteObj_ = nullptr;
    }
}
// LCOV_EXCL_START
void SettingsDataUtils::Release()
{
    std::list<sptr<SettingsDataObserver>> observerList;
    {
        std::lock_guard<decltype(observerListMutex_)> lock(observerListMutex_);
        observerList = observerList_;
        observerList_.clear();
    }
    if (!observerList.empty()) {
        for (auto &observer : observerList) {
            UnregisterObserver(observer);
        }
    }
}
// LCOV_EXCL_STOP
SettingsDataUtils &SettingsDataUtils::GetInstance()
{
    static SettingsDataUtils instance;
    return instance;
}

int32_t SettingsDataUtils::CreateAndRegisterObserver(
    const std::string &uriProxy, const std::string &key, const SettingsDataObserver::CallbackFunc &func)
{
    IMSA_HILOGD("uriProxy:%{public}s, key: %{public}s.", uriProxy.c_str(), key.c_str());
    sptr<SettingsDataObserver> observer = new (std::nothrow) SettingsDataObserver(uriProxy, key, func);
    if (observer == nullptr) {
        IMSA_HILOGE("observer is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    return RegisterObserver(observer);
}
// LCOV_EXCL_START
int32_t SettingsDataUtils::RegisterObserver(const std::string &uriProxy, const std::string &key,
    const SettingsDataObserver::CallbackFunc &func, sptr<SettingsDataObserver> &observer)
{
    observer = new (std::nothrow) SettingsDataObserver(uriProxy, key, func);
    if (observer == nullptr) {
        IMSA_HILOGE("observer is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    return RegisterObserver(observer);
}
// LCOV_EXCL_STOP
int32_t SettingsDataUtils::RegisterObserver(const sptr<SettingsDataObserver> &observer)
{
    if (observer == nullptr) {
        IMSA_HILOGE("observer is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto uri = GenerateTargetUri(observer->GetUriProxy(), observer->GetKey());
    auto helper = SettingsDataUtils::CreateDataShareHelper(observer->GetUriProxy());
    if (helper == nullptr) {
        IMSA_HILOGE("helper is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    helper->RegisterObserver(uri, observer);
    ReleaseDataShareHelper(helper);
    IMSA_HILOGD("succeed to register observer of uri: %{public}s.", uri.ToString().c_str());

    std::lock_guard<decltype(observerListMutex_)> lock(observerListMutex_);
    observerList_.push_back(observer);
    return ErrorCode::NO_ERROR;
}

int32_t SettingsDataUtils::UnregisterObserver(const sptr<SettingsDataObserver> &observer)
{
    if (observer == nullptr) {
        IMSA_HILOGE("observer is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto uri = GenerateTargetUri(observer->GetUriProxy(), observer->GetKey());
    auto helper = SettingsDataUtils::CreateDataShareHelper(observer->GetUriProxy());
    if (helper == nullptr) {
        IMSA_HILOGE("helper is nullptr!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    helper->UnregisterObserver(uri, observer);
    ReleaseDataShareHelper(helper);
    IMSA_HILOGD("succeed to unregister observer of uri: %{public}s.", uri.ToString().c_str());

    std::lock_guard<decltype(observerListMutex_)> lock(observerListMutex_);
    observerList_.remove(observer);
    return ErrorCode::NO_ERROR;
}

std::shared_ptr<DataShare::DataShareHelper> SettingsDataUtils::CreateDataShareHelper(const std::string &uriProxy)
{
    auto remoteObj = GetToken();
    if (remoteObj == nullptr) {
        IMSA_HILOGE("remoteObk is nullptr!");
        return nullptr;
    }

    auto helper = DataShare::DataShareHelper::Creator(remoteObj_, uriProxy, std::string(SETTINGS_DATA_EXT_URI));
    if (helper == nullptr) {
        IMSA_HILOGE("create helper failed, uri: %{public}s!", uriProxy.c_str());
        return nullptr;
    }
    return helper;
}

bool SettingsDataUtils::ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> &helper)
{
    if (helper == nullptr) {
        IMSA_HILOGW("helper is nullptr.");
        return true;
    }
    if (!helper->Release()) {
        IMSA_HILOGE("release data share helper failed.");
        return false;
    }
    return true;
}

Uri SettingsDataUtils::GenerateTargetUri(const std::string &uriProxy, const std::string &key)
{
    Uri uri(uriProxy + "&key=" + key);
    return uri;
}
// LCOV_EXCL_START
bool SettingsDataUtils::SetStringValue(const std::string &uriProxy, const std::string &key, const std::string &value)
{
    IMSA_HILOGD("start.");
    auto helper = CreateDataShareHelper(uriProxy);
    if (helper == nullptr) {
        IMSA_HILOGE("helper is nullptr.");
        return false;
    }
    DataShare::DataShareValueObject keyObj(key);
    DataShare::DataShareValueObject valueObj(value);
    DataShare::DataShareValuesBucket bucket;
    bucket.Put(SETTING_COLUMN_KEYWORD, keyObj);
    bucket.Put(SETTING_COLUMN_VALUE, valueObj);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);
    Uri uri(GenerateTargetUri(uriProxy, key));
    if (helper->Update(uri, predicates, bucket) <= 0) {
        int index = helper->Insert(uri, bucket);
        IMSA_HILOGI("no data exists, insert ret index: %{public}d", index);
    } else {
        IMSA_HILOGI("data exits");
    }
    bool ret = ReleaseDataShareHelper(helper);
    IMSA_HILOGI("ReleaseDataShareHelper isSuccess: %{public}d", ret);
    return ret;
}

int32_t SettingsDataUtils::GetStringValue(const std::string &uriProxy, const std::string &key, std::string &value)
{
    IMSA_HILOGD("start.");
    auto helper = CreateDataShareHelper(uriProxy);
    if (helper == nullptr) {
        IMSA_HILOGE("helper is nullptr.");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    std::vector<std::string> columns = { SETTING_COLUMN_VALUE };
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);
    Uri uri(GenerateTargetUri(uriProxy, key));
    auto resultSet = helper->Query(uri, predicates, columns);
    ReleaseDataShareHelper(helper);
    if (resultSet == nullptr) {
        IMSA_HILOGE("resultSet is nullptr.");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    int32_t count = 0;
    resultSet->GetRowCount(count);
    if (count <= 0) {
        IMSA_HILOGW("not found keyword, key: %{public}s, count: %{public}d.", key.c_str(), count);
        resultSet->Close();
        return ErrorCode::ERROR_KEYWORD_NOT_FOUND;
    }

    int32_t columIndex = 0;
    resultSet->GoToFirstRow();
    resultSet->GetColumnIndex(SETTING_COLUMN_VALUE, columIndex);
    int32_t ret = resultSet->GetString(columIndex, value);
    if (ret != DataShare::E_OK) {
        IMSA_HILOGE("failed to GetString, ret: %{public}d!", ret);
    }
    resultSet->Close();
    return ret;
}
// LCOV_EXCL_STOP
sptr<IRemoteObject> SettingsDataUtils::GetToken()
{
    std::lock_guard<std::mutex> autoLock(remoteObjMutex_);
    if (remoteObj_ != nullptr) {
        return remoteObj_;
    }
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        IMSA_HILOGE("system ability manager is nullptr!");
        return nullptr;
    }
    auto remoteObj = samgr->GetSystemAbility(INPUT_METHOD_SYSTEM_ABILITY_ID);
    if (remoteObj == nullptr) {
        IMSA_HILOGE("system ability is nullptr!");
        return nullptr;
    }
    remoteObj_ = remoteObj;
    return remoteObj_;
}

void SettingsDataUtils::NotifyDataShareReady()
{
    isDataShareReady_.store(true);
}

bool SettingsDataUtils::IsDataShareReady()
{
    return isDataShareReady_.load();
}
} // namespace MiscServices
} // namespace OHOS