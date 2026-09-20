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

#include "exam_mode_manager.h"

#include "cJSON.h"
#include "settings_data_utils.h"

namespace OHOS {
namespace MiscServices {
namespace {
constexpr const char *FIELD_IS_EXAM_MODE = "isExamMode";
constexpr const char *FIELD_PREVIOUS_BUNDLE_NAME = "previousBundleName";
constexpr const char *FIELD_PREVIOUS_SUB_NAME = "previousSubName";
}

ExamModeManager &ExamModeManager::GetInstance()
{
    static ExamModeManager instance;
    return instance;
}

void ExamModeManager::InitFromPersistedData()
{
    if (!LoadFromPersistedData()) {
        IMSA_HILOGI("no persisted exam mode data found, using defaults");
        isExamMode_.store(false);
        {
            std::lock_guard<std::mutex> lock(previousImeMutex_);
            previousImeBundleName_.clear();
            previousImeSubName_.clear();
        }
    }
}

bool ExamModeManager::LoadFromPersistedData()
{
    std::string value;
    auto ret = SettingsDataUtils::GetInstance().GetStringValue(SETTING_URI_PROXY, EXAM_MODE_KEY, value);
    if (ret != ErrorCode::NO_ERROR || value.empty()) {
        return false;
    }
    cJSON *root = cJSON_Parse(value.c_str());
    if (root == nullptr) {
        IMSA_HILOGE("failed to parse persisted exam mode data");
        return false;
    }
    cJSON *examModeItem = cJSON_GetObjectItem(root, FIELD_IS_EXAM_MODE);
    cJSON *bundleItem = cJSON_GetObjectItem(root, FIELD_PREVIOUS_BUNDLE_NAME);
    cJSON *subItem = cJSON_GetObjectItem(root, FIELD_PREVIOUS_SUB_NAME);
    if (examModeItem != nullptr && cJSON_IsBool(examModeItem)) {
        isExamMode_.store(examModeItem->valueint != 0);
    }
    std::lock_guard<std::mutex> lock(previousImeMutex_);
    if (bundleItem != nullptr && bundleItem->valuestring != nullptr) {
        previousImeBundleName_ = bundleItem->valuestring;
    }
    if (subItem != nullptr && subItem->valuestring != nullptr) {
        previousImeSubName_ = subItem->valuestring;
    }
    cJSON_Delete(root);
    IMSA_HILOGI("loaded persisted exam mode: %{public}d, previous ime: %{public}s/%{public}s",
        isExamMode_.load(), previousImeBundleName_.c_str(), previousImeSubName_.c_str());
    return true;
}

void ExamModeManager::Persist()
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        IMSA_HILOGE("failed to create json object for persist");
        return;
    }
    cJSON_AddBoolToObject(root, FIELD_IS_EXAM_MODE, isExamMode_.load());
    std::lock_guard<std::mutex> lock(previousImeMutex_);
    cJSON_AddStringToObject(root, FIELD_PREVIOUS_BUNDLE_NAME, previousImeBundleName_.c_str());
    cJSON_AddStringToObject(root, FIELD_PREVIOUS_SUB_NAME, previousImeSubName_.c_str());
    char *jsonStr = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (jsonStr == nullptr) {
        IMSA_HILOGE("failed to serialize exam mode data");
        return;
    }
    std::string value(jsonStr);
    cJSON_free(jsonStr);
    auto ret = SettingsDataUtils::GetInstance().SetStringValue(SETTING_URI_PROXY, EXAM_MODE_KEY, value);
    if (!ret) {
        IMSA_HILOGE("failed to persist exam mode data");
    }
}

bool ExamModeManager::IsExamMode()
{
    return isExamMode_.load();
}

void ExamModeManager::SetExamMode(bool isExamMode)
{
    IMSA_HILOGI("set exam mode: %{public}d", isExamMode);
    isExamMode_.store(isExamMode);
    Persist();
}

void ExamModeManager::SavePreviousIme(const std::string &bundleName, const std::string &subName)
{
    {
        std::lock_guard<std::mutex> lock(previousImeMutex_);
        previousImeBundleName_ = bundleName;
        previousImeSubName_ = subName;
    }
    IMSA_HILOGI("save previous ime: %{public}s/%{public}s", bundleName.c_str(), subName.c_str());
    Persist();
}

void ExamModeManager::GetPreviousIme(std::string &bundleName, std::string &subName)
{
    std::lock_guard<std::mutex> lock(previousImeMutex_);
    bundleName = previousImeBundleName_;
    subName = previousImeSubName_;
}

std::string ExamModeManager::GetPreviousImeBundleName()
{
    std::lock_guard<std::mutex> lock(previousImeMutex_);
    return previousImeBundleName_;
}

std::string ExamModeManager::GetPreviousImeSubName()
{
    std::lock_guard<std::mutex> lock(previousImeMutex_);
    return previousImeSubName_;
}

void ExamModeManager::ClearPreviousIme()
{
    {
        std::lock_guard<std::mutex> lock(previousImeMutex_);
        previousImeBundleName_.clear();
        previousImeSubName_.clear();
    }
    Persist();
}
} // namespace MiscServices
} // namespace OHOS
