/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef SERVICES_INCLUDE_FILE_MANAGER_H
#define SERVICES_INCLUDE_FILE_MANAGER_H
#include "third_party/json/include/nlohmann/json.hpp"
namespace OHOS {
namespace MiscServices {
struct FileInfo {
    std::string path;
    std::string fileName;
    mode_t pathMode;
    int32_t fileMode;
};

class FileManager {
public:
    static FileManager &GetInstance();
    int32_t CreateCacheFile(FileInfo &info);
    bool ReadJsonFile(const std::string &path, nlohmann::json &jsonCfg);
    bool WriteJsonFile(const std::string &path, const nlohmann::json &jsonCfg);

private:
    bool isCachePathExit(std::string &path);
    static const int SUCCESS = 0;
};
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_FILE_MANAGER_H