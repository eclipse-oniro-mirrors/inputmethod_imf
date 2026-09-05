/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IMF_CLI_COMMAND_MANAGER_H
#define IMF_CLI_COMMAND_MANAGER_H
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "command.h"

namespace OHOS {
namespace MiscServices {

class CommandManager {
public:
    static CommandManager &GetInstance();
    void Init();
    std::vector<std::string> GetAllCmdNames();
    std::shared_ptr<Command> GetCmd(const std::string &name);

private:
    CommandManager() = default;
    std::unordered_map<std::string, std::shared_ptr<Command>> commands_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // IMF_CLI_COMMAND_MANAGER_H