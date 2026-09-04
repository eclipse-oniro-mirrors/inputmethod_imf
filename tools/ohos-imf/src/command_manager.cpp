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
#include "command_manager.h"

#include "insert_command.h"
namespace OHOS {
namespace MiscServices {
CommandManager &CommandManager::GetInstance()
{
    static CommandManager manager;
    return manager;
}

void CommandManager::Init()
{
    std::shared_ptr<Command> insertCommand = std::make_shared<InsertCommand>();
    commands_[insertCommand->GetName()] = insertCommand;
}

std::shared_ptr<Command> CommandManager::GetCmd(const std::string &name)
{
    auto iter = commands_.find(name);
    if (iter == commands_.end()) {
        return nullptr;
    }
    return iter->second;
}

std::vector<std::string> CommandManager::GetAllCmdNames()
{
    std::vector<std::string> names;
    for (const auto &command : commands_) {
        names.push_back(command.first);
    }
    return names;
}
} // namespace MiscServices
} // namespace OHOS