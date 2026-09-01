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
#include "executor.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "cli_utils.h"
#include "command_manager.h"
namespace OHOS {
namespace MiscServices {
constexpr const char *TOOL_VERSION = "1.0.0"; // must same with the "version" in config.json
constexpr const char *TOOL_NAME = "ohos-imf";
constexpr const char *TOOL_DESCRIPTION = "Input method framework CLI tool";
constexpr int COLUMN_WIDTH = 18;
Executor::Executor(int argc, char *argv[])
{
    CommandManager::GetInstance().Init();
    if (argc < MIN_ARGUMENT_NUMBER) {
        cmd_ = "--help";
        return;
    }
    // 1 represent the second param
    cmd_ = argv[1];
    for (int i = 2; i < argc; i++) {
        argList_.emplace_back(argv[i]);
    }
}

std::string Executor::GenerateFullHelp()
{
    std::ostringstream oss;

    oss << TOOL_NAME << " - " << TOOL_DESCRIPTION << std::endl;
    oss << std::endl;
    oss << "Usage:" << std::endl;
    oss << "  " << TOOL_NAME << " [command] [options]" << std::endl;
    oss << std::endl;

    oss << "Parameters:" << std::endl;
    oss << std::left;
    oss << "  " << std::setw(COLUMN_WIDTH) << "--help"
        << "Display this help message" << std::endl;
    oss << "  " << std::setw(COLUMN_WIDTH) << "--version"
        << "Display tool version" << std::endl;
    oss << std::endl;

    oss << "SubCommands:" << std::endl;
    auto names = CommandManager::GetInstance().GetAllCmdNames();
    for (const auto &name : names) {
        auto cmd = CommandManager::GetInstance().GetCmd(name);
        oss << "  " << std::setw(COLUMN_WIDTH) << name << cmd->GetDescription() << std::endl;
    }
    oss << std::endl;

    oss << std::right;
    oss << "Examples:" << std::endl;
    oss << "  # View version" << std::endl;
    oss << "  " << TOOL_NAME << " --version" << std::endl;
    oss << "  # View the help of subCommand insert " << std::endl;
    oss << "  " << TOOL_NAME << " insert --help" << std::endl;
    oss << std::endl;

    return oss.str();
}

std::string Executor::GenerateCmdHelp(std::shared_ptr<Command> cmd)
{
    if (cmd == nullptr) {
        return "";
    }
    std::ostringstream oss;

    oss << TOOL_NAME << " " << cmd->GetName() << " - " << cmd->GetDescription() << '\n';
    oss << '\n';

    oss << "Usage:" << '\n';
    oss << "  " << cmd->GetUsage() << '\n';
    oss << '\n';

    oss << "Parameters:" << '\n';
    oss << std::left;
    for (const auto &param : cmd->GetParams()) {
        oss << "  " << std::setw(COLUMN_WIDTH) << param.first << param.second << '\n';
    }
    oss << "  " << std::setw(COLUMN_WIDTH) << "--help"
        << "Display this help message" << '\n';
    oss << std::right;
    oss << '\n';

    oss << "Examples:" << '\n';
    for (const auto &example : cmd->GetExamples()) {
        oss << "  " << example.first << std::endl;
        oss << "  " << example.second << std::endl;
        oss << std::endl;
    }

    return oss.str();
}

std::string Executor::ExtractVersion()
{
    return TOOL_VERSION;
}

std::string Executor::Execute()
{
    if (cmd_ == "--help") {
        return GenerateFullHelp();
    }
    if (cmd_ == "--version") {
        return ExtractVersion();
    }
    auto cmd = CommandManager::GetInstance().GetCmd(cmd_);
    if (cmd == nullptr) {
        return CliUtils::GenerateError({ "ERR_CMD_INVALID", "The command is unknown",
            "Please execute 'ohos-imf --help' to see detailed usage instructions" });
    }
    if (!argList_.empty() && argList_[0] == "--help") {
        return GenerateCmdHelp(cmd);
    }
    return cmd->Execute(argList_);
}
} // namespace MiscServices
} // namespace OHOS