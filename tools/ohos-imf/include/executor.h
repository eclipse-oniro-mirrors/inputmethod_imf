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

#ifndef IMF_CLI_EXECUTOR_H
#define IMF_CLI_EXECUTOR_H
#include <memory>
#include <string>
#include <vector>

#include "command.h"

namespace OHOS {
namespace MiscServices {
class Executor {
public:
    Executor(int argc, char *argv[]);
    std::string Execute();

private:
    static constexpr int32_t MIN_ARGUMENT_NUMBER = 2;
    std::string GenerateFullHelp();
    std::string GenerateCmdHelp(std::shared_ptr<Command> cmd);
    std::string ExtractVersion();
    std::string cmd_;
    std::vector<std::string> argList_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // IMF_CLI_EXECUTOR_H