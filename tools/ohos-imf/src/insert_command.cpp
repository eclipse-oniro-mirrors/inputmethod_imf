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
#include "insert_command.h"

#include "cli_utils.h"
#include "input_method_controller.h"
#include "param_parser.h"
namespace OHOS {
namespace MiscServices {
std::string InsertCommand::GetName() const
{
    return "insert";
}

std::string InsertCommand::GetDescription() const
{
    return "Insert text into the focused edit box bound to the input method application";
}

std::string InsertCommand::GetUsage() const
{
    return "ohos-imf insert [options]";
}

std::vector<std::pair<std::string, std::string>> InsertCommand::GetParams() const
{
    return { { "--text <text>", "Text to be inserted(required, type: string, max size 512 bytes)" } };
}

std::vector<std::pair<std::string, std::string>> InsertCommand::GetExamples() const
{
    return { { "# Insert text into the edit box", R"(ohos-imf insert --text "hello world")" } };
}

std::string InsertCommand::Execute(const std::vector<std::string> &argList)
{
    std::string text;
    auto errInfo = GetInsertedText(argList, text);
    if (!errInfo.empty()) {
        return errInfo;
    }
    auto imcInstance = InputMethodController::GetInstance();
    if (imcInstance == nullptr) {
        return CliUtils::GenerateError({ "ERR_INTERNAL_ERROR", "Failed to get InputMethodController instance",
            "Please check the tool process memory usage" });
    }
    auto ret = imcInstance->ExecTextInteraction(text);
    if (ret != ErrorCode::NO_ERROR) {
        if (ret == ErrorCode::ERROR_STATUS_PERMISSION_DENIED) {
            return CliUtils::GenerateError(
                { "ERR_PERMISSION_DENIED", "Permission denied: missing ohos.permission.CONTROL_DEVICE permission",
                    "Please add ohos.permission.CONTROL_DEVICE in the requirePermissions field of module.json5" });
        } else {
            return CliUtils::GenerateError(
                { "ERR_EDIT_BOX_NOT_BOUND_WITH_IME_APP", "No focused edit box or not bound to the IME app",
                    "Please click the edit box in current focused window to trigger the binding operation first and "
                    "try again" });
        }
    }
    return CliUtils::GenerateSuccess(std::make_shared<CommonSuccessInfo>());
}

std::string InsertCommand::GetInsertedText(const std::vector<std::string> &argList, std::string &text)
{
    if (argList.size() != ARG_NUM) {
        return CliUtils::GenerateError({ "ERR_ARG_COUNT_MISMATCH", "Invalid argument count",
            "Only '--text <content>' is supported. Please execute 'ohos-imf insert --help' for usage" });
    }
    text = ParamParse::GetParam(argList, "--text");
    if (text.empty()) {
        return CliUtils::GenerateError({ "ERR_ARG_MISSING", "Missing required option '--text' or its value",
            "Please execute 'ohos-imf insert --help' for usage" });
    }
    auto textSize = text.size();
    if (textSize > MAX_INSERT_TEXT_SIZE) {
        std::string errMsg = "Text size is " + std::to_string(textSize) + ", exceeds the limit, it must not exceed "
                             + std::to_string(MAX_INSERT_TEXT_SIZE) + " bytes";
        return CliUtils::GenerateError({ "ERR_ARG_OUT_OF_RANGE", errMsg, "Please provide valid text" });
    }
    return "";
}
} // namespace MiscServices
} // namespace OHOS