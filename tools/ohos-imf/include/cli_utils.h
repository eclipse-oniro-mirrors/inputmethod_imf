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

#ifndef IMF_CLI_UTILS_H
#define IMF_CLI_UTILS_H

#include <memory>
#include <string>

#include "serializable.h"
namespace OHOS {
namespace MiscServices {
struct SuccessInfo : public Serializable {
    virtual ~SuccessInfo() = default;
    bool Marshal(cJSON *node) const override = 0;
};

struct CommonSuccessData : public Serializable {
    bool Marshal(cJSON *node) const override
    {
        return true;
    }
};

struct CommonSuccessInfo : public SuccessInfo {
    CommonSuccessData data;
    bool Marshal(cJSON *node) const override
    {
        auto ret = SetValue(node, GET_NAME(type), std::string(GET_NAME(result)));
        ret = SetValue(node, GET_NAME(status), std::string(GET_NAME(success))) && ret;
        return SetValue(node, GET_NAME(data), data) && ret;
    }
};

struct ErrorInfo : public Serializable {
    std::string errCode;
    std::string errMsg;
    std::string suggestion;
    ErrorInfo(std::string errCode, std::string errMsg, std::string suggestion)
        : errCode(std::move(errCode)), errMsg(std::move(errMsg)), suggestion(std::move(suggestion))
    {
    }
    bool Marshal(cJSON *node) const override
    {
        auto ret = SetValue(node, GET_NAME(type), std::string(GET_NAME(result)));
        ret = SetValue(node, GET_NAME(status), std::string(GET_NAME(failed))) && ret;
        ret = SetValue(node, GET_NAME(errCode), errCode) && ret;
        ret = SetValue(node, GET_NAME(errMsg), errMsg) && ret;
        return SetValue(node, GET_NAME(suggestion), suggestion) && ret;
    }
};
class CliUtils {
public:
    static std::string GenerateError(const ErrorInfo &error);
    static std::string GenerateSuccess(std::shared_ptr<SuccessInfo> info);
};
} // namespace MiscServices
} // namespace OHOS
#endif // IMF_CLI_UTILS_H