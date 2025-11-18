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

#include "sys_cfg_parser.h"
#include "file_operator.h"

namespace OHOS {
namespace MiscServices {
// LCOV_EXCL_START
constexpr const char *SYS_CFG_FILE_PATH = "etc/inputmethod/inputmethod_framework_config.json";
bool SysCfgParser::ParseSystemConfig(SystemConfig &systemConfig)
{
    auto content = GetSysCfgContent(GET_NAME(systemConfig));
    if (content.empty()) {
        IMSA_HILOGE("content is empty");
        return false;
    }
    ImeSystemConfig imeSysCfg;
    auto ret = imeSysCfg.Unmarshall(content);
    systemConfig = imeSysCfg.systemConfig;
    return ret;
}

bool SysCfgParser::ParseInputType(std::vector<InputTypeInfo> &inputType)
{
    auto content = GetSysCfgContent(GET_NAME(supportedInputTypeList));
    if (content.empty()) {
        IMSA_HILOGD("content is empty");
        return false;
    }
    InputTypeCfg inputTypeCfg;
    auto ret = inputTypeCfg.Unmarshall(content);
    inputType = inputTypeCfg.inputType;
    return ret;
}

bool SysCfgParser::ParseDynamicStartImeCfg(std::vector<DynamicStartImeCfgItem> &dynamicStartImeCfgList)
{
    auto content = GetSysCfgContent(GET_NAME(dynamicStartImeCfgList));
    if (content.empty()) {
        IMSA_HILOGW("dynamic start ime cfg content is empty");
        return false;
    }

    DynamicStartImeCfg dynamicStartImeCfg;
    auto ret = dynamicStartImeCfg.Unmarshall(content);
    if (ret) {
        dynamicStartImeCfgList = dynamicStartImeCfg.dynamicStartImeCfgList;
    }
    return ret;
}

bool SysCfgParser::ParsePanelAdjust(std::vector<SysPanelAdjust> &sysPanelAdjust)
{
    auto content = GetSysCfgContent(GET_NAME(sysPanelAdjust));
    if (content.empty()) {
        IMSA_HILOGE("content is empty");
        return false;
    }
    SysPanelAdjustCfg sysPanelAdjustCfg;
    auto ret = sysPanelAdjustCfg.Unmarshall(content);
    sysPanelAdjust = sysPanelAdjustCfg.panelAdjust;
    return ret;
}

bool SysCfgParser::ParseDefaultFullIme(std::vector<DefaultFullImeInfo> &defaultFullImeList)
{
    auto content = GetSysCfgContent(GET_NAME(defaultFullImeList));
    if (content.empty()) {
        IMSA_HILOGD("content is empty");
        return false;
    }
    DefaultFullImeCfg defaultFullImeCfg;
    auto ret = defaultFullImeCfg.Unmarshall(content);
    defaultFullImeList = defaultFullImeCfg.defaultFullImeList;
    return ret;
}

bool SysCfgParser::ParseIgnoreSysPanelAdjust(IgnoreSysPanelAdjust &ignoreSysPanelAdjust)
{
    auto content = GetSysCfgContent(GET_NAME(ignoreSysPanelAdjust));
    if (content.empty()) {
        IMSA_HILOGD("content is empty");
        return false;
    }
    IgnoreSysPanelAdjustCfg ignoreSysPanelAdjustCfg;
    auto ret = ignoreSysPanelAdjustCfg.Unmarshall(content);
    ignoreSysPanelAdjust = ignoreSysPanelAdjustCfg.ignoreSysPanelAdjust;
    return ret;
}

std::string SysCfgParser::GetSysCfgContent(const std::string &key)
{
    std::string content;
    auto ret = FileOperator::Read(SYS_CFG_FILE_PATH, key, content);
    if (!ret) {
        IMSA_HILOGD("get content by %{public}s failed.", key.c_str());
    }
    return content;
}

bool SysCfgParser::IsContainField(const std::string& fieldName)
{
    SystemConfig systemConfig;
    auto content = GetSysCfgContent(GET_NAME(systemConfig));
    if (content.empty()) {
        IMSA_HILOGE("content is empty");
        return false;
    }
    cJSON *root = cJSON_Parse(content.c_str());
    if (root == NULL) {
        IMSA_HILOGE("%{public}s: parse failed!", content.c_str());
        return false;
    }
    cJSON *nestedObject = cJSON_GetObjectItem(root, GET_NAME(systemConfig));
    if (nestedObject == NULL || !cJSON_IsObject(nestedObject)) {
        IMSA_HILOGE("get object item failed!");
        return false;
    }
    bool isContained = cJSON_HasObjectItem(nestedObject, fieldName.c_str());
    IMSA_HILOGD("fieldName: %{public}s, isContained: %{public}d", fieldName.c_str(), isContained);
    cJSON_Delete(root);
    return isContained;
}
// LCOV_EXCL_STOP
} // namespace MiscServices
} // namespace OHOS