/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "extra_config_napi.h"
#include "js_utils.h"

namespace OHOS {
namespace MiscServices {
napi_status JsExtraConfig::GetValue(napi_env env, napi_value in, ExtraConfig &out, uint32_t maxLen)
{
    if (maxLen > MAX_EXTRA_CONFIG_SIZE) {
        return napi_generic_failure;
    }
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, in, &type);
    CHECK_RETURN(type != napi_undefined, "param is undefined.", napi_generic_failure);

    napi_value propType = nullptr;
    status = napi_get_named_property(env, in, "customSettings", &propType);
    CHECK_RETURN((status == napi_ok), "no property customSettings ", status);
    return GetValue(env, propType, out.customSettings, maxLen);
}

napi_status JsExtraConfig::GetValue(napi_env env, napi_value in, CustomSettings &out, uint32_t maxLen)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, in, &type);
    CHECK_RETURN(type != napi_undefined, "param is undefined.", napi_generic_failure);

    napi_value keys = nullptr;
    napi_get_property_names(env, in, &keys);
    uint32_t arrLen = 0;
    status = napi_get_array_length(env, keys, &arrLen);
    if (status != napi_ok) {
        IMSA_HILOGE("napi_get_array_length error");
        return status;
    }
    IMSA_HILOGD("length : %{public}u", arrLen);
    uint32_t totalSize = 0;
    for (size_t iter = 0; iter < arrLen; ++iter) {
        napi_value key = nullptr;
        status = napi_get_element(env, keys, iter, &key);
        CHECK_RETURN(status == napi_ok, "napi_get_element error", status);

        napi_value value = nullptr;
        status = napi_get_property(env, in, key, &value);
        CHECK_RETURN(status == napi_ok, "napi_get_property error", status);

        std::string keyStr;
        status = JsUtils::GetValue(env, key, keyStr);
        CHECK_RETURN(status == napi_ok, "GetValue keyStr error", status);
        uint32_t keySize = keyStr.size();

        CustomValueType customSettingData;
        uint32_t valueSize = 0;
        status = GetValue(env, value, customSettingData, valueSize);
        CHECK_RETURN(status == napi_ok, "GetValue customSettingData error", status);
        totalSize = totalSize + keySize + valueSize;
        out.emplace(keyStr, customSettingData);
    }
    if (totalSize > maxLen) {
        out.clear();
        IMSA_HILOGE("totalSize : %{public}d", totalSize);
        return napi_generic_failure;
    }
    return status;
}

napi_status JsExtraConfig::GetValue(napi_env env, napi_value in, CustomValueType &out, uint32_t &valueSize)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, in, &valueType);
    CHECK_RETURN(status == napi_ok, "napi_typeof error", napi_generic_failure);
    if (valueType == napi_string) {
        std::string customSettingStr;
        status = JsUtils::GetValue(env, in, customSettingStr);
        CHECK_RETURN(status == napi_ok, "GetValue napi_string error", napi_generic_failure);
        valueSize = customSettingStr.size();
        out.emplace<std::string>(customSettingStr);
    } else if (valueType == napi_boolean) {
        bool customSettingBool = false;
        status = JsUtils::GetValue(env, in, customSettingBool);
        CHECK_RETURN(status == napi_ok, "GetValue napi_boolean error", napi_generic_failure);
        valueSize = sizeof(bool);
        out.emplace<bool>(customSettingBool);
    } else if (valueType == napi_number) {
        int32_t customSettingInt = 0;
        status = JsUtils::GetValue(env, in, customSettingInt);
        CHECK_RETURN(status == napi_ok, "GetValue napi_number error", napi_generic_failure);
        valueSize = sizeof(int32_t);
        out.emplace<int32_t>(customSettingInt);
    } else {
        CHECK_RETURN(false, "value type must be string | boolean | number", napi_generic_failure);
    }
    return status;
}

napi_status JsExtraConfig::GetJsExtraConfig(napi_env env, const ExtraConfig &in, napi_value &out)
{
    napi_value jsObject = nullptr;
    CHECK_RETURN(napi_create_object(env, &jsObject) == napi_ok, "create_object error", napi_generic_failure);
    for (const auto &iter : in.customSettings) {
        size_t idx = iter.second.index();
        napi_value value = nullptr;
        if (idx == static_cast<size_t>(CustomValueTypeValue::CUSTOM_VALUE_TYPE_STRING)) {
            auto stringValue = std::get_if<std::string>(&iter.second);
            CHECK_RETURN(stringValue != nullptr, "stringValue is nullptr", napi_generic_failure);
            CHECK_RETURN(napi_create_string_utf8(env, (*stringValue).c_str(), (*stringValue).size(), &value)
                == napi_ok, "create_string_utf8 error", napi_generic_failure);
        } else if (idx == static_cast<size_t>(CustomValueTypeValue::CUSTOM_VALUE_TYPE_BOOL)) {
            auto boolValue = std::get_if<bool>(&iter.second);
            CHECK_RETURN(boolValue != nullptr, "boolValue is nullptr", napi_generic_failure);
            CHECK_RETURN(napi_get_boolean(env, *boolValue, &value) == napi_ok, "get_boolean error",
                napi_generic_failure);
        } else if (idx == static_cast<size_t>(CustomValueTypeValue::CUSTOM_VALUE_TYPE_NUMBER)) {
            auto numberValue = std::get_if<int32_t>(&iter.second);
            CHECK_RETURN(numberValue != nullptr, "numberValue is nullptr", napi_generic_failure);
            CHECK_RETURN(napi_create_int32(env, *numberValue, &value) == napi_ok, "create_int32 error",
                napi_generic_failure);
        }
        CHECK_RETURN(napi_set_named_property(env, jsObject, iter.first.c_str(), value) == napi_ok,
            "set_named_property error", napi_generic_failure);
    }
    std::string name = "customSettings";
    CHECK_RETURN(napi_set_named_property(env, out, name.c_str(), jsObject) == napi_ok, "set_named_property error",
        napi_generic_failure);
    return napi_ok;
}

napi_status JsExtraConfig::CreateExtraConfig(napi_env env, const ExtraConfig &in, napi_value &out)
{
    return GetJsExtraConfig(env, in, out);
}

napi_status JsExtraConfig::GetExtraConfig(napi_env env, napi_value in, ExtraConfig &out, uint32_t maxLen)
{
    auto status = GetValue(env, in, out, maxLen);
    CHECK_RETURN(status == napi_ok, "ExtraConfig convert failed", status);
    return napi_ok;
}
} // namespace MiscServices
} // namespace OHOS