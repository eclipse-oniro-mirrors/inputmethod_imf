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

#include <string>
#include <variant>

#include "extra_config_ani.h"
#include "global.h"
#include "input_attribute.h"

namespace OHOS {
namespace MiscServices {
std::string AniExtraConfig::ConvertString(ani_env* env, ani_object in)
{
    if (env == nullptr) {
        return "";
    }
    ani_boolean res;
    ani_class stringCls {};
    ani_status ret = env->FindClass("std.core.String", &stringCls);
    if (ret != ANI_OK || stringCls == nullptr) {
        IMSA_HILOGE("ConvertString, FindClass failed!");
        return "";
    }
    ret = env->Object_InstanceOf(in, stringCls, &res);
    if (ret != ANI_OK || !res) {
        IMSA_HILOGE("ConvertString, obj is not string!");
        return "";
    }
    ani_size sz {};
    ani_string str = static_cast<ani_string>(in);
    env->String_GetUTF8Size(str, &sz);
    std::string result(sz + 1, 0);
    env->String_GetUTF8(str, result.data(), result.size(), &sz);
    result.resize(sz);
    return result;
}

ani_field AniExtraConfig::AniFindClassField(ani_env* env, ani_class cls, const char* name)
{
    ani_field fld;
    if (cls == nullptr || env == nullptr) {
        return nullptr;
    }
    if (ANI_OK != env->Class_FindField(cls, name, &fld)) {
        return nullptr;
    }
    return fld;
}

ani_class AniExtraConfig::AniGetClass(ani_env* env, const char* className)
{
    if (env == nullptr) {
        return nullptr;
    }
    ani_class cls {};
    if (ANI_OK != env->FindClass(className, &cls)) {
        return nullptr;
    }
    return cls;
}

ani_method AniExtraConfig::AniGetClassMethod(ani_env* env, const char* className,
    const char* methodName, const char* signature)
{
    if (env == nullptr) {
        return nullptr;
    }
    ani_class retClass = AniGetClass(env, className);
    if (retClass == nullptr) {
        return nullptr;
    }
    ani_method retMethod {};
    if (ANI_OK != env->Class_FindMethod(retClass, methodName, signature, &retMethod)) {
        return nullptr;
    }
    return retMethod;
}

bool AniExtraConfig::ParseValue(ani_env* env, ani_object aniValue, CustomValueType &valueObj, uint32_t& valueSize)
{
    if (env == nullptr || aniValue == nullptr) {
        IMSA_HILOGE("ParseValue, param is invalid!");
        return false;
    }
    ani_boolean res;
    ani_class optionClass {};
    env->FindClass("std.core.Boolean", &optionClass);
    if (ANI_OK != env->Object_InstanceOf(aniValue, optionClass, &res)) {
        IMSA_HILOGE("to boolean failed");
        return false;
    }
    if (res) {
        ani_boolean value;
        if (ANI_OK != env->Object_CallMethodByName_Boolean(aniValue, "toBoolean", ":z", &value)) {
            IMSA_HILOGE("ParseValue, Object_CallMethodByName_Boolean failed!");
            return false;
        }
        valueObj = static_cast<bool>(value);
        valueSize = sizeof(bool);
        return true;
    }
    env->FindClass("std.core.Int", &optionClass);
    if (ANI_OK != env->Object_InstanceOf(aniValue, optionClass, &res)) {
        IMSA_HILOGE("to int failed");
        return false;
    }
    if (res) {
        ani_int value = 0;
        if (ANI_OK != env->Object_CallMethodByName_Int(aniValue, "toInt", ":i", &value)) {
            IMSA_HILOGE("ParseValue, Object_CallMethodByName_Int failed!");
            return false;
        }
        valueObj = static_cast<int32_t>(value);
        valueSize = sizeof(int32_t);
        return true;
    }

    env->FindClass("std.core.String", &optionClass);
    if (ANI_OK != env->Object_InstanceOf(aniValue, optionClass, &res)) {
        IMSA_HILOGE("to str failed");
        return false;
    }
    if (res) {
        auto tmpString = ConvertString(env, aniValue);
        valueObj = tmpString;
        valueSize = tmpString.size();
        return true;
    }
    return true;
}

bool AniExtraConfig::ParseRecordItem(ani_env* env, ani_object entryIterator,
    ani_method iterNextMethod, ani_class iterResultClass, CustomSettings& out)
{
    if (env == nullptr) {
        IMSA_HILOGE("env is null");
        return false;
    }
    ani_boolean iter_done = false;
    uint32_t totalSize = 0;
    while (!iter_done) {
        ani_object iteratorNextResult = {};
        env->Object_CallMethod_Ref(entryIterator, iterNextMethod, reinterpret_cast<ani_ref *>(&iteratorNextResult));
        ani_field fieldTmp = AniFindClassField(env, iterResultClass, "done");
        env->Object_GetField_Boolean(iteratorNextResult, fieldTmp, &iter_done);
        if (iter_done) {
            break;
        }
        ani_tuple_value temp_ani_item = {};
        fieldTmp = AniFindClassField(env, iterResultClass, "value");
        env->Object_GetField_Ref(iteratorNextResult, fieldTmp, reinterpret_cast<ani_ref *>(&temp_ani_item));
        ani_ref temp_ani_key = {};
        env->TupleValue_GetItem_Ref(temp_ani_item, 0, &temp_ani_key);
        ani_object keyObj = reinterpret_cast<ani_object>(temp_ani_key);
        std::string stdKey = ConvertString(env, keyObj);
        if (stdKey.size() == 0) {
            break;
        }
        uint32_t keySize = stdKey.size();
        ani_ref temp_ani_val = {};
        env->TupleValue_GetItem_Ref(temp_ani_item, 1, &temp_ani_val);
        CustomValueType parseResult {};
        uint32_t valueSize = 0;
        ParseValue(env, static_cast<ani_object>(temp_ani_val), parseResult, valueSize);
        if ((keySize > UINT32_MAX - valueSize) || (totalSize > UINT32_MAX - keySize - valueSize)) {
            out.clear();
            IMSA_HILOGE("integer overflow detected in size calculation");
            return false;
        }
        totalSize = totalSize + keySize + valueSize;
        out[stdKey] = parseResult;
    }
    ExtraConfigInner configInner;
    configInner.customSettings = out;
    if (totalSize > DEFAULT_MAX_EXTRA_CONFIG_SIZE || !configInner.IsMarshallingPass()) {
        out.clear();
        IMSA_HILOGE("input data exceed limit. totalSize: %{public}d", totalSize);
        return false;
    }
    return true;
}

bool AniExtraConfig::ParseRecord(ani_env* env, ani_object recordObj, CustomSettings& out, uint32_t maxLen)
{
    if (env == nullptr || recordObj == nullptr) {
        IMSA_HILOGE("param is invalid");
        return false;
    }
    ani_method entryMethod = AniGetClassMethod(env, "std.core.Record", "entries", ":C{std.core.IterableIterator}");
    ani_method iterNextMethod = AniGetClassMethod(env, "std.core.Iterator", "next", ":C{std.core.IteratorResult}");
    ani_class iterResultClass = AniGetClass(env, "std.core.IteratorResult");
    if (entryMethod == nullptr || iterNextMethod == nullptr || iterResultClass == nullptr) {
        IMSA_HILOGE("ParseRecord, get iter failed!");
        return false;
    }
    ani_object entryIterator = {};
    if (ANI_OK != env->Object_CallMethod_Ref(recordObj, entryMethod, reinterpret_cast<ani_ref *>(&entryIterator))) {
        IMSA_HILOGE("ParseRecord, Object_CallMethod_Ref failed!");
        return false;
    }
    if (!ParseRecordItem(env, entryIterator, iterNextMethod, iterResultClass, out)) {
        IMSA_HILOGE("ParseRecord, ParseRecordItem!");
        return false;
    }
    return true;
}

bool AniExtraConfig::GetRecordOrUndefined(ani_env* env, ani_object in,
    const char* name, CustomSettings& out, uint32_t maxLen)
{
    if (maxLen > DEFAULT_MAX_EXTRA_CONFIG_SIZE) {
        maxLen = DEFAULT_MAX_EXTRA_CONFIG_SIZE;
    }
    if (env == nullptr || in == nullptr) {
        return false;
    }

    ani_ref ref = nullptr;
    ani_boolean isUndefined = false;
    ani_boolean isNull = false;
    ani_status ret = env->Object_GetPropertyByName_Ref(in, name, &ref);
    if (ret != ANI_OK) {
        IMSA_HILOGE("Object_GetPropertyByName_Ref failed, ret: %{public}d", ret);
        return false;
    }
    ret = env->Reference_IsUndefined(ref, &isUndefined);
    if (ret != ANI_OK || isUndefined) {
        IMSA_HILOGE("customSettings is undefined, ret: %{public}d", ret);
        return false;
    }
    ret = env->Reference_IsNull(ref, &isNull);
    if (ret != ANI_OK || isNull) {
        IMSA_HILOGE("customSettings is null, ret: %{public}d", ret);
        return false;
    }
    ani_class cls;
    ret = env->FindClass("std.core.Record", &cls);
    if (ret != ANI_OK || cls == nullptr) {
        IMSA_HILOGE("customSettings FindClass failed, ret: %{public}d", ret);
        return false;
    }
    ani_boolean result = false;
    auto recordObj = static_cast<ani_object>(ref);
    ret = env->Object_InstanceOf(recordObj, cls, &result);
    if (ret != ANI_OK || !result) {
        IMSA_HILOGE("customSettings is not record, ret: %{public}d", ret);
        return false;
    }
    if (!ParseRecord(env, recordObj, out, maxLen)) {
        IMSA_HILOGE("ParseRecord failed");
        return false;
    }
    return true;
}

bool AniExtraConfig::GetExtraConfig([[maybe_unused]]ani_env* env, ani_object in, ExtraConfig &out, uint32_t maxLen)
{
    if (maxLen > DEFAULT_MAX_EXTRA_CONFIG_SIZE) {
        maxLen = DEFAULT_MAX_EXTRA_CONFIG_SIZE;
    }

    if (env == nullptr) {
        IMSA_HILOGE("env is null");
        return false;
    }

    ani_boolean isUndefined = false;
    ani_status ret = env->Reference_IsUndefined(in, &isUndefined);
    if (ret != ANI_OK || isUndefined) {
        IMSA_HILOGE("ExtraConfig is undefined, ret: %{public}d", ret);
        return false;
    }
    ani_boolean isNull = false;
    ret = env->Reference_IsNull(in, &isNull);
    if (ret != ANI_OK || isNull) {
        IMSA_HILOGE("ExtraConfig is null, ret: %{public}d", ret);
        return false;
    }
    if (!GetRecordOrUndefined(env, in, "customSettings", out.customSettings, maxLen)) {
        IMSA_HILOGE("GetRecordOrUndefined failed");
        return false;
    }
    IMSA_HILOGI("parse extraConfig success!");
    return true;
}
} // namespace MiscServices
} // namespace OHOS