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

#ifndef IMF_HISYSEVENT_UTIL_H
#define IMF_HISYSEVENT_UTIL_H
#include <unordered_set>
#include <vector>
#include <map>
#include "imf_hisysevent_info.h"
namespace OHOS {
namespace MiscServices {
enum IMFErrorCode : int32_t {
    EXCEPTION_PERMISSION = 201,
    EXCEPTION_SYSTEM_PERMISSION = 202,
    EXCEPTION_PARAMCHECK = 401,
    EXCEPTION_UNSUPPORTED = 801,
    EXCEPTION_PACKAGEMANAGER = 12800001,
    EXCEPTION_IMENGINE = 12800002,
    EXCEPTION_IMCLIENT = 12800003,
    EXCEPTION_IME = 12800004,
    EXCEPTION_CONFPERSIST = 12800005,
    EXCEPTION_CONTROLLER = 12800006,
    EXCEPTION_SETTINGS = 12800007,
    EXCEPTION_IMMS = 12800008,
    EXCEPTION_DETACHED = 12800009,
    EXCEPTION_DEFAULTIME = 12800010,
    EXCEPTION_TEXT_PREVIEW_NOT_SUPPORTED = 12800011,
    EXCEPTION_PANEL_NOT_FOUND = 12800012,
    EXCEPTION_WINDOW_MANAGER = 12800013,
    EXCEPTION_BASIC_MODE = 12800014,
    EXCEPTION_REQUEST_NOT_ACCEPT = 12800015,
    EXCEPTION_EDITABLE = 12800016,
    EXCEPTION_INVALID_PANEL_TYPE_FLAG = 12800017,
    EXCEPTION_IME_NOT_FOUND = 12800018,
    EXCEPTION_OPERATE_DEFAULTIME = 12800019,
    EXCEPTION_INVALID_IMMERSIVE_EFFECT = 12800020,
    EXCEPTION_PRECONDITION_REQUIRED = 12800021,
    EXCEPTION_INVALID_DISPLAYID = 12800022,
    EXCEPTION_USER_NOT_EXIST = 12800023,
    EXCEPTION_USER_NOT_IN_FOREGROUND = 12800024,
    EXCEPTION_CROSS_USER_OPERATION_DENIED = 12800025,
    EXCEPTION_SYSTEM_PANEL_ERROR = 12800026,
};
class ImfHiSysEventUtil {
public:
    static void ReportClientAttachFault(const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info);
    static void ReportClientShowFault(const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info);
    static void ReportImeStartInputFault(const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info);
    static void ReportBaseTextOperationFault(
        const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info);
    static void ReportStatisticsEvent(const std::string &eventName, const std::vector<std::string> &imeNames,
        const std::vector<std::string> &appNames, const std::vector<std::string> &statistics);
    static void ReportStatisticsEvent(const std::string &eventName, const std::string &imeName,
        const std::vector<std::string> &appNames, const std::vector<std::string> &statistics);
    static std::string GetAppName(uint64_t fullTokenId);
    static std::string AddIfAbsent(const std::string &bundleName, std::vector<std::string> &bundleNames);
    static int32_t ConvertErrorCode(int32_t code);
    static int32_t HidumperConvertErrorCode(int32_t code);
    static const std::map<int32_t, int32_t> ERROR_CODE_MAP;
    static const std::map<int32_t, int32_t> HIDUMPER_ERROR_CODE_MAP;
};
} // namespace MiscServices
} // namespace OHOS

#endif // IMF_HISYSEVENT_UTIL_H