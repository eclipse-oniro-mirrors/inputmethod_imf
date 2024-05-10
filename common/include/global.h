/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef SERVICES_INCLUDE_GLOBAL_H
#define SERVICES_INCLUDE_GLOBAL_H

#include <errno.h>
#include <sys/time.h>
#include <time.h>

#include <functional>

#include "hilog/log.h"

namespace OHOS {
namespace MiscServices {

#define LOG_INFO(fmt, args...) \
    LogTimeStamp();            \
    printf("I %s:%d  %s - " fmt, basename(__FILE__), __LINE__, __FUNCTION__, ##args)

#define LOG_ERROR(fmt, args...) \
    LogTimeStamp();             \
    printf("E %s:%d  %s - " fmt, basename(__FILE__), __LINE__, __FUNCTION__, ##args)

#define LOG_WARNING(fmt, args...) \
    LogTimeStamp();               \
    printf("W %s:%d  %s - " fmt, basename(__FILE__), __LINE__, __FUNCTION__, ##args)

#if DEBUG
#define LOG_DEBUG(fmt, args...) \
    LogTimeStamp();             \
    printf("D %s:%d  %s - " fmt, basename(__FILE__), __LINE__, __FUNCTION__, ##args)
#else
#define LOG_DEBUG(fmt, args...)
#endif

void LogTimeStamp();

// Error Code
namespace ErrorCode {
// Error Code definition in the input method management system
enum {
    ERROR_STATUS_PERMISSION_DENIED = -EPERM,                          // permission denied
    ERROR_STATUS_UNKNOWN_TRANSACTION = -EBADMSG,                      // unknown transaction

    // binder exception error code from Status.h
    ERROR_EX_ILLEGAL_ARGUMENT = -3,      // illegal argument exception
    ERROR_EX_NULL_POINTER = -4,          // null pointer exception
    ERROR_EX_ILLEGAL_STATE = -5,         // illegal state exception
    ERROR_EX_PARCELABLE  = -6,           // parcelable exception
    ERROR_EX_UNSUPPORTED_OPERATION = -7, // unsupported operation exception
    ERROR_EX_SERVICE_SPECIFIC = -8,      // service specific exception
    // no error
    NO_ERROR = 0, // no error

    // system service error
    ERROR_NULL_POINTER = 1,          // null pointer
    ERROR_BAD_PARAMETERS = 2,        // bad parameters
    ERROR_CLIENT_NOT_FOUND = 3,
    ERROR_CLIENT_NULL_POINTER = 4,
    ERROR_SUBSCRIBE_KEYBOARD_EVENT = 5,
    ERROR_IME_NOT_STARTED = 6,
    ERROR_SERVICE_START_FAILED = 7,

    ERROR_CONTROLLER_INVOKING_FAILED = 8,
    ERROR_PERSIST_CONFIG = 9,
    ERROR_KBD_HIDE_FAILED = 10,
    ERROR_SWITCH_IME = 11,
    ERROR_PACKAGE_MANAGER = 12,
    ERROR_REMOTE_CLIENT_DIED = 13,
    ERROR_IME_START_FAILED = 14,          // failed to start IME service
    ERROR_KBD_SHOW_FAILED = 15,           // failed to show keyboard
    ERROR_CLIENT_NOT_BOUND = 16,
    ERROR_CLIENT_NOT_EDITABLE = 17,
    ERROR_CLIENT_NOT_FOCUSED = 18,
    ERROR_CLIENT_ADD_FAILED = 19,
    ERROR_OPERATE_PANEL = 20,
    ERROR_NOT_CURRENT_IME = 21,
    ERROR_NOT_IME = 22,
    ERROR_ADD_DEATH_RECIPIENT_FAILED = 23,
    ERROR_STATUS_SYSTEM_PERMISSION = 24, // not system application
    ERROR_IME = 25,
	ERROR_PARAMETER_CHECK_FAILED = 26,
    ERROR_IME_START_INPUT_FAILED = 27,
    ERROR_KEYWORD_NOT_FOUND = 28,
    ERROR_ENABLE_IME = 29,
    ERROR_PARSE_CONFIG_FILE = 30,
    ERROR_NOT_DEFAULT_IME = 31,
    ERROR_ENABLE_SECURITY_MODE = 32,
    ERROR_DISPATCH_KEY_EVENT = 33,
    ERROR_INVALID_PRIVATE_COMMAND_SIZE = 34,
    ERROR_TEXT_LISTENER_ERROR = 35,
    ERROR_PANEL_NOT_FOUND = 36,
    ERROR_WINDOW_MANAGER = 37,
    ERROR_GET_TEXT_CONFIG = 38,
    ERROR_TEXT_PREVIEW_NOT_SUPPORTED = 39,
    ERROR_INVALID_RANGE = 40,
    ERROR_CMD_LISTENER_ERROR = 41,
    ERROR_SYSTEM_CMD_CHANNEL_ERROR = 42,
    ERROR_INVALID_PRIVATE_COMMAND = 43,
};
}; // namespace ErrorCode

static constexpr HiviewDFX::HiLogLabel g_SMALL_SERVICES_LABEL = { LOG_CORE, 0xD001C10, "ImsaKit" };

#define IMSA_HILOGD(fmt, ...)                                                                                    \
    (void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, OHOS::MiscServices::g_SMALL_SERVICES_LABEL.domain,                     \
        OHOS::MiscServices::g_SMALL_SERVICES_LABEL.tag, "line: %{public}d, function: %{public}s," fmt, __LINE__, \
        __FUNCTION__, ##__VA_ARGS__)
#define IMSA_HILOGE(fmt, ...)                                                                                    \
    (void)HILOG_IMPL(LOG_CORE, LOG_ERROR, OHOS::MiscServices::g_SMALL_SERVICES_LABEL.domain,                     \
        OHOS::MiscServices::g_SMALL_SERVICES_LABEL.tag, "line: %{public}d, function: %{public}s," fmt, __LINE__, \
        __FUNCTION__, ##__VA_ARGS__)
#define IMSA_HILOGF(fmt, ...)                                                                                    \
    (void)HILOG_IMPL(LOG_CORE, LOG_FATAL, OHOS::MiscServices::g_SMALL_SERVICES_LABEL.domain,                     \
        OHOS::MiscServices::g_SMALL_SERVICES_LABEL.tag, "line: %{public}d, function: %{public}s," fmt, __LINE__, \
        __FUNCTION__, ##__VA_ARGS__)
#define IMSA_HILOGI(fmt, ...)                                                                                    \
    (void)HILOG_IMPL(LOG_CORE, LOG_INFO, OHOS::MiscServices::g_SMALL_SERVICES_LABEL.domain,                      \
        OHOS::MiscServices::g_SMALL_SERVICES_LABEL.tag, "line: %{public}d, function: %{public}s," fmt, __LINE__, \
        __FUNCTION__, ##__VA_ARGS__)
#define IMSA_HILOGW(fmt, ...)                                                                                    \
    (void)HILOG_IMPL(LOG_CORE, LOG_WARN, OHOS::MiscServices::g_SMALL_SERVICES_LABEL.domain,                      \
        OHOS::MiscServices::g_SMALL_SERVICES_LABEL.tag, "line: %{public}d, function: %{public}s," fmt, __LINE__, \
        __FUNCTION__, ##__VA_ARGS__)
using Function = std::function<bool()>;
bool BlockRetry(uint32_t interval, uint32_t maxRetryTimes, Function func);
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_GLOBAL_H
