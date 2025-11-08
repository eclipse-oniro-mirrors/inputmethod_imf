/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef INPUTMETHOD_IMF_IMC_INNER_LISTENER_H
#define INPUTMETHOD_IMF_IMC_INNER_LISTENER_H

namespace OHOS {
namespace MiscServices {
enum class AttachFailureReason : int32_t {
    CALLER_NOT_FOCUSED,
    IME_ABNORMAL,
    SERVICE_ABNORMAL,
};
inline const std::map<int32_t, AttachFailureReason> ATTACH_FAILURE_REASON_MAP = {
    { ErrorCode::ERROR_CLIENT_NOT_FOCUSED, AttachFailureReason::CALLER_NOT_FOCUSED },
    { ErrorCode::ERROR_IME_NOT_STARTED, AttachFailureReason::IME_ABNORMAL },
    { ErrorCode::ERROR_IMSA_REBOOT_OLD_IME_NOT_STOP, AttachFailureReason::IME_ABNORMAL },
    { ErrorCode::ERROR_IMSA_IME_CONNECT_FAILED, AttachFailureReason::IME_ABNORMAL },
    { ErrorCode::ERROR_IMSA_IME_DISCONNECT_FAILED, AttachFailureReason::IME_ABNORMAL },
    { ErrorCode::ERROR_IMSA_IME_START_TIMEOUT, AttachFailureReason::IME_ABNORMAL },
    { ErrorCode::ERROR_IMSA_IME_START_MORE_THAN_EIGHT_SECOND, AttachFailureReason::IME_ABNORMAL },
    { ErrorCode::ERROR_IMSA_FORCE_STOP_IME_TIMEOUT, AttachFailureReason::IME_ABNORMAL },
    { ErrorCode::ERROR_IME_NOT_FOUND, AttachFailureReason::IME_ABNORMAL },
    { ErrorCode::ERROR_TRY_IME_START_FAILED, AttachFailureReason::IME_ABNORMAL },
    { ErrorCode::ERROR_IME_START_INPUT_FAILED, AttachFailureReason::IME_ABNORMAL },
};
class ImcInnerListener {
public:
    virtual ~ImcInnerListener() = default;
    virtual void OnAttachmentDidFail(AttachFailureReason reason){};
};
} // namespace MiscServices
} // namespace OHOS
#endif // INPUTMETHOD_IMF_IMC_INNER_LISTENER_H