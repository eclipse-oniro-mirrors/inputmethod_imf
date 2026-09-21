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

#include "push_to_talk_connection.h"

#include <mutex>
#include <utility>

#include "global.h"
#include "message_option.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace MiscServices {

PushToTalkConnection::PushToTalkConnection() = default;

PushToTalkConnection::PushToTalkConnection(
    const std::string &bundleName, const std::string &abilityName, const std::string &paramStr)
    : bundleName_(bundleName), abilityName_(abilityName), paramStr_(paramStr)
{
}

void PushToTalkConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    IMSA_HILOGI("PTT: Ability Connect enter");
    {
        std::lock_guard<std::mutex> lock(remoteObjMutex_);
        remoteObj_ = remoteObject;
    }
    if (remoteObject == nullptr) {
        return;
    }
    if (bundleName_.empty()) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    const std::pair<std::u16string, std::u16string> params[] = {
        { u"bundleName", Str8ToStr16(bundleName_) },
        { u"abilityName", Str8ToStr16(abilityName_) },
        { u"parameters", Str8ToStr16(paramStr_) },
    };
    const int32_t paramCount = static_cast<int32_t>(sizeof(params) / sizeof(params[0]));
    data.WriteInt32(paramCount);
    for (const auto &[key, value] : params) {
        data.WriteString16(key);
        data.WriteString16(value);
    }
    const uint32_t cmdCode = 1;
    int32_t ret = remoteObject->SendRequest(cmdCode, data, reply, option);
    int32_t result = 0;
    int32_t replyRet = reply.ReadInt32(result);
    IMSA_HILOGW("PTT: ret: %{public}d, replyRet:%{public}d, reply: %{public}d", ret, replyRet, result);
}

void PushToTalkConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode)
{
    IMSA_HILOGI("enter");
    std::lock_guard<std::mutex> lock(remoteObjMutex_);
    remoteObj_ = nullptr;
}

} // namespace MiscServices
} // namespace OHOS
