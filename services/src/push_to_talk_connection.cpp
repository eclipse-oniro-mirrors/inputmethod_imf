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

#include "global.h"
#include "message_option.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace MiscServices {

static std::recursive_mutex g_servicesConnectionMutex;

PushToTalkConnection::PushToTalkConnection(void) {}

PushToTalkConnection::PushToTalkConnection(
    const std::string &bundleName, const std::string &abilityName, const std::string &paramStr)
{
    bundleName_ = bundleName;
    abilityName_ = abilityName;
    paramStr_ = paramStr;
}

void PushToTalkConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    IMSA_HILOGI("PTT: Ability Connect enter");
    {
        std::unique_lock<std::recursive_mutex> lock(g_servicesConnectionMutex);
        remoteObj_ = remoteObject;
    }
    if (bundleName_.empty()) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    const int32_t keySize = 3;
    data.WriteInt32(keySize);
    data.WriteString16(u"bundleName");
    data.WriteString16(Str8ToStr16(bundleName_));
    data.WriteString16(u"abilityName");
    data.WriteString16(Str8ToStr16(abilityName_));
    data.WriteString16(u"parameters");
    data.WriteString16(Str8ToStr16(paramStr_));
    const uint32_t cmdCode = 1;
    if (remoteObject == nullptr) {
        return;
    }
    int32_t ret = remoteObject->SendRequest(cmdCode, data, reply, option);
    int32_t result = 0;
    int32_t replyRet = reply.ReadInt32(result);
    IMSA_HILOGW("PTT: ret: %{public}d, replyRet:%{public}d, reply: %{public}d", ret, replyRet, result);
}

void PushToTalkConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode)
{
    IMSA_HILOGI("enter");
    std::unique_lock<std::recursive_mutex> lock(g_servicesConnectionMutex);
    remoteObj_ = nullptr;
}

} // namespace MiscServices
} // namespace OHOS
