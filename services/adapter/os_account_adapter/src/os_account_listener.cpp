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

#include "os_account_listener.h"

#include <cinttypes>

#include "global.h"
#include "inputmethod_message_handler.h"
#include "itypes_util.h"

namespace OHOS {
namespace MiscServices {
using namespace AccountSA;
void OsAccountListener::OnStateChanged(const OsAccountStateData &data)
{
    IMSA_HILOGI("display: %{public}" PRIu64 ", state[%{public}d]: %{public}d to %{public}d",
        data.displayId.value_or(ImfCommonConst::DEFAULT_DISPLAY_ID), static_cast<int32_t>(data.state), data.fromId,
        data.toId);
    auto state = data.state;
    if (state == OsAccountState::SWITCHED) {
        SendUserEvent(MessageID::MSG_ID_USER_SWITCHED, data);
    } else if (state == OsAccountState::STOPPED) {
        SendUserEvent(MessageID::MSG_ID_USER_STOPPED, data);
    } else if (state == OsAccountState::REMOVED) {
        SendUserEvent(MessageID::MSG_ID_USER_REMOVED, data);
    }
}

void OsAccountListener::SendUserEvent(int32_t eventId, const AccountSA::OsAccountStateData &data)
{
    auto parcel = new (std::nothrow) MessageParcel();
    if (parcel == nullptr) {
        IMSA_HILOGE("failed to create MessageParcel");
        return;
    }
    uint64_t displayId = data.displayId.value_or(ImfCommonConst::DEFAULT_DISPLAY_ID);
    if (!ITypesUtil::Marshal(*parcel, data.fromId, data.toId, displayId)) {
        IMSA_HILOGE("failed to write parcel");
        delete parcel;
        return;
    }
    auto msg = new (std::nothrow) Message(eventId, parcel);
    if (msg == nullptr) {
        IMSA_HILOGE("failed to create Message");
        delete parcel;
        return;
    }
    MessageHandler::Instance()->SendMessage(msg);
}
} // namespace MiscServices
} // namespace OHOS