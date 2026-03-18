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

#ifndef IMF_OS_ACCOUNT_LISTENER_H
#define IMF_OS_ACCOUNT_LISTENER_H

#include "os_account_subscriber.h"
namespace OHOS {
namespace MiscServices {
class OsAccountListener final : public AccountSA::OsAccountSubscriber {
public:
    explicit OsAccountListener(const AccountSA::OsAccountSubscribeInfo &info) : AccountSA::OsAccountSubscriber(info)
    {
    }
    void OnStateChanged(const AccountSA::OsAccountStateData &data) override;

private:
    void SendUserEvent(int32_t eventId, const AccountSA::OsAccountStateData &data);
};
} // namespace MiscServices
} // namespace OHOS

#endif // IMF_OS_ACCOUNT_LISTENER_H
