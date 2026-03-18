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

#include "os_account_adapter.h"

#include "global.h"
#include "os_account_listener.h"
#include "os_account_manager.h"
#include "os_account_subscriber.h"
namespace OHOS {
namespace MiscServices {
// LCOV_EXCL_START
using namespace AccountSA;
bool OsAccountAdapter::IsOsAccountForeground(int32_t userId)
{
    bool isForeground = false;
    auto errCode = OsAccountManager::IsOsAccountForeground(userId, isForeground);
    if (errCode != ERR_OK) {
        IMSA_HILOGE("IsOsAccountForeground failed, userId:%{public}d.", userId);
    }
    return isForeground;
}

std::vector<int32_t> OsAccountAdapter::QueryActiveOsAccountIds()
{
    std::vector<int32_t> userIds;
    int errCode = OsAccountManager::QueryActiveOsAccountIds(userIds);
    if (errCode != ERR_OK) {
        IMSA_HILOGE("QueryActiveOsAccountIds failed.");
    }
    return userIds;
}

int32_t OsAccountAdapter::GetForegroundOsAccountLocalId()
{
    int32_t userId = MAIN_USER_ID;
    if (!BlockRetry(RETRY_INTERVAL, BLOCK_RETRY_TIMES,
        [&userId]() -> bool { return OsAccountManager::GetForegroundOsAccountLocalId(userId) == ERR_OK; })) {
        IMSA_HILOGE("get foreground userId failed!");
    }
    return userId;
}

std::vector<int32_t> OsAccountAdapter::GetForegroundOsAccountIds()
{
    std::vector<ForegroundOsAccount> accounts;
    auto ret = OsAccountManager::GetForegroundOsAccounts(accounts);
    if (ret != ERR_OK) {
        IMSA_HILOGE("GetForegroundOsAccounts failed, ret: %{public}d.", ret);
        return { MAIN_USER_ID };
    }
    std::vector<int32_t> userIds;
    for (auto const &account : accounts) {
        userIds.emplace_back(account.localId);
    }
    return userIds;
}

std::vector<ForegroundOsAccount> OsAccountAdapter::GetForegroundOsAccounts()
{
    std::vector<ForegroundOsAccount> accounts;
    auto ret = OsAccountManager::GetForegroundOsAccounts(accounts);
    if (ret != ERR_OK) {
        IMSA_HILOGE("GetForegroundOsAccounts failed, ret: %{public}d.", ret);
        ForegroundOsAccount defaultMainAccount(MAIN_USER_ID, MAIN_DISPLAY_ID);
        accounts.emplace_back(defaultMainAccount);
    }
    return accounts;
}

int32_t OsAccountAdapter::GetOsAccountLocalIdFromUid(int32_t uid)
{
    int32_t userId = INVALID_USER_ID;
    auto errCode = OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    if (errCode != ERR_OK) {
        IMSA_HILOGE("GetOsAccountLocalIdFromUid failed, uid:%{public}d", uid);
    }
    return userId;
}

int32_t OsAccountAdapter::IsOsAccountVerified(int32_t userId, bool &isUnlocked)
{
    auto errCode = OsAccountManager::IsOsAccountVerified(userId, isUnlocked);
    if (errCode != ERR_OK) {
        IMSA_HILOGE("IsOsAccountVerified failed, userId: %{public}d, errCode: %{public}d", userId, errCode);
        return ErrorCode::ERROR_OS_ACCOUNT;
    }
    return ErrorCode::NO_ERROR;
}

int32_t OsAccountAdapter::GetMainAccountId()
{
    int32_t accountId = INVALID_USER_ID;
    auto errCode = OsAccountManager::GetForegroundOsAccountLocalId(ImfCommonConst::DEFAULT_DISPLAY_ID, accountId);
    if (errCode != ERR_OK) {
        IMSA_HILOGE("GetForegroundOsAccountLocalId failed, errCode: %{public}d", errCode);
        return MAIN_USER_ID;
    }
    IMSA_HILOGD("accountId: %{public}d", accountId);
    return accountId;
}

int32_t OsAccountAdapter::RegisterOsAccountStateListener()
{
    std::set<OsAccountState> states = { OsAccountState::REMOVED, OsAccountState::STOPPED, OsAccountState::SWITCHED };
    OsAccountSubscribeInfo subscribeInfo(states, false); // no need handshake
    auto listener = std::make_shared<OsAccountListener>(subscribeInfo);
    ErrCode ret = OsAccountManager::SubscribeOsAccount(listener);
    if (ret != ERR_OK) {
        IMSA_HILOGI("SubscribeOsAccount failed: %{public}d", ret);
        return ErrorCode::ERROR_OS_ACCOUNT;
    }
    IMSA_HILOGI("success");
    return ErrorCode::NO_ERROR;
}
// LCOV_EXCL_STOP
} // namespace MiscServices
} // namespace OHOS