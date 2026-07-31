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

#ifndef IMF_TEST_SCREENLOCK_MANAGER_MOCK_H
#define IMF_TEST_SCREENLOCK_MANAGER_MOCK_H

#include <mutex>
#include "refbase.h"
#include "iremote_object.h"

namespace OHOS {
namespace ScreenLock {

namespace ScreenLockError {
static constexpr int32_t E_SCREENLOCK_OK = 0;
} // namespace ScreenLockError

class ScreenLockManagerMock : public RefBase {
public:
    static sptr<ScreenLockManagerMock> GetInstance()
    {
        static auto instance = sptr<ScreenLockManagerMock>(new ScreenLockManagerMock());
        return instance;
    }
    int32_t IsDeviceLocked(int32_t userId, bool &isDeviceLocked)
    {
        isDeviceLocked = isDeviceLocked_;
        return ScreenLockError::E_SCREENLOCK_OK;
    }
    bool IsScreenLocked()
    {
        return isScreenLocked_;
    }
    static void SetDeviceLocked(bool isDeviceLocked)
    {
        isDeviceLocked_ = isDeviceLocked;
    }
    static void SetScreenLocked(bool isScreenLocked)
    {
        isScreenLocked_ = isScreenLocked;
    }
    static void ResetParam()
    {
        isDeviceLocked_ = false;
        isScreenLocked_ = false;
    }

    // Unused stubs required by PerUserSession compilation
    int32_t IsLocked(bool &isLocked)
    {
        isLocked = isScreenLocked_;
        return 0;
    }
    bool GetSecure() { return false; }
    int32_t Lock(int32_t userId) { return 0; }
    int32_t Unlock(int, const sptr<IRemoteObject> &) { return 0; }
    int32_t OnSystemEvent(const sptr<IRemoteObject> &) { return 0; }
    int32_t SendScreenLockEvent(const std::string &, int) { return 0; }
    int32_t IsScreenLockDisabled(int, bool &) { return 0; }
    int32_t SetScreenLockDisabled(bool, int) { return 0; }
    int32_t SetScreenLockAuthState(int, int32_t, std::string &) { return 0; }
    int32_t GetScreenLockAuthState(int, int32_t &) { return 0; }
    int32_t RequestStrongAuth(int, int32_t) { return 0; }
    int32_t GetStrongAuth(int, int32_t &) { return 0; }
    int32_t IsLockedWithUserId(int, bool &) { return 0; }
    int32_t RegisterStrongAuthListener(const sptr<IRemoteObject> &) { return 0; }
    int32_t UnRegisterStrongAuthListener(const sptr<IRemoteObject> &) { return 0; }
    int32_t RegisterDeviceLockedListener(const sptr<IRemoteObject> &) { return 0; }
    int32_t UnRegisterDeviceLockedListener(const sptr<IRemoteObject> &) { return 0; }
    int32_t SetUnlockPolicy(int32_t, int32_t) { return 0; }
    int32_t GetUnlockPolicy(int32_t, int32_t &) { return 0; }

private:
    ScreenLockManagerMock() = default;
    ~ScreenLockManagerMock() override = default;
    static bool isDeviceLocked_;
    static bool isScreenLocked_;
};

bool ScreenLockManagerMock::isDeviceLocked_ { false };
bool ScreenLockManagerMock::isScreenLocked_ { false };

using ScreenLockManager = ScreenLockManagerMock;

} // namespace ScreenLock
} // namespace OHOS

#endif // IMF_TEST_SCREENLOCK_MANAGER_MOCK_H
