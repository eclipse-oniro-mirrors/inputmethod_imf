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

#include "global.h"
#include "peruser_session.h"
#include <atomic>

namespace OHOS {
namespace MiscServices {

static std::atomic<bool> g_isDeviceLocked { false };
static std::atomic<bool> g_isScreenLocked { false };

void SetMockDeviceLocked(bool isDeviceLocked)
{
    g_isDeviceLocked.store(isDeviceLocked);
}

void SetMockScreenLocked(bool isScreenLocked)
{
    g_isScreenLocked.store(isScreenLocked);
}

void ResetMockScreenLock()
{
    g_isDeviceLocked.store(false);
    g_isScreenLocked.store(false);
}

// Override the real IsDeviceLockAndScreenLocked from inputmethod_service_static.
// The linker will prefer this object file's definition over the static library's.
bool PerUserSession::IsDeviceLockAndScreenLocked()
{
    IMSA_HILOGI("Mock IsDeviceLockAndScreenLocked: device=%{public}d, screen=%{public}d", g_isDeviceLocked.load(),
        g_isScreenLocked.load());
    return g_isScreenLocked.load() && g_isDeviceLocked.load();
}

} // namespace MiscServices
} // namespace OHOS
