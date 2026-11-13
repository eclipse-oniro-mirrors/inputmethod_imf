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
#ifndef NATIVE_SESSION_GUARD_H
#define NATIVE_SESSION_GUARD_H

#include <atomic>

namespace OHOS {
namespace MiscServices {
class NativeSessionGuard {
public:
    NativeSessionGuard() : acquired_(!active_.test_and_set(std::memory_order_acquire)) { }
    ~NativeSessionGuard()
    {
        if (acquired_) {
            active_.clear(std::memory_order_release);
        }
    }
    NativeSessionGuard(const NativeSessionGuard &) = delete;
    NativeSessionGuard &operator=(const NativeSessionGuard &) = delete;
    bool IsAcquired() const
    {
        return acquired_;
    }

private:
    // Reject callback re-entry instead of waiting while an application callback is in progress.
    inline static std::atomic_flag active_ = ATOMIC_FLAG_INIT;
    bool acquired_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // NATIVE_SESSION_GUARD_H
