/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_INPUTMETHOD_IMF_FRAMEWORKS_BLOCK_DATA_H
#define OHOS_INPUTMETHOD_IMF_FRAMEWORKS_BLOCK_DATA_H
#include <condition_variable>
#include <mutex>

namespace OHOS {
namespace MiscServices {
template<typename T> class BlockData {
public:
    explicit BlockData(uint32_t interval, const T &invalid = T()) : INTERVAL(interval), data_(invalid)
    {
    }

    ~BlockData()
    {
    }

public:
    void SetValue(T &data)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        data_ = data;
        isSet_ = true;
        cv_.notify_one();
    }

    T GetValue()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(INTERVAL), [this]() { return isSet_; });
        isTimeOut_ = !isSet_;
        T data = data_;
        return data;
    }

    void Clear(const T &invalid = T())
    {
        std::lock_guard<std::mutex> lock(mutex_);
        isSet_ = false;
        data_ = invalid;
    }

    bool IsTimeOut()
    {
        return isTimeOut_;
    }

private:
    bool isSet_ = false;
    const uint32_t INTERVAL;
    T data_;
    bool isTimeOut_{ false };
    std::mutex mutex_;
    std::condition_variable cv_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // OHOS_INPUTMETHOD_IMF_FRAMEWORKS_BLOCK_DATA_H