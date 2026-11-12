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

#ifndef OHOS_INPUTMETHOD_FFRT_BLOCK_QUEUE_H
#define OHOS_INPUTMETHOD_FFRT_BLOCK_QUEUE_H
#include <chrono>
#include <queue>
#include <utility>

#include "ffrt.h"

namespace OHOS {
namespace MiscServices {
template<typename T> class FFRTBlockQueue {
public:
    explicit FFRTBlockQueue(uint32_t timeout) : timeout_(timeout)
    {
    }

    ~FFRTBlockQueue() = default;

    void Pop()
    {
        std::unique_lock<ffrt::mutex> lock(queuesMutex_);
        if (queues_.empty()) {
            return;
        }
        queues_.pop();
        cv_.notify_all();
    }

    bool Pop(const T &data)
    {
        std::unique_lock<ffrt::mutex> lock(queuesMutex_);
        if (queues_.empty() || !(data == queues_.front())) {
            return false;
        }
        queues_.pop();
        cv_.notify_all();
        return true;
    }

    bool Remove(const T &data)
    {
        std::unique_lock<ffrt::mutex> lock(queuesMutex_);
        std::queue<T> remaining;
        bool removed = false;
        while (!queues_.empty()) {
            if (!removed && data == queues_.front()) {
                removed = true;
            } else {
                remaining.push(std::move(queues_.front()));
            }
            queues_.pop();
        }
        queues_.swap(remaining);
        if (removed) {
            cv_.notify_all();
        }
        return removed;
    }

    void Push(const T &data)
    {
        std::unique_lock<ffrt::mutex> lock(queuesMutex_);
        queues_.push(data);
        cv_.notify_all();
    }

    bool Wait(const T &data)
    {
        std::unique_lock<ffrt::mutex> lock(queuesMutex_);
        return cv_.wait_for(lock, std::chrono::milliseconds(timeout_), [&data, this]() {
            return !queues_.empty() && data == queues_.front();
        });
    }

    bool IsReady(const T &data)
    {
        std::unique_lock<ffrt::mutex> lock(queuesMutex_);
        return !queues_.empty() && data == queues_.front();
    }

    bool GetFront(T &data)
    {
        std::unique_lock<ffrt::mutex> lock(queuesMutex_);
        if (queues_.empty()) {
            return false;
        }
        data = queues_.front();
        return true;
    }

private:
    const uint32_t timeout_;
    ffrt::mutex queuesMutex_;
    std::queue<T> queues_;
    ffrt::condition_variable cv_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // OHOS_INPUTMETHOD_FFRT_BLOCK_QUEUE_H
