/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "block_queue.h"

#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <unistd.h>

#include <cinttypes>
#include <sstream>
#include <thread>

#include "global.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace testing::mt;
using namespace std::chrono;
class ImfBlockQueueTest : public testing::Test {
public:
    static constexpr int32_t maxWaitTime_ = 5000;
    static constexpr int32_t eachThreadCirculationTime_ = 100;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void TestImfBlockQueue();
    static int64_t GetThreadId();
    static bool timeout_;

private:
    static BlockQueue<std::chrono::system_clock::time_point> timeQueue_;
};
BlockQueue<std::chrono::system_clock::time_point> ImfBlockQueueTest::timeQueue_ { maxWaitTime_ };
bool ImfBlockQueueTest::timeout_ { false };
void ImfBlockQueueTest::SetUpTestCase(void) { }

void ImfBlockQueueTest::TearDownTestCase(void) { }

void ImfBlockQueueTest::SetUp() { }

void ImfBlockQueueTest::TearDown() { }

int64_t ImfBlockQueueTest::GetThreadId()
{
    std::thread::id id = std::this_thread::get_id();
    std::ostringstream oss;
    oss << id;
    std::string idStr = oss.str();
    return atol(idStr.c_str());
}

void ImfBlockQueueTest::TestImfBlockQueue()
{
    for (int32_t i = 0; i < eachThreadCirculationTime_; i++) {
        if (timeout_) {
            break;
        }
        auto time = std::chrono::system_clock::now();
        timeQueue_.Push(time);
        int64_t start = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        timeQueue_.Wait(time);
        int64_t end = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        auto consume = end - start;
        auto threadId = GetThreadId();
        IMSA_HILOGI("consume:%{public}" PRId64 ",threadId:%{public}" PRId64 "", consume, threadId);
        if (consume >= maxWaitTime_) {
            timeout_ = true;
        }
        timeQueue_.Pop();
    }
}

/**
 * @tc.name: blockQueueTest_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_001, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_001 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;

    if (queue.IsEmpty()) {
        IMSA_HILOGI("Queue is empty");
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        try {
            queue.Pop();
        } catch (const std::exception& e) {
            IMSA_HILOGI("Exception: %{public}s", e.what());
        }
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_002, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_002 START");
    BlockQueue<int> queue(10);
    for (int i = 0; i < 10; ++i) {
        EXPECT_TRUE(queue.Push(i));
    }
    EXPECT_FALSE(queue.Push(11));
}

/**
 * @tc.name: blockQueueTest_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_003, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_003 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, i]() {
            for (int j = 0; j < 10; ++j) {
                queue.Push(i * 10 + j);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_EQ(queue.Size(), 100);
}

/**
 * @tc.name: blockQueueTest_004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_004, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_004 START");
    BlockQueue<int> queue(10);
    auto startTime = std::chrono::system_clock::now();
    EXPECT_FALSE(queue.Wait(100));
    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    EXPECT_GE(duration.count(), 100);
}

/**
 * @tc.name: blockQueueTest_005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_005, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_005 START");
    BlockQueue<int> queue(1);
    EXPECT_TRUE(queue.Push(1));
    EXPECT_FALSE(queue.Push(2));
    EXPECT_EQ(queue.Pop(), 1);
    EXPECT_TRUE(queue.Push(2));
}

/**
 * @tc.name: blockQueueTest_006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_006, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_006 START");
    BlockQueue<int> queue(100);
    for (int i = 0; i < 100; ++i) {
        queue.Push(i);
    }
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue]() {
            for (int j = 0; j < 10; ++j) {
                queue.Pop();
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_007
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_007, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_007 START");
    BlockQueue<int> queue(10);
    EXPECT_TRUE(queue.Empty());
    EXPECT_THROW(queue.Pop(), std::runtime_error);
}

/**
 * @tc.name: blockQueueTest_008
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_008, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_008 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, i]() {
            for (int j = 0; j < 10; ++j) {
                queue.Push(i * 10 + j);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_TRUE(queue.Wait(100));
}

/**
 * @tc.name: blockQueueTest_009
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_009, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_009 START");
    BlockQueue<int> queue(100);
    for (int i = 0; i < 100; ++i) {
        queue.Push(i);
    }
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue]() {
            for (int j = 0; j < 10; ++j) {
                queue.Pop();
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_TRUE(queue.Wait(100));
}

/**
 * @tc.name: blockQueueTest_010
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_010, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_010 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, i]() {
            for (int j = 0; j < 10; ++j) {
                queue.Push(i * 10 + j);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_EQ(queue.Size(), 100);
    for (int i = 0; i < 50; ++i) {
        queue.Pop();
    }
    EXPECT_EQ(queue.Size(), 50);
}

/**
 * @tc.name: blockQueueTest_011
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_011, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_011 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, i]() {
            for (int j = 0; j < 10; ++j) {
                queue.Push(i * 10 + j);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_FALSE(queue.Empty());
    for (int i = 0; i < 100; ++i) {
        queue.Pop();
    }
    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_012
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_012, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_012 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, i]() {
            for (int j = 0; j < 10; ++j) {
                queue.Push(i * 10 + j);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_TRUE(queue.Full());
    EXPECT_FALSE(queue.Push(101));
}

/**
 * @tc.name: blockQueueTest_013
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_013, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_013 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, i]() {
            for (int j = 0; j < 10; ++j) {
                queue.Push(i * 10 + j);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_TRUE(queue.Full());
    EXPECT_FALSE(queue.Push(101));
    for (int i = 0; i < 100; ++i) {
        queue.Pop();
    }
    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_014
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_014, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_014 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    std::vector<int> pushTimes;
    std::vector<int> popTimes;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, &pushTimes, &popTimes, i]() {
            for (int j = 0; j < 10; ++j) {
                auto startTime = std::chrono::system_clock::now();
                queue.Push(i * 10 + j);
                auto endTime = std::chrono::system_clock::now();
                pushTimes.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        auto startTime = std::chrono::system_clock::now();
        queue.Pop();
        auto endTime = std::chrono::system_clock::now();
        popTimes.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
    }

    // 计算平均等待时间
    int totalPushTime = 0;
    for (auto time : pushTimes) {
        totalPushTime += time;
    }
    int avgPushTime = totalPushTime / pushTimes.size();

    int totalPopTime = 0;
    for (auto time : popTimes) {
        totalPopTime += time;
    }
    int avgPopTime = totalPopTime / popTimes.size();

    IMSA_HILOGI("Average Push Time: %{public}d ms", avgPushTime);
    IMSA_HILOGI("Average Pop Time: %{public}d ms", avgPopTime);
}

/**
 * @tc.name: blockQueueTest_015
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_015, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_015 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    auto startTime = std::chrono::system_clock::now();

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("Total Time: %{public}d ms", duration);
    IMSA_HILOGI("Throughput: %{public}d items/ms", totalItems / duration);
}

/**
 * @tc.name: blockQueueTest_016
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_016, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_016 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_017
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_017, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_017 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;

    if (queue.IsEmpty()) {
        IMSA_HILOGI("Queue is empty");
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        try {
            queue.Pop();
        } catch (const std::exception& e) {
            IMSA_HILOGI("Exception: %{public}s", e.what());
        }
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_018
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_018, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_018 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    auto startTime = std::chrono::system_clock::now();

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("Total Time: %{public}d ms", duration);
    IMSA_HILOGI("Throughput: %{public}d items/ms", totalItems / duration);
}

/**
 * @tc.name: blockQueueTest_019
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_019, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_019 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_020
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_020, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_020 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;

    if (queue.IsEmpty()) {
        IMSA_HILOGI("Queue is empty");
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        try {
            queue.Pop();
        } catch (const std::exception& e) {
            IMSA_HILOGI("Exception: %{public}s", e.what());
        }
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_021
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_021, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_021 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    std::vector<int> pushTimes;
    std::vector<int> popTimes;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, &pushTimes, &popTimes, i]() {
            for (int j = 0; j < 10; ++j) {
                auto startTime = std::chrono::system_clock::now();
                queue.Push(i * 10 + j);
                auto endTime = std::chrono::system_clock::now();
                pushTimes.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        auto startTime = std::chrono::system_clock::now();
        queue.Pop();
        auto endTime = std::chrono::system_clock::now();
        popTimes.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
    }

    // 计算平均等待时间
    int totalPushTime = 0;
    for (auto time : pushTimes) {
        totalPushTime += time;
    }
    int avgPushTime = totalPushTime / pushTimes.size();

    int totalPopTime = 0;
    for (auto time : popTimes) {
        totalPopTime += time;
    }
    int avgPopTime = totalPopTime / popTimes.size();

    IMSA_HILOGI("Average Push Time: %{public}d ms", avgPushTime);
    IMSA_HILOGI("Average Pop Time: %{public}d ms", avgPopTime);
}

/**
 * @tc.name: blockQueueTest_022
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_022, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_022 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    auto startTime = std::chrono::system_clock::now();

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("Total Time: %{public}d ms", duration);
    IMSA_HILOGI("Throughput: %{public}d items/ms", totalItems / duration);
}

/**
 * @tc.name: blockQueueTest_023
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_023, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_023 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_024
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_024, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_024 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;

    if (queue.IsEmpty()) {
        IMSA_HILOGI("Queue is empty");
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        try {
            queue.Pop();
        } catch (const std::exception& e) {
            IMSA_HILOGI("Exception: %{public}s", e.what());
        }
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_025
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_025, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_025 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    auto startTime = std::chrono::system_clock::now();

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("Total Time: %{public}d ms", duration);
    IMSA_HILOGI("Throughput: %{public}d items/ms", totalItems / duration);
}

/**
 * @tc.name: blockQueueTest_026
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_026, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_026 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_027
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_027, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_027 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;

    if (queue.IsEmpty()) {
        IMSA_HILOGI("Queue is empty");
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        try {
            queue.Pop();
        } catch (const std::exception& e) {
            IMSA_HILOGI("Exception: %{public}s", e.what());
        }
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_028
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_028, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_028 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    auto startTime = std::chrono::system_clock::now();

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("Total Time: %{public}d ms", duration);
    IMSA_HILOGI("Throughput: %{public}d items/ms", totalItems / duration);
}

/**
 * @tc.name: blockQueueTest_029
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_029, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_029 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_030
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_030, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_030 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;

    if (queue.IsEmpty()) {
        IMSA_HILOGI("Queue is empty");
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        try {
            queue.Pop();
        } catch (const std::exception& e) {
            IMSA_HILOGI("Exception: %{public}s", e.what());
        }
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_031
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_031, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_031 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    std::vector<int> pushTimes;
    std::vector<int> popTimes;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, &pushTimes, &popTimes, i]() {
            for (int j = 0; j < 10; ++j) {
                auto startTime = std::chrono::system_clock::now();
                queue.Push(i * 10 + j);
                auto endTime = std::chrono::system_clock::now();
                pushTimes.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        auto startTime = std::chrono::system_clock::now();
        queue.Pop();
        auto endTime = std::chrono::system_clock::now();
        popTimes.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
    }

    // 计算平均等待时间
    int totalPushTime = 0;
    for (auto time : pushTimes) {
        totalPushTime += time;
    }
    int avgPushTime = totalPushTime / pushTimes.size();

    int totalPopTime = 0;
    for (auto time : popTimes) {
        totalPopTime += time;
    }
    int avgPopTime = totalPopTime / popTimes.size();

    IMSA_HILOGI("Average Push Time: %{public}d ms", avgPushTime);
    IMSA_HILOGI("Average Pop Time: %{public}d ms", avgPopTime);
}

/**
 * @tc.name: blockQueueTest_032
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_032, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_032 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    auto startTime = std::chrono::system_clock::now();

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("Total Time: %{public}d ms", duration);
    IMSA_HILOGI("Throughput: %{public}d items/ms", totalItems / duration);
}

/**
 * @tc.name: blockQueueTest_033
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_033, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_033 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_034
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_034, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_034 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;

    if (queue.IsEmpty()) {
        IMSA_HILOGI("Queue is empty");
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        try {
            queue.Pop();
        } catch (const std::exception& e) {
            IMSA_HILOGI("Exception: %{public}s", e.what());
        }
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_042
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_042, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_042 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    auto startTime = std::chrono::system_clock::now();

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("Total Time: %{public}d ms", duration);
    IMSA_HILOGI("Throughput: %{public}d items/ms", totalItems / duration);
}

/**
 * @tc.name: blockQueueTest_043
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_043, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_043 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_044
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_044, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_044 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;

    if (queue.IsEmpty()) {
        IMSA_HILOGI("Queue is empty");
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        try {
            queue.Pop();
        } catch (const std::exception& e) {
            IMSA_HILOGI("Exception: %{public}s", e.what());
        }
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_045
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_045, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_045 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    auto startTime = std::chrono::system_clock::now();

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("Total Time: %{public}d ms", duration);
    IMSA_HILOGI("Throughput: %{public}d items/ms", totalItems / duration);
}

/**
 * @tc.name: blockQueueTest_046
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_046, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_046 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_047
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_047, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_047 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;

    if (queue.IsEmpty()) {
        IMSA_HILOGI("Queue is empty");
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < 100; ++i) {
        try {
            queue.Pop();
        } catch (const std::exception& e) {
            IMSA_HILOGI("Exception: %{public}s", e.what());
        }
    }

    EXPECT_TRUE(queue.Empty());
}

/**
 * @tc.name: blockQueueTest_048
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_048, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_048 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    auto startTime = std::chrono::system_clock::now();

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    auto endTime = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("Total Time: %{public}d ms", duration);
    IMSA_HILOGI("Throughput: %{public}d items/ms", totalItems / duration);
}

/**
 * @tc.name: blockQueueTest_049
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(ImfBlockQueueTest, blockQueueTest_049, TestSize.Level1)
{
    IMSA_HILOGI("ImfBlockQueueTest blockQueueTest_049 START");
    BlockQueue<int> queue(100);
    std::vector<std::thread> threads;
    int totalItems = 1000;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&queue, totalItems, i]() {
            for (int j = 0; j < totalItems / 10; ++j) {
                queue.Push(i * totalItems / 10 + j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (int i = 0; i < totalItems; ++i) {
        queue.Pop();
    }

    EXPECT_TRUE(queue.Empty());
}
} // namespace MiscServices
} // namespace OHOS
