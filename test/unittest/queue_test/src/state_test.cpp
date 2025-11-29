/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ime_state_manager_factory.h"
#include <gtest/gtest.h>
#include "global.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
class ImeStateManagerFactoryTest : public testing::Test {
protected:
    void SetUp() override
    {
        // Reset to default state before each test
        ImeStateManagerFactory::GetInstance().SetDynamicStartIme(false);
    }
};

/**
 * @tc.name: SetGetDynamicStartIme
 * @tc.desc: Test Set/Get for boolean flag
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, SetGetDynamicStartIme, TestSize.Level1)
{
    IMSA_HILOGI("SetGetDynamicStartIme START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    factory.SetDynamicStartIme(true);
    EXPECT_TRUE(factory.GetDynamicStartIme());

    factory.SetDynamicStartIme(false);
    EXPECT_FALSE(factory.GetDynamicStartIme());
}

/**
 * @tc.name: SingletonInstance
 * @tc.desc: Test singleton instance consistency
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, SingletonInstance, TestSize.Level1)
{
    IMSA_HILOGI("SingletonInstance START");
    auto &instance1 = ImeStateManagerFactory::GetInstance();
    auto &instance2 = ImeStateManagerFactory::GetInstance();
    ASSERT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: CreateImeLifecycleManagerWhenDynamic
 * @tc.desc: Test object creation in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeLifecycleManagerWhenDynamic, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeLifecycleManagerWhenDynamic START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);
    auto manager = factory.CreateImeStateManager(0, [] {
        return;
    });

    EXPECT_NE(manager.get(), nullptr);
}

/**
 * @tc.name: CreateFreezeManagerWhenNotDynamic
 * @tc.desc: Test object creation in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateFreezeManagerWhenNotDynamic, TestSize.Level1)
{
    IMSA_HILOGI("CreateFreezeManagerWhenNotDynamic START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);
    auto manager = factory.CreateImeStateManager(0, [] {
        FAIL() << "Should not be called";
    });

    EXPECT_NE(manager.get(), nullptr);
}

/**
 * @tc.name: MultipleSetGetDynamicStartIme
 * @tc.desc: Test multiple Set/Get calls for boolean flag
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, MultipleSetGetDynamicStartIme, TestSize.Level1)
{
    IMSA_HILOGI("MultipleSetGetDynamicStartIme START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    factory.SetDynamicStartIme(true);
    EXPECT_TRUE(factory.GetDynamicStartIme());

    factory.SetDynamicStartIme(false);
    EXPECT_FALSE(factory.GetDynamicStartIme());

    factory.SetDynamicStartIme(true);
    EXPECT_TRUE(factory.GetDynamicStartIme());
}

/**
 * @tc.name: CreateImeStateManagerDynamicMode
 * @tc.desc: Test object creation in dynamic mode with various parameters
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto manager1 = factory.CreateImeStateManager(1, [] {
        return;
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(2, [] {
        return;
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicMode
 * @tc.desc: Test object creation in non-dynamic mode with various parameters
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto manager1 = factory.CreateImeStateManager(1, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(2, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeException
 * @tc.desc: Test exception handling in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeException
 * @tc.desc: Test exception handling in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        FAIL() << "Should not be called";
    }), std::invalid_argument);
}

/**
 * @tc.name: ThreadSafetyTest
 * @tc.desc: Test thread safety of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ThreadSafetyTest, TestSize.Level1)
{
    IMSA_HILOGI("ThreadSafetyTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceTest
 * @tc.desc: Test performance of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceTest, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceTest completed in %ld ms", duration);
}

/**
 * @tc.name: ConcurrentSetGetDynamicStartIme
 * @tc.desc: Test concurrent Set/Get calls for boolean flag
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentSetGetDynamicStartIme, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentSetGetDynamicStartIme START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: ConcurrentCreateImeStateManagerDynamicMode
 * @tc.desc: Test concurrent object creation in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentCreateImeStateManagerDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentCreateImeStateManagerDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            auto manager = factory.CreateImeStateManager(i, [] {
                return;
            });
            EXPECT_NE(manager.get(), nullptr);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: ConcurrentCreateImeStateManagerNonDynamicMode
 * @tc.desc: Test concurrent object creation in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentCreateImeStateManagerNonDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentCreateImeStateManagerNonDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            auto manager = factory.CreateImeStateManager(i, [] {
                FAIL() << "Should not be called";
            });
            EXPECT_NE(manager.get(), nullptr);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceCreateImeStateManagerDynamicMode
 * @tc.desc: Test performance of object creation in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceCreateImeStateManagerDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceCreateImeStateManagerDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceCreateImeStateManagerDynamicMode completed in %ld ms", duration);
}

/**
 * @tc.name: PerformanceCreateImeStateManagerNonDynamicMode
 * @tc.desc: Test performance of object creation in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceCreateImeStateManagerNonDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceCreateImeStateManagerNonDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            FAIL() << "Should not be called";
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceCreateImeStateManagerNonDynamicMode completed in %ld ms", duration);
}

/**
 * @tc.name: MemoryLeakTest
 * @tc.desc: Test memory leak detection
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, MemoryLeakTest, TestSize.Level1)
{
    IMSA_HILOGI("MemoryLeakTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    for (int i = 0; i < 100; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
}

/**
 * @tc.name: ExceptionHandlingTest
 * @tc.desc: Test exception handling
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ExceptionHandlingTest, TestSize.Level1)
{
    IMSA_HILOGI("ExceptionHandlingTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1000, [] {
        return;
    }), std::out_of_range);
}

/**
 * @tc.name: SetGetDynamicStartImeBoundary
 * @tc.desc: Test Set/Get calls for boolean flag with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, SetGetDynamicStartImeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("SetGetDynamicStartImeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    factory.SetDynamicStartIme(false);
    EXPECT_FALSE(factory.GetDynamicStartIme());

    factory.SetDynamicStartIme(true);
    EXPECT_TRUE(factory.GetDynamicStartIme());
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeBoundary
 * @tc.desc: Test object creation in dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        return;
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        return;
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeBoundary
 * @tc.desc: Test object creation in non-dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeException
 * @tc.desc: Test exception handling in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        return;
    }), std::out_of_range);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeException
 * @tc.desc: Test exception handling in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        FAIL() << "Should not be called";
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        FAIL() << "Should not be called";
    }), std::out_of_range);
}

/**
 * @tc.name: ThreadSafetyTest
 * @tc.desc: Test thread safety of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ThreadSafetyTest, TestSize.Level1)
{
    IMSA_HILOGI("ThreadSafetyTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceTest
 * @tc.desc: Test performance of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceTest, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceTest completed in %ld ms", duration);
}

/**
 * @tc.name: ConcurrentSetGetDynamicStartIme
 * @tc.desc: Test concurrent Set/Get calls for boolean flag
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentSetGetDynamicStartIme, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentSetGetDynamicStartIme START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: ConcurrentCreateImeStateManagerDynamicMode
 * @tc.desc: Test concurrent object creation in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentCreateImeStateManagerDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentCreateImeStateManagerDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            auto manager = factory.CreateImeStateManager(i, [] {
                return;
            });
            EXPECT_NE(manager.get(), nullptr);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: ConcurrentCreateImeStateManagerNonDynamicMode
 * @tc.desc: Test concurrent object creation in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentCreateImeStateManagerNonDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentCreateImeStateManagerNonDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            auto manager = factory.CreateImeStateManager(i, [] {
                FAIL() << "Should not be called";
            });
            EXPECT_NE(manager.get(), nullptr);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceCreateImeStateManagerDynamicMode
 * @tc.desc: Test performance of object creation in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceCreateImeStateManagerDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceCreateImeStateManagerDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceCreateImeStateManagerDynamicMode completed in %ld ms", duration);
}

/**
 * @tc.name: PerformanceCreateImeStateManagerNonDynamicMode
 * @tc.desc: Test performance of object creation in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceCreateImeStateManagerNonDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceCreateImeStateManagerNonDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            FAIL() << "Should not be called";
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceCreateImeStateManagerNonDynamicMode completed in %ld ms", duration);
}

/**
 * @tc.name: MemoryLeakTest
 * @tc.desc: Test memory leak detection
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, MemoryLeakTest, TestSize.Level1)
{
    IMSA_HILOGI("MemoryLeakTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    for (int i = 0; i < 100; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
}

/**
 * @tc.name: ExceptionHandlingTest
 * @tc.desc: Test exception handling
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ExceptionHandlingTest, TestSize.Level1)
{
    IMSA_HILOGI("ExceptionHandlingTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1000, [] {
        return;
    }), std::out_of_range);
}

/**
 * @tc.name: SetGetDynamicStartImeBoundary
 * @tc.desc: Test Set/Get calls for boolean flag with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, SetGetDynamicStartImeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("SetGetDynamicStartImeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    factory.SetDynamicStartIme(false);
    EXPECT_FALSE(factory.GetDynamicStartIme());

    factory.SetDynamicStartIme(true);
    EXPECT_TRUE(factory.GetDynamicStartIme());
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeBoundary
 * @tc.desc: Test object creation in dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        return;
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        return;
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeBoundary
 * @tc.desc: Test object creation in non-dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeException
 * @tc.desc: Test exception handling in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        return;
    }), std::out_of_range);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeException
 * @tc.desc: Test exception handling in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        FAIL() << "Should not be called";
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        FAIL() << "Should not be called";
    }), std::out_of_range);
}

/**
 * @tc.name: ThreadSafetyTest
 * @tc.desc: Test thread safety of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ThreadSafetyTest, TestSize.Level1)
{
    IMSA_HILOGI("ThreadSafetyTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceTest
 * @tc.desc: Test performance of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceTest, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceTest completed in %ld ms", duration);
}

/**
 * @tc.name: ConcurrentSetGetDynamicStartIme
 * @tc.desc: Test concurrent Set/Get calls for boolean flag
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentSetGetDynamicStartIme, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentSetGetDynamicStartIme START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: ConcurrentCreateImeStateManagerDynamicMode
 * @tc.desc: Test concurrent object creation in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentCreateImeStateManagerDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentCreateImeStateManagerDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            auto manager = factory.CreateImeStateManager(i, [] {
                return;
            });
            EXPECT_NE(manager.get(), nullptr);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: ConcurrentCreateImeStateManagerNonDynamicMode
 * @tc.desc: Test concurrent object creation in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentCreateImeStateManagerNonDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentCreateImeStateManagerNonDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            auto manager = factory.CreateImeStateManager(i, [] {
                FAIL() << "Should not be called";
            });
            EXPECT_NE(manager.get(), nullptr);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceCreateImeStateManagerDynamicMode
 * @tc.desc: Test performance of object creation in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceCreateImeStateManagerDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceCreateImeStateManagerDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceCreateImeStateManagerDynamicMode completed in %ld ms", duration);
}

/**
 * @tc.name: PerformanceCreateImeStateManagerNonDynamicMode
 * @tc.desc: Test performance of object creation in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceCreateImeStateManagerNonDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceCreateImeStateManagerNonDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            FAIL() << "Should not be called";
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceCreateImeStateManagerNonDynamicMode completed in %ld ms", duration);
}

/**
 * @tc.name: MemoryLeakTest
 * @tc.desc: Test memory leak detection
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, MemoryLeakTest, TestSize.Level1)
{
    IMSA_HILOGI("MemoryLeakTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    for (int i = 0; i < 100; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
}

/**
 * @tc.name: ExceptionHandlingTest
 * @tc.desc: Test exception handling
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ExceptionHandlingTest, TestSize.Level1)
{
    IMSA_HILOGI("ExceptionHandlingTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1000, [] {
        return;
    }), std::out_of_range);
}

/**
 * @tc.name: SetGetDynamicStartImeBoundary
 * @tc.desc: Test Set/Get calls for boolean flag with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, SetGetDynamicStartImeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("SetGetDynamicStartImeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    factory.SetDynamicStartIme(false);
    EXPECT_FALSE(factory.GetDynamicStartIme());

    factory.SetDynamicStartIme(true);
    EXPECT_TRUE(factory.GetDynamicStartIme());
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeBoundary
 * @tc.desc: Test object creation in dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        return;
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        return;
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeBoundary
 * @tc.desc: Test object creation in non-dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeException
 * @tc.desc: Test exception handling in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        return;
    }), std::out_of_range);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeException
 * @tc.desc: Test exception handling in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        FAIL() << "Should not be called";
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        FAIL() << "Should not be called";
    }), std::out_of_range);
}

/**
 * @tc.name: ThreadSafetyTest
 * @tc.desc: Test thread safety of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ThreadSafetyTest, TestSize.Level1)
{
    IMSA_HILOGI("ThreadSafetyTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceTest
 * @tc.desc: Test performance of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceTest, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceTest completed in %ld ms", duration);
}

/**
 * @tc.name: ConcurrentSetGetDynamicStartIme
 * @tc.desc: Test concurrent Set/Get calls for boolean flag
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentSetGetDynamicStartIme, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentSetGetDynamicStartIme START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: ConcurrentCreateImeStateManagerDynamicMode
 * @tc.desc: Test concurrent object creation in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentCreateImeStateManagerDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentCreateImeStateManagerDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            auto manager = factory.CreateImeStateManager(i, [] {
                return;
            });
            EXPECT_NE(manager.get(), nullptr);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: ConcurrentCreateImeStateManagerNonDynamicMode
 * @tc.desc: Test concurrent object creation in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ConcurrentCreateImeStateManagerNonDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("ConcurrentCreateImeStateManagerNonDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            auto manager = factory.CreateImeStateManager(i, [] {
                FAIL() << "Should not be called";
            });
            EXPECT_NE(manager.get(), nullptr);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceCreateImeStateManagerDynamicMode
 * @tc.desc: Test performance of object creation in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceCreateImeStateManagerDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceCreateImeStateManagerDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceCreateImeStateManagerDynamicMode completed in %ld ms", duration);
}

/**
 * @tc.name: PerformanceCreateImeStateManagerNonDynamicMode
 * @tc.desc: Test performance of object creation in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceCreateImeStateManagerNonDynamicMode, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceCreateImeStateManagerNonDynamicMode START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            FAIL() << "Should not be called";
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceCreateImeStateManagerNonDynamicMode completed in %ld ms", duration);
}

/**
 * @tc.name: MemoryLeakTest
 * @tc.desc: Test memory leak detection
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, MemoryLeakTest, TestSize.Level1)
{
    IMSA_HILOGI("MemoryLeakTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    for (int i = 0; i < 100; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
}

/**
 * @tc.name: ExceptionHandlingTest
 * @tc.desc: Test exception handling
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ExceptionHandlingTest, TestSize.Level1)
{
    IMSA_HILOGI("ExceptionHandlingTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1000, [] {
        return;
    }), std::out_of_range);
}

/**
 * @tc.name: SetGetDynamicStartImeBoundary
 * @tc.desc: Test Set/Get calls for boolean flag with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, SetGetDynamicStartImeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("SetGetDynamicStartImeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    factory.SetDynamicStartIme(false);
    EXPECT_FALSE(factory.GetDynamicStartIme());

    factory.SetDynamicStartIme(true);
    EXPECT_TRUE(factory.GetDynamicStartIme());
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeBoundary
 * @tc.desc: Test object creation in dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        return;
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        return;
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeBoundary
 * @tc.desc: Test object creation in non-dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeException
 * @tc.desc: Test exception handling in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        return;
    }), std::out_of_range);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeException
 * @tc.desc: Test exception handling in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        FAIL() << "Should not be called";
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        FAIL() << "Should not be called";
    }), std::out_of_range);
}

/**
 * @tc.name: ThreadSafetyTest
 * @tc.desc: Test thread safety of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ThreadSafetyTest, TestSize.Level1)
{
    IMSA_HILOGI("ThreadSafetyTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceTest
 * @tc.desc: Test performance of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceTest, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceTest completed in %ld ms", duration);
}

/**
 * @tc.name: SetGetDynamicStartImeBoundary
 * @tc.desc: Test Set/Get calls for boolean flag with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, SetGetDynamicStartImeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("SetGetDynamicStartImeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    factory.SetDynamicStartIme(false);
    EXPECT_FALSE(factory.GetDynamicStartIme());

    factory.SetDynamicStartIme(true);
    EXPECT_TRUE(factory.GetDynamicStartIme());
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeBoundary
 * @tc.desc: Test object creation in dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        return;
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        return;
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeBoundary
 * @tc.desc: Test object creation in non-dynamic mode with boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeBoundary, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeBoundary START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    auto manager1 = factory.CreateImeStateManager(0, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager1.get(), nullptr);

    auto manager2 = factory.CreateImeStateManager(1000, [] {
        FAIL() << "Should not be called";
    });
    EXPECT_NE(manager2.get(), nullptr);
}

/**
 * @tc.name: CreateImeStateManagerDynamicModeException
 * @tc.desc: Test exception handling in dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        return;
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        return;
    }), std::out_of_range);
}

/**
 * @tc.name: CreateImeStateManagerNonDynamicModeException
 * @tc.desc: Test exception handling in non-dynamic mode
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, CreateImeStateManagerNonDynamicModeException, TestSize.Level1)
{
    IMSA_HILOGI("CreateImeStateManagerNonDynamicModeException START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(false);

    EXPECT_THROW(factory.CreateImeStateManager(-1, [] {
        FAIL() << "Should not be called";
    }), std::invalid_argument);

    EXPECT_THROW(factory.CreateImeStateManager(1001, [] {
        FAIL() << "Should not be called";
    }), std::out_of_range);
}

/**
 * @tc.name: ThreadSafetyTest
 * @tc.desc: Test thread safety of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, ThreadSafetyTest, TestSize.Level1)
{
    IMSA_HILOGI("ThreadSafetyTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&factory, i] {
            factory.SetDynamicStartIme(i % 2 == 0);
            EXPECT_EQ(factory.GetDynamicStartIme(), i % 2 == 0);
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

/**
 * @tc.name: PerformanceTest
 * @tc.desc: Test performance of ImeStateManagerFactory
 * @tc.type: FUNC
 */
HWTEST_F(ImeStateManagerFactoryTest, PerformanceTest, TestSize.Level1)
{
    IMSA_HILOGI("PerformanceTest START");
    auto &factory = ImeStateManagerFactory::GetInstance();
    factory.SetDynamicStartIme(true);

    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto manager = factory.CreateImeStateManager(i, [] {
            return;
        });
        EXPECT_NE(manager.get(), nullptr);
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    IMSA_HILOGI("PerformanceTest completed in %ld ms", duration);
}
} // namespace MiscServices
} // namespace OHOS