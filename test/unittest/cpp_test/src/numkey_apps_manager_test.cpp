/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "numkey_apps_manager.h"

#include "ime_info_inquirer.h"

#undef private

#include <gtest/gtest.h>

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
class NumKeyAppsManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
};

constexpr std::int32_t MAIN_USER_ID = 100;
constexpr std::int32_t INVALID_USER_ID = 10001;
static constexpr const char *WHITE_LIST_APP_NAME = "WHITE_LIST_APP_NAME";
static constexpr const char *BLOCK_LIST_APP_NAME = "BLOCK_LIST_APP_NAME";
static constexpr const char *DEFAULT_DEVICETYPE = "default";

void NumKeyAppsManagerTest::SetUpTestCase(void)
{
    IMSA_HILOGI("NumKeyAppsManagerTest::SetUpTestCase");
}

void NumKeyAppsManagerTest::TearDownTestCase(void)
{
    IMSA_HILOGI("NumKeyAppsManagerTest::TearDownTestCase");
}

void NumKeyAppsManagerTest::SetUp()
{
    IMSA_HILOGI("NumKeyAppsManagerTest::SetUp");
}

void NumKeyAppsManagerTest::TearDown()
{
    IMSA_HILOGI("NumKeyAppsManagerTest::TearDown");
}

/**
 * @tc.name: testFeatureNotEnabled_001
 * @tc.desc: when feature not enabled
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testFeatureNotEnabled_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testFeatureNotEnabled_001 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = false;
    ImeInfoInquirer::GetInstance().systemConfig_.enableNumKeyFeature = false;
    int32_t ret = NumkeyAppsManager::GetInstance().Init(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(NumkeyAppsManager::GetInstance().usersBlockList_.find(MAIN_USER_ID),
        NumkeyAppsManager::GetInstance().usersBlockList_.end());
    ret = NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(MAIN_USER_ID, WHITE_LIST_APP_NAME);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = NumkeyAppsManager::GetInstance().OnUserSwitched(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = NumkeyAppsManager::GetInstance().OnUserRemoved(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testInit_001
 * @tc.desc: test init when feature enabled
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testInit_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testInit_001 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    ImeInfoInquirer::GetInstance().systemConfig_.enableNumKeyFeature = true;
    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.clear();
    ImeInfoInquirer::GetInstance().systemConfig_.disableNumKeyAppDeviceTypes.clear();
    ImeInfoInquirer::GetInstance().systemConfig_.disableNumKeyAppDeviceTypes.insert(DEFAULT_DEVICETYPE);
    int32_t ret = NumkeyAppsManager::GetInstance().Init(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.count(DEFAULT_DEVICETYPE), 1);
    EXPECT_NE(NumkeyAppsManager::GetInstance().usersBlockList_.find(MAIN_USER_ID),
        NumkeyAppsManager::GetInstance().usersBlockList_.end());
}

#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
/**
 * @tc.name: testNeedAutoNumKeyInput_001
 * @tc.desc: test NeedAutoNumKeyInput when app in usersBlockList_, priority: consumer > developer > system
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testNeedAutoNumKeyInput_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testNeedAutoNumKeyInput_001 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.clear();
    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.insert(DEFAULT_DEVICETYPE);
    NumkeyAppsManager::GetInstance().compConfigInited_ = false;

    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
    NumkeyAppsManager::GetInstance().usersBlockList_[MAIN_USER_ID] = { WHITE_LIST_APP_NAME };
    bool ret = NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(MAIN_USER_ID, WHITE_LIST_APP_NAME);
    EXPECT_FALSE(ret);

    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
    ret = NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(MAIN_USER_ID, WHITE_LIST_APP_NAME);
    // compConfigInited_ = false, so dev config returns DevConfigState:NO_CONFIG
    // fall through to device type fallback, app not in whitelist and no compatible device type match
    EXPECT_FALSE(ret);

    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.clear();
}

/**
 * @tc.name: testNeedAutoNumKeyInput_002
 * @tc.desc: test NeedAutoNumKeyInput when comp config not inited and no whitelist
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testNeedAutoNumKeyInput_002, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testNeedAutoNumKeyInput_002 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    NumkeyAppsManager::GetInstance().compConfigInited_ = false;
    NumkeyAppsManager::GetInstance().usersBlockList_.clear();

    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.clear();
    bool ret = NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(MAIN_USER_ID, WHITE_LIST_APP_NAME);
    EXPECT_FALSE(ret);

    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.insert(DEFAULT_DEVICETYPE);
    ret = NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(MAIN_USER_ID, WHITE_LIST_APP_NAME);
    EXPECT_FALSE(ret);

    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.clear();
}

/**
 * @tc.name: testQueryDevCompConfig_001
 * @tc.desc: test QueryDevCompConfig when comp config not inited
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testQueryDevCompConfig_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testQueryDevCompConfig_001 START");
    NumkeyAppsManager::GetInstance().compConfigInited_ = false;
    auto ret = NumkeyAppsManager::GetInstance().QueryDevCompConfig(WHITE_LIST_APP_NAME);
    EXPECT_EQ(ret, DevConfigState::NO_CONFIG);
}
 
/**
 * @tc.name: testInitCompConfigReader_001
 * @tc.desc: test InitCompConfigReader when already inited
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testInitCompConfigReader_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testInitCompConfigReader_001 START");
    bool inited = NumkeyAppsManager::GetInstance().compConfigInited_;
    NumkeyAppsManager::GetInstance().compConfigInited_ = true;
    auto ret = NumkeyAppsManager::GetInstance().InitCompConfigReader();
    NumkeyAppsManager::GetInstance().compConfigInited_ = inited;
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}
 
/**
 * @tc.name: testInitCompConfigReader_002
 * @tc.desc: test InitCompConfigReader when library is available
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testInitCompConfigReader_002, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testInitCompConfigReader_002 START");
    NumkeyAppsManager::GetInstance().compConfigInited_ = false;
    auto ret = NumkeyAppsManager::GetInstance().InitCompConfigReader();
    // Library exists in test environment, Load and Init succeed
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    NumkeyAppsManager::GetInstance().compConfigInited_ = false;
}
 
/**
 * @tc.name: testPriorityConsumerOverDev_001
 * @tc.desc: test consumer block list has priority over developer config
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testPriorityConsumerOverDev_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testPriorityConsumerOverDev_001 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    NumkeyAppsManager::GetInstance().compConfigInited_ = false;
    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.clear();
    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
    NumkeyAppsManager::GetInstance().usersBlockList_[MAIN_USER_ID] = { BLOCK_LIST_APP_NAME };
    bool ret = NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(MAIN_USER_ID, BLOCK_LIST_APP_NAME);
    EXPECT_FALSE(ret);
    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
}
 
/**
 * @tc.name: testDevConfigEnabled_001
 * @tc.desc: test NeedAutoNumKeyInput when developer config is enabled, not in block list
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDevConfigEnabled_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDevConfigEnabled_001 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    NumkeyAppsManager::GetInstance().compConfigInited_ = true;
    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.clear();
 
    // Simulate developer config enabled by using mock compConfigReader_
    // In real test environment, compConfigReader_ is nullptr if Init not called
    // so QueryDevCompConfig returns DevConfigState::NO_CONFIG
    auto ret = NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(MAIN_USER_ID, WHITE_LIST_APP_NAME);
    // Without a real compConfigReader_, dev config returns DevConfigState::NO_CONFIG, falls to system fallback
    EXPECT_FALSE(ret);
 
    NumkeyAppsManager::GetInstance().compConfigInited_ = false;
}
 
/**
 * @tc.name: testCompConfigNotInited_001
 * @tc.desc: test NeedAutoNumKeyInput when comp config not inited, fall through to device type check
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testCompConfigNotInited_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testCompConfigNotInited_001 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    NumkeyAppsManager::GetInstance().compConfigInited_ = false;
    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
    NumkeyAppsManager::GetInstance().disableNumKeyAppDeviceTypes_.clear();
 
    bool ret = NumkeyAppsManager::GetInstance().NeedAutoNumKeyInput(MAIN_USER_ID, WHITE_LIST_APP_NAME);
    EXPECT_FALSE(ret);
}
 
// Mock function pointers for CompConfigDlLoader dlsym results
static CompConfigPropertyValueMapResult mockGetConfigResult = {0, nullptr, 0};
static SystemCompConfigReaderHandle *mockCreateFn()
{
    return reinterpret_cast<SystemCompConfigReaderHandle *>(0x1);
}
static void mockDestroyFn(SystemCompConfigReaderHandle *) {}
static int32_t mockInitFn(SystemCompConfigReaderHandle *, const char **, int32_t)
{
    return 0;
}
static CompConfigPropertyValueMapResult mockGetConfigFn(
    SystemCompConfigReaderHandle *, const char *, const char **, int32_t)
{
    return mockGetConfigResult;
}
static void mockFreeResultFn(CompConfigPropertyValueMapResult *) {}
 
/**
 * @tc.name: testDlLoaderLoad_001
 * @tc.desc: CompConfigDlLoader Load succeeds when library is available
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderLoad_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderLoad_001 START");
    CompConfigDlLoader loader;
    bool ret = loader.Load();
    EXPECT_TRUE(ret);
    EXPECT_TRUE(loader.loaded_);
    EXPECT_NE(loader.handle_, nullptr);
}
 
/**
 * @tc.name: testDlLoaderLoad_002
 * @tc.desc: CompConfigDlLoader Load returns true when already loaded
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderLoad_002, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderLoad_002 START");
    CompConfigDlLoader loader;
    loader.loaded_ = true;
    bool ret = loader.Load();
    EXPECT_TRUE(ret);
}
 
/**
 * @tc.name: testDlLoaderIsLoaded_001
 * @tc.desc: CompConfigDlLoader IsLoaded returns false by default
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderIsLoaded_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderIsLoaded_001 START");
    CompConfigDlLoader loader;
    EXPECT_FALSE(loader.loaded_);
    EXPECT_FALSE(loader.IsLoaded());
    EXPECT_EQ(loader.IsLoaded(), false);
}
 
/**
 * @tc.name: testDlLoaderIsLoaded_002
 * @tc.desc: CompConfigDlLoader IsLoaded returns true when loaded
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderIsLoaded_002, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderIsLoaded_002 START");
    CompConfigDlLoader loader;
    loader.loaded_ = true;
    EXPECT_TRUE(loader.loaded_);
    EXPECT_TRUE(loader.IsLoaded());
    EXPECT_EQ(loader.IsLoaded(), true);
}
 
/**
 * @tc.name: testDlLoaderInit_001
 * @tc.desc: CompConfigDlLoader Init returns -1 when not loaded
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderInit_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderInit_001 START");
    CompConfigDlLoader loader;
    loader.loaded_ = false;
    int32_t ret = loader.Init({"numKeyOptions"});
    EXPECT_EQ(ret, -1);
}
 
/**
 * @tc.name: testDlLoaderInit_002
 * @tc.desc: CompConfigDlLoader Init returns -1 when loaded but fnInit_ is null
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderInit_002, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderInit_002 START");
    CompConfigDlLoader loader;
    loader.loaded_ = true;
    loader.fnInit_ = nullptr;
    int32_t ret = loader.Init({"numKeyOptions"});
    EXPECT_EQ(ret, -1);
}
 
/**
 * @tc.name: testDlLoaderInit_003
 * @tc.desc: CompConfigDlLoader Init succeeds when loaded and fnInit_ is set
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderInit_003, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderInit_003 START");
    CompConfigDlLoader loader;
    loader.loaded_ = true;
    loader.fnInit_ = mockInitFn;
    int32_t ret = loader.Init({"numKeyOptions"});
    EXPECT_EQ(ret, 0);
}
 
/**
 * @tc.name: testDlLoaderGetConfig_001
 * @tc.desc: CompConfigDlLoader GetConfig returns {-1, {}} when not loaded
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderGetConfig_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderGetConfig_001 START");
    CompConfigDlLoader loader;
    loader.loaded_ = false;
    auto [ret, valMap] = loader.GetConfig("com.test.app", {"numKeyOptions"});
    EXPECT_EQ(ret, -1);
    EXPECT_TRUE(valMap.empty());
}
 
/**
 * @tc.name: testDlLoaderGetConfig_002
 * @tc.desc: CompConfigDlLoader GetConfig returns {-1, {}} when loaded but fnGetConfig_ is null
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderGetConfig_002, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderGetConfig_002 START");
    CompConfigDlLoader loader;
    loader.loaded_ = true;
    loader.fnGetConfig_ = nullptr;
    auto [ret, valMap] = loader.GetConfig("com.test.app", {"numKeyOptions"});
    EXPECT_EQ(ret, -1);
    EXPECT_TRUE(valMap.empty());
}
 
/**
 * @tc.name: testDlLoaderGetConfig_003
 * @tc.desc: CompConfigDlLoader GetConfig when fnGetConfig_ returns non-zero result
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderGetConfig_003, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderGetConfig_003 START");
    CompConfigDlLoader loader;
    loader.loaded_ = true;
    loader.fnCreate_ = mockCreateFn;
    loader.fnDestroy_ = mockDestroyFn;
    loader.fnInit_ = mockInitFn;
    loader.fnGetConfig_ = mockGetConfigFn;
    loader.fnFreeResult_ = mockFreeResultFn;
    mockGetConfigResult = {-1, nullptr, 0};
    auto [ret, valMap] = loader.GetConfig("com.test.app", {"numKeyOptions"});
    EXPECT_EQ(ret, -1);
    EXPECT_TRUE(valMap.empty());
}
 
/**
 * @tc.name: testDlLoaderGetConfig_004
 * @tc.desc: CompConfigDlLoader GetConfig with entries containing null key
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderGetConfig_004, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderGetConfig_004 START");
    CompConfigDlLoader loader;
    loader.loaded_ = true;
    loader.fnCreate_ = mockCreateFn;
    loader.fnDestroy_ = mockDestroyFn;
    loader.fnInit_ = mockInitFn;
    loader.fnGetConfig_ = mockGetConfigFn;
    loader.fnFreeResult_ = mockFreeResultFn;
    static CompConfigKvEntry entries[] = {
        {nullptr, "value1"},
        {"key2", nullptr},
        {"key3", "value3"},
    };
    mockGetConfigResult = {0, entries, 3};
    auto [ret, valMap] = loader.GetConfig("com.test.app", {"numKeyOptions"});
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(valMap.size(), 2u);
    EXPECT_EQ(valMap.count("key2"), 1u);
    EXPECT_EQ(valMap.at("key2"), "");
    EXPECT_EQ(valMap.count("key3"), 1u);
    EXPECT_EQ(valMap.at("key3"), "value3");
}
 
/**
 * @tc.name: testDlLoaderGetConfig_005
 * @tc.desc: CompConfigDlLoader GetConfig with all entries having valid key and value
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderGetConfig_005, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderGetConfig_005 START");
    CompConfigDlLoader loader;
    loader.loaded_ = true;
    loader.fnCreate_ = mockCreateFn;
    loader.fnDestroy_ = mockDestroyFn;
    loader.fnInit_ = mockInitFn;
    loader.fnGetConfig_ = mockGetConfigFn;
    loader.fnFreeResult_ = mockFreeResultFn;
    static CompConfigKvEntry entries[] = {
        {"numKeyOptions", R"({"autoConsumeNumKeysAndInsert":true})"},
    };
    mockGetConfigResult = {0, entries, 1};
    auto [ret, valMap] = loader.GetConfig("com.test.app", {"numKeyOptions"});
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(valMap.size(), 1u);
    EXPECT_EQ(valMap.at("numKeyOptions"), R"({"autoConsumeNumKeysAndInsert":true})");
}
 
/**
 * @tc.name: testDlLoaderDestructor_NullPointers
 * @tc.desc: CompConfigDlLoader destructor handles null handle and reader gracefully
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderDestructor_NullPointers, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderDestructor_NullPointers START");
    CompConfigDlLoader loader;
    EXPECT_EQ(loader.handle_, nullptr);
    EXPECT_EQ(loader.reader_, nullptr);
    EXPECT_FALSE(loader.loaded_);
}
 
/**
 * @tc.name: testDlLoaderDestructor_Cleanup
 * @tc.desc: CompConfigDlLoader destructor properly cleans up handle and reader
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testDlLoaderDestructor_Cleanup, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testDlLoaderDestructor_Cleanup START");
    CompConfigDlLoader loader;
    loader.handle_ = reinterpret_cast<void *>(0x1);
    loader.reader_ = mockCreateFn();
    loader.fnDestroy_ = mockDestroyFn;
    loader.loaded_ = true;
    EXPECT_NE(loader.handle_, nullptr);
    EXPECT_NE(loader.reader_, nullptr);
    EXPECT_TRUE(loader.loaded_);
    // Reset handle_ to nullptr to avoid dlclose on fake pointer
    loader.handle_ = nullptr;
}
#endif

/**
 * @tc.name: testOnUserSwitched_001
 * @tc.desc: already inited, no need to update when user switch
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testOnUserSwitched_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testOnUserSwitched_001 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    NumkeyAppsManager::GetInstance().usersBlockList_[INVALID_USER_ID] = { BLOCK_LIST_APP_NAME };
    auto ret = NumkeyAppsManager::GetInstance().OnUserSwitched(INVALID_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(NumkeyAppsManager::GetInstance().usersBlockList_[INVALID_USER_ID].size(), 0);
    EXPECT_EQ(NumkeyAppsManager::GetInstance().usersBlockList_[INVALID_USER_ID].count(BLOCK_LIST_APP_NAME), 0);
}

/**
 * @tc.name: testOnUserSwitched_002
 * @tc.desc: update usersblocklist with user not inited when user switched
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testOnUserSwitched_002, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testOnUserSwitched_002 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
    auto ret = NumkeyAppsManager::GetInstance().OnUserSwitched(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_NE(NumkeyAppsManager::GetInstance().usersBlockList_.find(MAIN_USER_ID),
        NumkeyAppsManager::GetInstance().usersBlockList_.end());
}

/**
 * @tc.name: testOnUserSwitched_003
 * @tc.desc: test usersBlockList_ not empty after OnUserSwitched
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testOnUserSwitched_003, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testOnUserSwitched_003 START");
    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
    auto ret = NumkeyAppsManager::GetInstance().OnUserSwitched(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    bool result = NumkeyAppsManager::GetInstance().usersBlockList_.find(MAIN_USER_ID)
                  != NumkeyAppsManager::GetInstance().usersBlockList_.end();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: testOnUserRemoved_001
 * @tc.desc: user removed when observers empty
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testOnUserRemoved_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testOnUserRemoved_001 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    NumkeyAppsManager::GetInstance().observers_.clear();
    auto ret = NumkeyAppsManager::GetInstance().OnUserRemoved(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testOnUserRemoved_002
 * @tc.desc: observers_ not empty, remove valid user
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testOnUserRemoved_002, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testOnUserRemoved_002 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    sptr<SettingsDataObserver> observer = new (std::nothrow) SettingsDataObserver("", "", nullptr);
    ASSERT_TRUE(observer != nullptr);
    NumkeyAppsManager::GetInstance().observers_.clear();
    NumkeyAppsManager::GetInstance().observers_[MAIN_USER_ID] = observer;
    NumkeyAppsManager::GetInstance().OnUserRemoved(MAIN_USER_ID);
    EXPECT_EQ(NumkeyAppsManager::GetInstance().observers_.find(MAIN_USER_ID),
        NumkeyAppsManager::GetInstance().observers_.end());
    NumkeyAppsManager::GetInstance().observers_.clear();
}

/**
 * @tc.name: testOnUserRemoved_003
 * @tc.desc: observers_ not empty, remove invalid user
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testOnUserRemoved_003, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testOnUserRemoved_003 START");
    NumkeyAppsManager::GetInstance().isFeatureEnabled_ = true;
    sptr<SettingsDataObserver> observer = new (std::nothrow) SettingsDataObserver("", "", nullptr);
    ASSERT_TRUE(observer != nullptr);
    NumkeyAppsManager::GetInstance().observers_.clear();
    NumkeyAppsManager::GetInstance().observers_[MAIN_USER_ID] = observer;
    NumkeyAppsManager::GetInstance().OnUserRemoved(INVALID_USER_ID);
    EXPECT_NE(NumkeyAppsManager::GetInstance().observers_.find(MAIN_USER_ID),
        NumkeyAppsManager::GetInstance().observers_.end());
    NumkeyAppsManager::GetInstance().observers_.clear();
}

/**
 * @tc.name: testUpdateUserBlockList_001
 * @tc.desc: usersBlockList_ not empty update user block list
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testUpdateUserBlockList_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testUpdateUserBlockList_001 START");
    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
    auto ret = NumkeyAppsManager::GetInstance().UpdateUserBlockList(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_NE(NumkeyAppsManager::GetInstance().usersBlockList_.find(MAIN_USER_ID),
        NumkeyAppsManager::GetInstance().usersBlockList_.end());
    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
}

/**
 * @tc.name: testParseBlockList_001
 * @tc.desc: test ParseBlockList
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testParseBlockList_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testParseBlockList_001 START");
    std::unordered_set<std::string> list;
    auto ret = NumkeyAppsManager::GetInstance().ParseBlockList(MAIN_USER_ID, list);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testRegisterUserBlockListData_001
 * @tc.desc: test RegisterUserBlockListData
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testRegisterUserBlockListData_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testRegisterUserBlockListData_001 START");
    NumkeyAppsManager::GetInstance().observers_.clear();
    auto ret = NumkeyAppsManager::GetInstance().RegisterUserBlockListData(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testRegisterUserBlockListData_002
 * @tc.desc: test RegisterUserBlockListData
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testRegisterUserBlockListData_002, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testRegisterUserBlockListData_002 START");
    NumkeyAppsManager::GetInstance().observers_.clear();
    sptr<SettingsDataObserver> observer = new (std::nothrow) SettingsDataObserver("", "", nullptr);
    ASSERT_TRUE(observer != nullptr);
    NumkeyAppsManager::GetInstance().observers_[MAIN_USER_ID] = observer;
    auto ret = NumkeyAppsManager::GetInstance().RegisterUserBlockListData(MAIN_USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    NumkeyAppsManager::GetInstance().Release();
    NumkeyAppsManager::GetInstance().observers_.clear();
}

/**
 * @tc.name: testIsInNumkeyBlockList_001
 * @tc.desc: test IsInNumkeyBlockList
 * @tc.type: FUNC
 */
HWTEST_F(NumKeyAppsManagerTest, testIsInNumkeyBlockList_001, TestSize.Level1)
{
    IMSA_HILOGI("NumKeyAppsManagerTest testIsInNumkeyBlockList_001 START");

    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
    bool ret = NumkeyAppsManager::GetInstance().IsInNumkeyBlockList(MAIN_USER_ID, BLOCK_LIST_APP_NAME);
    EXPECT_FALSE(ret);

    NumkeyAppsManager::GetInstance().usersBlockList_[MAIN_USER_ID] = {};
    ret = NumkeyAppsManager::GetInstance().IsInNumkeyBlockList(MAIN_USER_ID, BLOCK_LIST_APP_NAME);
    EXPECT_FALSE(ret);

    NumkeyAppsManager::GetInstance().usersBlockList_[MAIN_USER_ID] = { BLOCK_LIST_APP_NAME };
    ret = NumkeyAppsManager::GetInstance().IsInNumkeyBlockList(MAIN_USER_ID, BLOCK_LIST_APP_NAME);
    EXPECT_TRUE(ret);

    NumkeyAppsManager::GetInstance().usersBlockList_.clear();
}
} // namespace MiscServices
} // namespace OHOS
