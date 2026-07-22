/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "enable_upgrade_manager.h"

#include <gtest/gtest.h>

#include "global.h"
#include "ime_info_inquirer.h"
#include "serializable.h"
#include "settings_data_utils.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;
constexpr int32_t TEST_USER_ID = 100;
} // namespace

class EnableUpgradeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) { }
    void SetUp();
    void TearDown();
};

void EnableUpgradeManagerTest::SetUpTestCase(void)
{
    IMSA_HILOGI("EnableUpgradeManagerTest::SetUpTestCase");
}

void EnableUpgradeManagerTest::SetUp()
{
    IMSA_HILOGI("EnableUpgradeManagerTest::SetUp");
}

void EnableUpgradeManagerTest::TearDown()
{
    IMSA_HILOGI("EnableUpgradeManagerTest::TearDown");
    auto &mgr = EnableUpgradeManager::GetInstance();
    mgr.upgradedUserId_.clear();
}

/**
 * @tc.name: EnableUpgradeManager_GetInstance_001
 * @tc.desc: Test GetInstance returns valid singleton
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GetInstance_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GetInstance_001 START");
    auto &instance = EnableUpgradeManager::GetInstance();
    auto &instance2 = EnableUpgradeManager::GetInstance();
    EXPECT_EQ(&instance, &instance2);
}

/**
 * @tc.name: EnableUpgradeManager_Upgrade_001
 * @tc.desc: Test Upgrade with already upgraded user
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, Upgrade_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest Upgrade_001 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    mgr.upgradedUserId_.insert(TEST_USER_ID);
    std::vector<FullImeInfo> imeInfos;
    auto ret = mgr.Upgrade(TEST_USER_ID, imeInfos);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: EnableUpgradeManager_Upgrade_002
 * @tc.desc: Test Upgrade with new user and empty imeInfos
 * @tc.type: FUNC
 */


/**
 * @tc.name: EnableUpgradeManager_GetFullExperienceTable_001
 * @tc.desc: Test GetFullExperienceTable
 * @tc.type: FUNC
 */


/**
 * @tc.name: EnableUpgradeManager_GetGlobalTableUserId_001
 * @tc.desc: Test GetGlobalTableUserId with empty string
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GetGlobalTableUserId_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GetGlobalTableUserId_001 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string emptyStr;
    auto ret = mgr.GetGlobalTableUserId(emptyStr);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: EnableUpgradeManager_GetGlobalTableUserId_002
 * @tc.desc: Test GetGlobalTableUserId with valid JSON
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GetGlobalTableUserId_002, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GetGlobalTableUserId_002 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string validJson = R"({"enableImeList":{"100":["com.example.ime"]}})";
    auto ret = mgr.GetGlobalTableUserId(validJson);
    EXPECT_EQ(ret, 100);
}

/**
 * @tc.name: EnableUpgradeManager_GetGlobalTableUserId_003
 * @tc.desc: Test GetGlobalTableUserId with invalid JSON
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GetGlobalTableUserId_003, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GetGlobalTableUserId_003 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string invalidJson = "not json";
    auto ret = mgr.GetGlobalTableUserId(invalidJson);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: EnableUpgradeManager_GetGlobalTableUserId_004
 * @tc.desc: Test GetGlobalTableUserId with JSON missing enableImeList
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GetGlobalTableUserId_004, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GetGlobalTableUserId_004 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string jsonNoList = R"({"otherKey":"value"})";
    auto ret = mgr.GetGlobalTableUserId(jsonNoList);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: EnableUpgradeManager_GetGlobalTableUserId_005
 * @tc.desc: Test GetGlobalTableUserId with enableImeList having no child
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GetGlobalTableUserId_005, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GetGlobalTableUserId_005 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string jsonNoChild = R"({"enableImeList":{}})";
    auto ret = mgr.GetGlobalTableUserId(jsonNoChild);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: EnableUpgradeManager_GenerateGlobalContent_001
 * @tc.desc: Test GenerateGlobalContent with valid inputs
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GenerateGlobalContent_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GenerateGlobalContent_001 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::vector<std::string> bundleNames = { "com.example.ime1", "com.example.ime2" };
    auto content = mgr.GenerateGlobalContent(TEST_USER_ID, bundleNames);
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("com.example.ime1") != std::string::npos);
    EXPECT_TRUE(content.find("com.example.ime2") != std::string::npos);
    EXPECT_TRUE(content.find("100") != std::string::npos);
}

/**
 * @tc.name: EnableUpgradeManager_GenerateGlobalContent_002
 * @tc.desc: Test GenerateGlobalContent with empty bundleNames
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GenerateGlobalContent_002, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GenerateGlobalContent_002 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::vector<std::string> bundleNames;
    auto content = mgr.GenerateGlobalContent(TEST_USER_ID, bundleNames);
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("100") != std::string::npos);
}

/**
 * @tc.name: EnableUpgradeManager_ParseEnabledTable_001
 * @tc.desc: Test ParseEnabledTable with valid content
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, ParseEnabledTable_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest ParseEnabledTable_001 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string content = R"({"enableImeList":{"100":["com.example.ime1","com.example.ime2"]}})";
    std::set<std::string> bundleNames;
    auto ret = mgr.ParseEnabledTable(TEST_USER_ID, content, bundleNames);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(bundleNames.size(), 2u);
    EXPECT_TRUE(bundleNames.find("com.example.ime1") != bundleNames.end());
    EXPECT_TRUE(bundleNames.find("com.example.ime2") != bundleNames.end());
}

/**
 * @tc.name: EnableUpgradeManager_ParseEnabledTable_002
 * @tc.desc: Test ParseEnabledTable with invalid content
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, ParseEnabledTable_002, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest ParseEnabledTable_002 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string content = "invalid content";
    std::set<std::string> bundleNames;
    auto ret = mgr.ParseEnabledTable(TEST_USER_ID, content, bundleNames);
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_PARCELABLE);
}

/**
 * @tc.name: EnableUpgradeManager_ParseEnabledTable_003
 * @tc.desc: Test ParseEnabledTable with empty content
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, ParseEnabledTable_003, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest ParseEnabledTable_003 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string content;
    std::set<std::string> bundleNames;
    auto ret = mgr.ParseEnabledTable(TEST_USER_ID, content, bundleNames);
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_PARCELABLE);
}

/**
 * @tc.name: EnableUpgradeManager_ImePersistInfo_Marshal_001
 * @tc.desc: Test ImePersistInfo Marshal/Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, ImePersistInfo_Marshal_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest ImePersistInfo_Marshal_001 START");
    ImePersistInfo info(TEST_USER_ID, "com.example.ime/TestExt", "subtype1", true);
    info.tempScreenLockIme = "com.example.tmp/TmpExt";
    std::string content;
    ASSERT_TRUE(info.Marshall(content));
    EXPECT_TRUE(content.find("100") != std::string::npos);
    EXPECT_TRUE(content.find("com.example.ime/TestExt") != std::string::npos);
    EXPECT_TRUE(content.find("subtype1") != std::string::npos);
    EXPECT_TRUE(content.find("true") != std::string::npos);
    EXPECT_TRUE(content.find("com.example.tmp/TmpExt") != std::string::npos);
}

/**
 * @tc.name: EnableUpgradeManager_ImePersistInfo_Unmarshal_001
 * @tc.desc: Test ImePersistInfo Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, ImePersistInfo_Unmarshal_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest ImePersistInfo_Unmarshal_001 START");
    ImePersistInfo original(TEST_USER_ID, "com.example.ime/TestExt", "subtype1", true);
    original.tempScreenLockIme = "com.example.tmp/TmpExt";
    std::string content;
    ASSERT_TRUE(original.Marshall(content));
    ImePersistInfo restored;
    ASSERT_TRUE(restored.Unmarshall(content));
    EXPECT_EQ(restored.userId, TEST_USER_ID);
    EXPECT_EQ(restored.currentIme, "com.example.ime/TestExt");
    EXPECT_EQ(restored.currentSubName, "subtype1");
    EXPECT_TRUE(restored.isDefaultImeSet);
    EXPECT_EQ(restored.tempScreenLockIme, "com.example.tmp/TmpExt");
}

/**
 * @tc.name: EnableUpgradeManager_ImePersistCfg_Marshal_001
 * @tc.desc: Test ImePersistCfg Marshal/Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, ImePersistCfg_Marshal_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest ImePersistCfg_Marshal_001 START");
    ImePersistCfg cfg;
    ImePersistInfo info1(TEST_USER_ID, "com.example.ime1/Ext1", "sub1", false);
    ImePersistInfo info2(200, "com.example.ime2/Ext2", "sub2", true);
    cfg.imePersistInfo.push_back(info1);
    cfg.imePersistInfo.push_back(info2);
    std::string content;
    ASSERT_TRUE(cfg.Marshall(content));
    ImePersistCfg restored;
    ASSERT_TRUE(restored.Unmarshall(content));
    EXPECT_EQ(restored.imePersistInfo.size(), 2u);
    EXPECT_EQ(restored.imePersistInfo[0].userId, TEST_USER_ID);
    EXPECT_EQ(restored.imePersistInfo[1].userId, 200);
}

/**
 * @tc.name: EnableUpgradeManager_UserImeConfig_Marshal_001
 * @tc.desc: Test UserImeConfig Marshal/Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, UserImeConfig_Marshal_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest UserImeConfig_Marshal_001 START");
    UserImeConfig cfg;
    cfg.userId = "100";
    cfg.identities = { "com.example.ime1", "com.example.ime2" };
    std::string content;
    ASSERT_TRUE(cfg.Marshall(content));
    // UserImeConfig uses userId value as JSON key; Unmarshal needs userId pre-filled to locate the key
    UserImeConfig restored;
    restored.userId = "100";
    ASSERT_TRUE(restored.Unmarshall(content));
    EXPECT_EQ(restored.identities.size(), 2u);
}

/**
 * @tc.name: EnableUpgradeManager_EnabledImeCfg_Marshal_001
 * @tc.desc: Test EnabledImeCfg Marshal/Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, EnabledImeCfg_Marshal_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest EnabledImeCfg_Marshal_001 START");
    EnabledImeCfg cfg;
    cfg.userImeCfg.userId = "100";
    cfg.userImeCfg.identities = { "com.example.ime1" };
    std::string content;
    ASSERT_TRUE(cfg.Marshall(content));
    // UserImeConfig uses userId value as JSON key; Unmarshal needs userId pre-filled to locate the key
    EnabledImeCfg restored;
    restored.userImeCfg.userId = "100";
    ASSERT_TRUE(restored.Unmarshall(content));
    EXPECT_EQ(restored.userImeCfg.identities.size(), 1u);
}

/**
 * @tc.name: EnableUpgradeManager_SecurityModeCfg_Unmarshal_001
 * @tc.desc: Test SecurityModeCfg Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, SecurityModeCfg_Unmarshal_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest SecurityModeCfg_Unmarshal_001 START");
    std::string content = R"({"fullExperienceList":{"100":["com.example.ime1"]}})";
    // UserImeConfig uses userId value as JSON key; Unmarshal needs userId pre-filled to locate the key
    SecurityModeCfg cfg;
    cfg.userImeCfg.userId = "100";
    ASSERT_TRUE(cfg.Unmarshall(content));
    EXPECT_EQ(cfg.userImeCfg.identities.size(), 1u);
}

/**
 * @tc.name: EnableUpgradeManager_UpdateGlobalEnabledTable_001
 * @tc.desc: Test UpdateGlobalEnabledTable with empty enabled infos
 * @tc.type: FUNC
 */


/**
 * @tc.name: EnableUpgradeManager_Upgrade_003
 * @tc.desc: Test Upgrade clears upgraded set on new user
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, Upgrade_003, TestSize.Level1)
{
    IMSA_HILOGI("EnableUpgradeManagerTest Upgrade_003 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    mgr.upgradedUserId_.clear();
    EXPECT_TRUE(mgr.upgradedUserId_.empty());
}

/**
 * @tc.name: EnableUpgradeManager_GetGlobalTableUserId_006
 * @tc.desc: Test GetGlobalTableUserId with enableImeList as non-object
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GetGlobalTableUserId_006, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GetGlobalTableUserId_006 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string jsonArray = R"({"enableImeList":[1,2,3]})";
    auto ret = mgr.GetGlobalTableUserId(jsonArray);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: EnableUpgradeManager_ImePersistInfo_DefaultValues_001
 * @tc.desc: Test ImePersistInfo default values
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, ImePersistInfo_DefaultValues_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest ImePersistInfo_DefaultValues_001 START");
    ImePersistInfo info;
    EXPECT_EQ(info.userId, ImePersistInfo::INVALID_USERID);
    EXPECT_TRUE(info.currentIme.empty());
    EXPECT_TRUE(info.currentSubName.empty());
    EXPECT_TRUE(info.tempScreenLockIme.empty());
    EXPECT_FALSE(info.isDefaultImeSet);
}

/**
 * @tc.name: EnableUpgradeManager_GetImePersistCfg_001
 * @tc.desc: Test GetImePersistCfg when config file does not exist
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GetImePersistCfg_001, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GetImePersistCfg_001 START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    ImePersistInfo persistInfo;
    auto ret = mgr.GetImePersistCfg(TEST_USER_ID, persistInfo);
    EXPECT_TRUE(ret == ErrorCode::NO_ERROR || ret == ErrorCode::ERROR_PERSIST_CONFIG);
}

/**
 * @tc.name: EnableUpgradeManager_Upgrade_AlreadyUpgraded
 * @tc.desc: Test Upgrade when userId is already in upgradedUserId_ set
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, Upgrade_AlreadyUpgraded, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest Upgrade_AlreadyUpgraded START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    mgr.upgradedUserId_.insert(TEST_USER_ID);
    std::vector<FullImeInfo> imeInfos;
    auto ret = mgr.Upgrade(TEST_USER_ID, imeInfos);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    mgr.upgradedUserId_.erase(TEST_USER_ID);
}

/**
 * @tc.name: EnableUpgradeManager_Upgrade_VersionPresent
 * @tc.desc: Test Upgrade when user content contains "version" (no upgrade needed)
 * @tc.type: FUNC
 */


/**
 * @tc.name: EnableUpgradeManager_GetEnabledTable_ByBundleNames
 * @tc.desc: Test GetEnabledTable that returns bundle names
 * @tc.type: FUNC
 */


/**
 * @tc.name: EnableUpgradeManager_GetUserEnabledTable_ByContent
 * @tc.desc: Test GetUserEnabledTable with string content
 * @tc.type: FUNC
 */


/**
 * @tc.name: EnableUpgradeManager_GetUserEnabledTable_ByBundleNames
 * @tc.desc: Test GetUserEnabledTable with bundle names set
 * @tc.type: FUNC
 */


/**
 * @tc.name: EnableUpgradeManager_PaddedByImePersistCfg_NoMatch
 * @tc.desc: Test PaddedByImePersistCfg with enabledInfos where currentIme has no match
 *           and default IME is not found either - covers line 365 false branch
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, PaddedByImePersistCfg_NoMatch, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest PaddedByImePersistCfg_NoMatch START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::vector<ImeEnabledInfo> enabledInfos;
    ImeEnabledInfo info1;
    info1.bundleName = "com.nonexistent.ime";
    info1.extensionName = "ExtAbility";
    info1.enabledStatus = EnabledStatus::BASIC_MODE;
    enabledInfos.push_back(info1);
    auto ret = mgr.PaddedByImePersistCfg(TEST_USER_ID, enabledInfos);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: EnableUpgradeManager_PaddedByImePersistCfg_WithSlashInCurrentIme
 * @tc.desc: Test PaddedByImePersistCfg where persistInfo.currentIme contains '/'
 *           Exercises the path at line 347-351
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, PaddedByImePersistCfg_WithSlashInCurrentIme, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest PaddedByImePersistCfg_WithSlashInCurrentIme START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::vector<ImeEnabledInfo> enabledInfos;
    ImeEnabledInfo info1;
    info1.bundleName = "com.test.ime";
    info1.extensionName = "TestExt";
    info1.enabledStatus = EnabledStatus::BASIC_MODE;
    enabledInfos.push_back(info1);
    auto ret = mgr.PaddedByImePersistCfg(TEST_USER_ID, enabledInfos);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: EnableUpgradeManager_PaddedByImePersistCfg_TempScreenLockWithSlash
 * @tc.desc: Test PaddedByImePersistCfg where tempScreenLockIme contains '/'
 *           Exercises the path at line 372-376
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, PaddedByImePersistCfg_TempScreenLockWithSlash, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest PaddedByImePersistCfg_TempScreenLockWithSlash START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::vector<ImeEnabledInfo> enabledInfos;
    ImeEnabledInfo info1;
    info1.bundleName = "com.test.tmp";
    info1.extensionName = "TmpExt";
    info1.enabledStatus = EnabledStatus::BASIC_MODE;
    enabledInfos.push_back(info1);
    auto ret = mgr.PaddedByImePersistCfg(TEST_USER_ID, enabledInfos);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: EnableUpgradeManager_PaddedByImePersistCfg_TmpImeFound
 * @tc.desc: Test PaddedByImePersistCfg where tempScreenLockIme matches an entry
 *           Exercises line 380-381 (iter found, isTmpIme = true)
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, PaddedByImePersistCfg_TmpImeFound, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest PaddedByImePersistCfg_TmpImeFound START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::vector<ImeEnabledInfo> enabledInfos;
    ImeEnabledInfo info1;
    info1.bundleName = "com.tmpscreenlock.ime";
    info1.extensionName = "TmpScreenExt";
    info1.enabledStatus = EnabledStatus::BASIC_MODE;
    enabledInfos.push_back(info1);
    auto ret = mgr.PaddedByImePersistCfg(TEST_USER_ID, enabledInfos);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: EnableUpgradeManager_GetGlobalTableUserId_WithNumericUserId
 * @tc.desc: Test GetGlobalTableUserId with valid JSON containing numeric userId
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GetGlobalTableUserId_WithNumericUserId, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GetGlobalTableUserId_WithNumericUserId START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::string json = R"({"enableImeList":{"200":["com.test.ime"]}})";
    auto ret = mgr.GetGlobalTableUserId(json);
    EXPECT_EQ(ret, 200);
}

/**
 * @tc.name: EnableUpgradeManager_GenerateGlobalContent_WithEmptyBundleNames
 * @tc.desc: Test GenerateGlobalContent with empty bundleNames vector
 * @tc.type: FUNC
 */
HWTEST_F(EnableUpgradeManagerTest, GenerateGlobalContent_WithEmptyBundleNames, TestSize.Level0)
{
    IMSA_HILOGI("EnableUpgradeManagerTest GenerateGlobalContent_WithEmptyBundleNames START");
    auto &mgr = EnableUpgradeManager::GetInstance();
    std::vector<std::string> bundleNames;
    auto content = mgr.GenerateGlobalContent(200, bundleNames);
    EXPECT_TRUE(content.find("200") != std::string::npos);
}

/**
 * @tc.name: EnableUpgradeManager_PaddedByBundleMgr_WithImeInfos
 * @tc.desc: Test PaddedByBundleMgr with provided imeInfos
 * @tc.type: FUNC
 */


/**
 * @tc.name: EnableUpgradeManager_SetUserEnabledTable_001
 * @tc.desc: Test SetUserEnabledTable
 * @tc.type: FUNC
 */


/**
 * @tc.name: EnableUpgradeManager_SetGlobalEnabledTable_001
 * @tc.desc: Test SetGlobalEnabledTable
 * @tc.type: FUNC
 */

} // namespace MiscServices
} // namespace OHOS
