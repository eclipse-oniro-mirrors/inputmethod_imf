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
#define private public
#define protected public
#include "ime_info_inquirer.h"
#undef private

#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>
#include <fstream>

#include <string>
#include <vector>

#include "common_event_data.h"
#include "common_event_subscribe_info.h"
#include "global.h"
#include "im_common_event_manager.h"
#include "input_method_property.h"
#include "want.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
using namespace OHOS::AppExecFwk;

class ImeInfoInquirerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ImeInfoInquirerTest::SetUpTestCase(void)
{
    IMSA_HILOGI("ImeInfoInquirerTest::SetUpTestCase");
}

void ImeInfoInquirerTest::TearDownTestCase(void)
{
    IMSA_HILOGI("ImeInfoInquirerTest::TearDownTestCase");
}

void ImeInfoInquirerTest::SetUp(void)
{
    IMSA_HILOGI("ImeInfoInquirerTest::SetUp");
}

void ImeInfoInquirerTest::TearDown(void)
{
    IMSA_HILOGI("ImeInfoInquirerTest::TearDown");
}

static void CleanupTempDir(const std::string& filePath)
{
    if (filePath.empty()) {
        return;
    }
    size_t pos = filePath.rfind('/');
    if (pos != std::string::npos) {
        std::string dirPath = filePath.substr(0, pos);
        std::string cmd = "rm -rf " + dirPath;
        system(cmd.c_str());
    }
}

HWTEST_F(ImeInfoInquirerTest, GetResConfigFileLite_001, TestSize.Level0)
{
    IMSA_HILOGI("GetResConfigFileLite_001 start");
    ExtensionAbilityInfo extInfo;
    extInfo.metadata.clear();
    std::vector<std::string> profileInfos;
    std::string metadataName = "test_metadata";
    auto result = ImeInfoInquirer::GetInstance().GetResConfigFileLite(extInfo, metadataName, profileInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, GetResConfigFileLite_002, TestSize.Level0)
{
    IMSA_HILOGI("GetResConfigFileLite_002 start");
    ExtensionAbilityInfo extInfo;
    Metadata meta;
    meta.name = "test_metadata";
    meta.resource = "$profile:test.json";
    extInfo.metadata.push_back(meta);
    extInfo.hapPath = "";
    extInfo.resourcePath = "";
    std::vector<std::string> profileInfos;
    std::string metadataName = "test_metadata";
    auto result = ImeInfoInquirer::GetInstance().GetResConfigFileLite(extInfo, metadataName, profileInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, GetResConfigFileLite_003, TestSize.Level0)
{
    IMSA_HILOGI("GetResConfigFileLite_003 start");
    ExtensionAbilityInfo extInfo;
    Metadata meta;
    meta.name = "test_metadata";
    meta.resource = "$profile:test.json";
    extInfo.metadata.push_back(meta);
    extInfo.hapPath = "/data/test.hap";
    std::vector<std::string> profileInfos;
    std::string metadataName = "not_exist_metadata";
    auto result = ImeInfoInquirer::GetInstance().GetResConfigFileLite(extInfo, metadataName, profileInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, GetResConfigFileLite_004, TestSize.Level0)
{
    IMSA_HILOGI("GetResConfigFileLite_004 start");
    ExtensionAbilityInfo extInfo;
    Metadata meta;
    meta.name = "test_metadata";
    meta.resource = "$profile:test.json";
    extInfo.metadata.push_back(meta);
    extInfo.hapPath = "/data/test.hap";
    std::vector<std::string> profileInfos;
    std::string metadataName = "test_metadata";
    auto result = ImeInfoInquirer::GetInstance().GetResConfigFileLite(extInfo, metadataName, profileInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, GetResFromResMgr_001, TestSize.Level0)
{
    IMSA_HILOGI("GetResFromResMgr_001 start");
    std::string resName = "";
    std::shared_ptr<Global::Resource::ResourceManager> resMgr = nullptr;
    bool isCompressed = false;
    std::vector<std::string> profileInfos;
    auto result = ImeInfoInquirer::GetInstance().GetResFromResMgr(resName, resMgr, isCompressed, profileInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, GetResFromResMgr_002, TestSize.Level0)
{
    IMSA_HILOGI("GetResFromResMgr_002 start");
    std::string resName = "invalid_name";
    std::shared_ptr<Global::Resource::ResourceManager> resMgr = nullptr;
    bool isCompressed = false;
    std::vector<std::string> profileInfos;
    auto result = ImeInfoInquirer::GetInstance().GetResFromResMgr(resName, resMgr, isCompressed, profileInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, GetResFromResMgr_003, TestSize.Level0)
{
    IMSA_HILOGI("GetResFromResMgr_003 start");
    std::string resName = "$profile:";
    std::shared_ptr<Global::Resource::ResourceManager> resMgr = nullptr;
    bool isCompressed = false;
    std::vector<std::string> profileInfos;
    auto result = ImeInfoInquirer::GetInstance().GetResFromResMgr(resName, resMgr, isCompressed, profileInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, GetResFromResMgr_004, TestSize.Level0)
{
    IMSA_HILOGI("GetResFromResMgr_004 start");
    std::string resName = "$profile:my_config_file";
    std::shared_ptr<Global::Resource::ResourceManager> resMgr(Global::Resource::CreateResourceManager(false));
    bool isCompressed = false;
    std::vector<std::string> profileInfos;
    auto result = ImeInfoInquirer::GetInstance().GetResFromResMgr(resName, resMgr, isCompressed, profileInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, TransformFileToJsonString_001, TestSize.Level0)
{
    IMSA_HILOGI("TransformFileToJsonString_001 start");
    std::string resPath = "/non/existent/path/test.json";
    std::string profile;
    auto result = ImeInfoInquirer::GetInstance().TransformFileToJsonString(resPath, profile);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, TransformFileToJsonString_002, TestSize.Level0)
{
    IMSA_HILOGI("TransformFileToJsonString_002 start");
    std::string tmpDir = "/tmp/imeinfo_test002_XXXXXX";
    char *dirName = mkdtemp(tmpDir.data());
    if (dirName == nullptr) {
        tmpDir = "/data/local/tmp/imeinfo_test002_XXXXXX";
        dirName = mkdtemp(tmpDir.data());
    }
    ASSERT_NE(dirName, nullptr);
    std::string emptyFile = std::string(dirName) + "/empty.json";
    std::ofstream outFile(emptyFile);
    outFile.close();
    std::string profile;
    auto result = ImeInfoInquirer::GetInstance().TransformFileToJsonString(emptyFile, profile);
    EXPECT_FALSE(result);
    CleanupTempDir(emptyFile);
}

HWTEST_F(ImeInfoInquirerTest, TransformFileToJsonString_003, TestSize.Level0)
{
    IMSA_HILOGI("TransformFileToJsonString_003 start");
    std::string tmpDir = "/tmp/imeinfo_test003_XXXXXX";
    char *dirName = mkdtemp(tmpDir.data());
    if (dirName == nullptr) {
        tmpDir = "/data/local/tmp/imeinfo_test003_XXXXXX";
        dirName = mkdtemp(tmpDir.data());
    }
    ASSERT_NE(dirName, nullptr);
    std::string invalidFile = std::string(dirName) + "/invalid.json";
    std::ofstream outFile(invalidFile);
    outFile << "{ invalid json }";
    outFile.close();
    std::string profile;
    auto result = ImeInfoInquirer::GetInstance().TransformFileToJsonString(invalidFile, profile);
    EXPECT_FALSE(result);
    CleanupTempDir(invalidFile);
}

HWTEST_F(ImeInfoInquirerTest, TransformFileToJsonString_004, TestSize.Level0)
{
    IMSA_HILOGI("TransformFileToJsonString_004 start");
    std::string tmpDir = "/tmp/imeinfo_test004_XXXXXX";
    char *dirName = mkdtemp(tmpDir.data());
    if (dirName == nullptr) {
        tmpDir = "/data/local/tmp/imeinfo_test004_XXXXXX";
        dirName = mkdtemp(tmpDir.data());
    }
    ASSERT_NE(dirName, nullptr);
    std::string validFile = std::string(dirName) + "/valid.json";
    std::ofstream outFile(validFile);
    outFile << "{\"subtypes\": []}";
    outFile.close();
    std::string profile;
    auto result = ImeInfoInquirer::GetInstance().TransformFileToJsonString(validFile, profile);
    EXPECT_TRUE(result);
    EXPECT_FALSE(profile.empty());
    CleanupTempDir(validFile);
}

HWTEST_F(ImeInfoInquirerTest, GetResConfigFileLite_Without_Global_ResMgr, TestSize.Level0)
{
    IMSA_HILOGI("GetResConfigFileLite_Without_Global_ResMgr start");
    ExtensionAbilityInfo extInfo;
    std::vector<std::string> profileInfos;
    auto result = ImeInfoInquirer::GetInstance().GetResConfigFileLite(extInfo, "test", profileInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(ImeInfoInquirerTest, ParseSubtype_001, TestSize.Level0)
{
    IMSA_HILOGI("ParseSubtype_001 start");
    ExtensionAbilityInfo extInfo;
    extInfo.metadata.clear();
    std::vector<Subtype> subtypes;
    auto result = ImeInfoInquirer::GetInstance().ParseSubtype(extInfo, subtypes);
    EXPECT_EQ(result, ErrorCode::ERROR_BAD_PARAMETERS);
}

HWTEST_F(ImeInfoInquirerTest, ParseSubtype_002, TestSize.Level0)
{
    IMSA_HILOGI("ParseSubtype_002 start");
    ExtensionAbilityInfo extInfo;
    Metadata meta;
    meta.name = "not_extension_metadata";
    meta.resource = "$profile:test.json";
    extInfo.metadata.push_back(meta);
    std::vector<Subtype> subtypes;
    auto result = ImeInfoInquirer::GetInstance().ParseSubtype(extInfo, subtypes);
    EXPECT_EQ(result, ErrorCode::ERROR_BAD_PARAMETERS);
}

HWTEST_F(ImeInfoInquirerTest, ListInputMethodSubtype_001, TestSize.Level0)
{
    IMSA_HILOGI("ListInputMethodSubtype_001 start");
    int32_t userId = 100;
    ExtensionAbilityInfo extInfo;
    extInfo.bundleName = "com.test.ime";
    extInfo.moduleName = "entry";
    extInfo.metadata.clear();
    std::vector<SubProperty> subProps;
    auto result = ImeInfoInquirer::GetInstance().ListInputMethodSubtype(userId, extInfo, subProps);
    EXPECT_EQ(result, ErrorCode::ERROR_BAD_PARAMETERS);
}

HWTEST_F(ImeInfoInquirerTest, ListInputMethodSubtype_002, TestSize.Level0)
{
    IMSA_HILOGI("ListInputMethodSubtype_002 start");
    int32_t userId = 100;
    ExtensionAbilityInfo extInfo;
    extInfo.bundleName = "com.test.ime";
    extInfo.moduleName = "entry";
    Metadata meta;
    meta.name = "not_extension_metadata";
    extInfo.metadata.push_back(meta);
    std::vector<SubProperty> subProps;
    auto result = ImeInfoInquirer::GetInstance().ListInputMethodSubtype(userId, extInfo, subProps);
    EXPECT_EQ(result, ErrorCode::ERROR_BAD_PARAMETERS);
}

/**
 * @tc.name: IsSupportPcMode_001
 * @tc.desc: IsSupportPcMode returns false by default
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeInfoInquirerTest, IsSupportPcMode_001, TestSize.Level0)
{
    IMSA_HILOGI("IsSupportPcMode_001 start");
    auto &inquirer = ImeInfoInquirer::GetInstance();
    bool origValue = inquirer.productConfig_.isSupportPcMode;
    inquirer.productConfig_.isSupportPcMode = false;
    EXPECT_FALSE(inquirer.IsSupportPcMode());
    inquirer.productConfig_.isSupportPcMode = origValue;
}

/**
 * @tc.name: IsSupportPcMode_002
 * @tc.desc: IsSupportPcMode returns true when configured
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeInfoInquirerTest, IsSupportPcMode_002, TestSize.Level0)
{
    IMSA_HILOGI("IsSupportPcMode_002 start");
    auto &inquirer = ImeInfoInquirer::GetInstance();
    bool origValue = inquirer.productConfig_.isSupportPcMode;
    inquirer.productConfig_.isSupportPcMode = true;
    EXPECT_TRUE(inquirer.IsSupportPcMode());
    inquirer.productConfig_.isSupportPcMode = origValue;
}

/**
 * @tc.name: IsDisablePcModeImmersiveMode_001
 * @tc.desc: IsDisablePcModeImmersiveMode returns false by default
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeInfoInquirerTest, IsDisablePcModeImmersiveMode_001, TestSize.Level0)
{
    IMSA_HILOGI("IsDisablePcModeImmersiveMode_001 start");
    auto &inquirer = ImeInfoInquirer::GetInstance();
    bool origValue = inquirer.productConfig_.disablePcModeImmersiveMode;
    inquirer.productConfig_.disablePcModeImmersiveMode = false;
    EXPECT_FALSE(inquirer.IsDisablePcModeImmersiveMode());
    inquirer.productConfig_.disablePcModeImmersiveMode = origValue;
}

/**
 * @tc.name: IsDisablePcModeImmersiveMode_002
 * @tc.desc: IsDisablePcModeImmersiveMode returns true when configured
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeInfoInquirerTest, IsDisablePcModeImmersiveMode_002, TestSize.Level0)
{
    IMSA_HILOGI("IsDisablePcModeImmersiveMode_002 start");
    auto &inquirer = ImeInfoInquirer::GetInstance();
    bool origValue = inquirer.productConfig_.disablePcModeImmersiveMode;
    inquirer.productConfig_.disablePcModeImmersiveMode = true;
    EXPECT_TRUE(inquirer.IsDisablePcModeImmersiveMode());
    inquirer.productConfig_.disablePcModeImmersiveMode = origValue;
}

/**
 * @tc.name: IsPcMode_001
 * @tc.desc: IsPcMode returns false by default
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeInfoInquirerTest, IsPcMode_001, TestSize.Level0)
{
    IMSA_HILOGI("IsPcMode_001 start");
    auto &inquirer = ImeInfoInquirer::GetInstance();
    bool origValue = inquirer.IsPcMode();
    inquirer.SetPcMode(false);
    EXPECT_FALSE(inquirer.IsPcMode());
    inquirer.SetPcMode(origValue);
}

/**
 * @tc.name: SetPcMode_001
 * @tc.desc: SetPcMode sets isPcMode to true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeInfoInquirerTest, SetPcMode_001, TestSize.Level0)
{
    IMSA_HILOGI("SetPcMode_001 start");
    auto &inquirer = ImeInfoInquirer::GetInstance();
    bool origValue = inquirer.IsPcMode();
    inquirer.SetPcMode(true);
    EXPECT_TRUE(inquirer.IsPcMode());
    inquirer.SetPcMode(origValue);
}

/**
 * @tc.name: IsDisableImmersiveMode_001
 * @tc.desc: IsDisableImmersiveMode returns false/true based on systemConfig_.disableImmersiveMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeInfoInquirerTest, IsDisableImmersiveMode_001, TestSize.Level0)
{
    IMSA_HILOGI("IsDisableImmersiveMode_001 start");
    auto &inquirer = ImeInfoInquirer::GetInstance();
    bool origDisableImmersiveMode = inquirer.systemConfig_.disableImmersiveMode;
    inquirer.systemConfig_.disableImmersiveMode = false;
    EXPECT_FALSE(inquirer.IsDisableImmersiveMode());
    inquirer.systemConfig_.disableImmersiveMode = true;
    EXPECT_TRUE(inquirer.IsDisableImmersiveMode());
    inquirer.systemConfig_.disableImmersiveMode = origDisableImmersiveMode;
}

/**
 * @tc.name: OnHybridModeSwitch_001
 * @tc.desc: OnHybridModeSwitch with HybridMode::PC_MODE sets isPcMode to true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeInfoInquirerTest, OnHybridModeSwitch_001, TestSize.Level0)
{
    IMSA_HILOGI("OnHybridModeSwitch_001 start");
    auto &inquirer = ImeInfoInquirer::GetInstance();
    bool origPcMode = inquirer.IsPcMode();
    // Construct CommonEventData with HybridMode::PC_MODE
    EventFwk::MatchingSkills matchingSkills;
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriber = std::make_shared<ImCommonEventManager::EventSubscriber>(subscribeInfo);
    AAFwk::Want want;
    want.SetParam("targetMode", static_cast<int32_t>(HybridMode::PC_MODE));
    EventFwk::CommonEventData data;
    data.SetWant(want);
    subscriber->OnHybridModeSwitch(data);
    EXPECT_TRUE(inquirer.IsPcMode());
    inquirer.SetPcMode(origPcMode);
}

/**
 * @tc.name: OnHybridModeSwitch_002
 * @tc.desc: OnHybridModeSwitch with HybridMode::PHONE_MODE sets isPcMode to false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImeInfoInquirerTest, OnHybridModeSwitch_002, TestSize.Level0)
{
    IMSA_HILOGI("OnHybridModeSwitch_002 start");
    auto &inquirer = ImeInfoInquirer::GetInstance();
    bool origPcMode = inquirer.IsPcMode();
    inquirer.SetPcMode(true);
    EventFwk::MatchingSkills matchingSkills;
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriber = std::make_shared<ImCommonEventManager::EventSubscriber>(subscribeInfo);
    AAFwk::Want want;
    want.SetParam("targetMode", static_cast<int32_t>(HybridMode::PHONE_MODE));
    EventFwk::CommonEventData data;
    data.SetWant(want);
    subscriber->OnHybridModeSwitch(data);
    EXPECT_FALSE(inquirer.IsPcMode());
    inquirer.SetPcMode(origPcMode);
}
} // namespace MiscServices
} // namespace OHOS
