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

#include "global.h"
#include "input_method_property.h"

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

} // namespace MiscServices
} // namespace OHOS
