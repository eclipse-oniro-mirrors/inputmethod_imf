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
#include "imf_hook_manager.h"
#include "imf_module_manager.h"
#undef private
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "global.h"
#include "ime_enabled_info_manager.h"
#include "ime_info_inquirer.h"

using namespace testing::ext;
namespace OHOS {
namespace MiscServices {
constexpr int32_t HOOK_EXEC_RESULT_SUCCESS = 0;
constexpr int32_t HOOK_EXEC_RESULT_FAILED = -1;
class ImfExtMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ImfExtMockTest::SetUpTestCase(void)
{
    IMSA_HILOGI("ImfExtMockTest::SetUpTestCase");
}

void ImfExtMockTest::TearDownTestCase(void)
{
    IMSA_HILOGI("ImfExtMockTest::TearDownTestCase");
}

void ImfExtMockTest::SetUp(void)
{
    IMSA_HILOGI("ImfExtMockTest::SetUp");
}

void ImfExtMockTest::TearDown(void)
{
    IMSA_HILOGI("ImfExtMockTest::TearDown");
}

/**
 * @tc.name: ImfHookMgr_ExecuteCurrentImeInfoReportHook
 * @tc.desc: ImfHookMgr_ExecuteCurrentImeInfoReportHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImfExtMockTest, ImfHookMgr_ExecuteCurrentImeInfoReportHook, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodPrivateMemberTest::ImfHookMgr_ExecuteCurrentImeInfoReportHook start.");
    std::string bundleName = "bundleName";
    std::string versionName = "versionName";
    int32_t securityMode = 1;
    int32_t userId = 10;
    int64_t timeStampMs = 0;
    int64_t timeStampMs1 = 10;
    int64_t timeStampMs2 = 1 * 60 * 60 * 1000 + 1;
    bool needSetConfig = true;
    // NeedReport() is false:report info is same,  report interval is not more than one hour
    ImfHookMgr::GetInstance().imeReportedInfo_ = { bundleName, versionName, securityMode, needSetConfig, timeStampMs };
    ImeInfoInquirer::GetInstance().SetImeVersionName(versionName);
    ImeEnabledInfoManager::GetInstance().SetEnabledState(static_cast<EnabledStatus>(securityMode));
    auto ret = ImfHookMgr::GetInstance().ExecuteCurrentImeInfoReportHook(userId, bundleName, timeStampMs1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    // NeedReport() is true:info != imeReportedInfo_
    // ExecuteHook() failed:scan failed
    ImfHookMgr::GetInstance().imeReportedInfo_ = {};
    ImfModuleMgr::GetInstance().modules_.clear();
    ImfHookMgr::GetInstance().needSetConfig_ = true;
    SetModulesCnt(0);
    ret = ImfHookMgr::GetInstance().ExecuteCurrentImeInfoReportHook(userId, bundleName, timeStampMs1);
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_ILLEGAL_STATE);
    EXPECT_TRUE(ImfHookMgr::GetInstance().needSetConfig_);
    EXPECT_NE(ImfHookMgr::GetInstance().imeReportedInfo_.timeStampMs, timeStampMs1);

    // NeedReport() is true:info != imeReportedInfo_
    // ExecuteHook() succeed, needSetConfig is false
    ImfHookMgr::GetInstance().imeReportedInfo_ = {};
    ImfHookMgr::GetInstance().needSetConfig_ = false;
    ImfModuleMgr::GetInstance().modules_.insert({ ImfModuleMgr::IMF_EXT_MODULE_PATH, nullptr });
    SetHookMgrExecuteRet(HOOK_EXEC_RESULT_SUCCESS);
    ret = ImfHookMgr::GetInstance().ExecuteCurrentImeInfoReportHook(userId, bundleName, timeStampMs1);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(ImfHookMgr::GetInstance().imeReportedInfo_.timeStampMs, timeStampMs1);

    // NeedReport() is true:report info is same,  but report interval is more than one hour
    // ExecuteHook() succeed, needSetConfig is true
    ImfHookMgr::GetInstance().imeReportedInfo_ = { bundleName, versionName, securityMode, needSetConfig, timeStampMs };
    ImfHookMgr::GetInstance().needSetConfig_ = true;
    ImeInfoInquirer::GetInstance().SetImeVersionName(versionName);
    ImeEnabledInfoManager::GetInstance().SetEnabledState(static_cast<EnabledStatus>(securityMode));
    ImfModuleMgr::GetInstance().modules_.insert({ ImfModuleMgr::IMF_EXT_MODULE_PATH, nullptr });
    SetHookMgrExecuteRet(HOOK_EXEC_RESULT_SUCCESS);
    ret = ImfHookMgr::GetInstance().ExecuteCurrentImeInfoReportHook(userId, bundleName, timeStampMs2);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_FALSE(ImfHookMgr::GetInstance().needSetConfig_);
    EXPECT_EQ(ImfHookMgr::GetInstance().imeReportedInfo_.timeStampMs, timeStampMs2);
}

/**
 * @tc.name: ImfHookMgr_ExecuteHook
 * @tc.desc: ImfHookMgr_ExecuteHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImfExtMockTest, ImfHookMgr_ExecuteHook, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodPrivateMemberTest::ImfHookMgr_ExecuteHook start.");
    // scan failed
    ImfModuleMgr::GetInstance().modules_.clear();
    SetModulesCnt(0);
    auto ret = ImfHookMgr::GetInstance().ExecuteHook(ImfHookStage::REPORT_CURRENT_IME_INFO, nullptr, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_ILLEGAL_STATE);

    // scan succeed, HookMgrExecute failed
    ImfModuleMgr::GetInstance().modules_.insert({ ImfModuleMgr::IMF_EXT_MODULE_PATH, nullptr });
    SetHookMgrExecuteRet(HOOK_EXEC_RESULT_FAILED);
    ret = ImfHookMgr::GetInstance().ExecuteHook(ImfHookStage::REPORT_CURRENT_IME_INFO, nullptr, nullptr);
    EXPECT_EQ(ret, ErrorCode::ERROR_OPERATION_NOT_ALLOWED);

    // scan succeed, HookMgrExecute succeed
    ImfModuleMgr::GetInstance().modules_.insert({ ImfModuleMgr::IMF_EXT_MODULE_PATH, nullptr });
    SetHookMgrExecuteRet(HOOK_EXEC_RESULT_SUCCESS);
    ret = ImfHookMgr::GetInstance().ExecuteHook(ImfHookStage::REPORT_CURRENT_IME_INFO, nullptr, nullptr);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: ImfModuleMgr_Scan
 * @tc.desc: ImfModuleMgr_Scan
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImfExtMockTest, ImfModuleMgr_Scan, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodPrivateMemberTest::ImfModuleMgr_Scan start.");
    // HasScan is true
    ImfModuleMgr::GetInstance().modules_.insert({ ImfModuleMgr::IMF_EXT_MODULE_PATH, nullptr });
    auto ret = ImfModuleMgr::GetInstance().Scan(ImfModuleMgr::IMF_EXT_MODULE_PATH);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    // HasScan is false, ModuleMgrGetCnt is 0
    ImfModuleMgr::GetInstance().modules_.clear();
    SetModulesCnt(0);
    ret = ImfModuleMgr::GetInstance().Scan(ImfModuleMgr::IMF_EXT_MODULE_PATH);
    EXPECT_EQ(ret, ErrorCode::ERROR_EX_ILLEGAL_STATE);

    // HasScan is false, ModuleMgrGetCnt is 1
    ImfModuleMgr::GetInstance().modules_.clear();
    SetModulesCnt(1);
    ret = ImfModuleMgr::GetInstance().Scan(ImfModuleMgr::IMF_EXT_MODULE_PATH);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(ImfModuleMgr::GetInstance().modules_.find(ImfModuleMgr::IMF_EXT_MODULE_PATH)
                != ImfModuleMgr::GetInstance().modules_.end());
}

/**
 * @tc.name: ImfModuleMgr_Destroy
 * @tc.desc: ImfModuleMgr_Destroy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ImfExtMockTest, ImfModuleMgr_Destroy, TestSize.Level1)
{
    IMSA_HILOGI("InputMethodPrivateMemberTest::ImfModuleMgr_Destroy start.");
    // not contain
    ImfModuleMgr::GetInstance().modules_.clear();
    ImfModuleMgr::GetInstance().Destroy(ImfModuleMgr::IMF_EXT_MODULE_PATH);

    // contain
    ImfModuleMgr::GetInstance().modules_.insert({ ImfModuleMgr::IMF_EXT_MODULE_PATH, nullptr });
    ImfModuleMgr::GetInstance().Destroy(ImfModuleMgr::IMF_EXT_MODULE_PATH);
    EXPECT_TRUE(ImfModuleMgr::GetInstance().modules_.empty());
}

} // namespace MiscServices
} // namespace OHOS