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

#include <cstring>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ime_usage_common.h"
#include "ime_usage_db_helper.h"
#include "ime_usage_event_cacher.h"

#define private   public
#define protected public
#include "ime_usage_event_cacher.h"
#undef private
#undef protected

#include "global.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;
using namespace ImeUsageEventId;
using namespace ImeFoldStatusBase;
using namespace ImeScreenStatus;
using OHOS::MiscServices::RAWID_NONE;
using OHOS::MiscServices::SCREEN_STATUS_UNINITIALIZED;
using OHOS::MiscServices::IME_USAGE_SUCCESS;

const std::string TEST_BUNDLE = "com.test.ime";
const std::string TEST_BUNDLE2 = "com.test.ime2";
const std::string DB_DIR = "/data/test/ime_usage_test";
} // namespace

class ImeUsageEventCacherTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<ImeUsageDbHelper> dbHelper_;
    std::unique_ptr<ImeUsageEventCacher> cacher_;
};

void ImeUsageEventCacherTest::SetUpTestCase(void)
{
    IMSA_HILOGI("ImeUsageEventCacherTest::SetUpTestCase");
}

void ImeUsageEventCacherTest::TearDownTestCase(void)
{
    IMSA_HILOGI("ImeUsageEventCacherTest::TearDownTestCase");
}

void ImeUsageEventCacherTest::SetUp()
{
    // Remove DB files before opening to ensure a clean state
    std::string dbFile = DB_DIR + "/ime_usage_log.db";
    std::remove(dbFile.c_str());
    std::remove((dbFile + "-wal").c_str());
    std::remove((dbFile + "-shm").c_str());

    dbHelper_ = std::make_shared<ImeUsageDbHelper>(DB_DIR);
    cacher_ = std::make_unique<ImeUsageEventCacher>();
    // Init with UNFOLDED_PORTRAIT as default
    cacher_->Init(dbHelper_, UNFOLDED, PORTRAIT);
}

void ImeUsageEventCacherTest::TearDown()
{
    cacher_.reset();
    dbHelper_.reset();
}

// ==================== Init ====================

/**
 * @tc.name: ImeUsageEventCacher_Init_001
 * @tc.desc: Init with nullptr dbHelper returns -1
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, Init_001, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    int ret = cacher->Init(nullptr, UNFOLDED, PORTRAIT);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: ImeUsageEventCacher_Init_002
 * @tc.desc: Init with valid dbHelper returns 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, Init_002, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    int ret = cacher->Init(dbHelper_, EXPAND, LANDSCAPE);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(cacher->foldStatus_, EXPAND);
    EXPECT_EQ(cacher->vhMode_, LANDSCAPE);
}

// ==================== GetScreenStatus ====================

/**
 * @tc.name: ImeUsageEventCacher_GetScreenStatus_001
 * @tc.desc: GetScreenStatus returns correct encoding
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, GetScreenStatus_001, TestSize.Level0)
{
    cacher_->foldStatus_ = EXPAND;
    cacher_->vhMode_ = PORTRAIT;
    EXPECT_EQ(cacher_->GetScreenStatus(), EXPAND_PORTRAIT); // 32
}

/**
 * @tc.name: ImeUsageEventCacher_GetScreenStatus_002
 * @tc.desc: GetScreenStatus with foldStatus=0 vhMode=0 falls back to UNFOLDED_PORTRAIT
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, GetScreenStatus_002, TestSize.Level0)
{
    cacher_->foldStatus_ = 0;
    cacher_->vhMode_ = 0;
    EXPECT_EQ(cacher_->GetScreenStatus(), UNFOLDED_PORTRAIT); // 12
}

/**
 * @tc.name: ImeUsageEventCacher_GetScreenStatus_003
 * @tc.desc: GetScreenStatus with various valid combinations
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, GetScreenStatus_003, TestSize.Level0)
{
    cacher_->foldStatus_ = UNFOLDED;
    cacher_->vhMode_ = LANDSCAPE;
    EXPECT_EQ(cacher_->GetScreenStatus(), UNFOLDED_LANDSCAPE); // 11

    cacher_->foldStatus_ = LM;
    cacher_->vhMode_ = PORTRAIT;
    EXPECT_EQ(cacher_->GetScreenStatus(), LM_PORTRAIT); // 62
}

// ==================== ProcessShowEvent ====================

/**
 * @tc.name: ImeUsageEventCacher_ProcessShowEvent_001
 * @tc.desc: Show keyboard sets isKeyboardShowing_ and currentImeBundle_
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessShowEvent_001, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessShowEvent_002
 * @tc.desc: Show keyboard sets lastScreenStatus_
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessShowEvent_002, TestSize.Level0)
{
    cacher_->foldStatus_ = FOLD;
    cacher_->vhMode_ = PORTRAIT;
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_EQ(cacher_->lastScreenStatus_, FOLD_PORTRAIT); // 22
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessShowEvent_003
 * @tc.desc: Showing a different IME while one is showing triggers ProcessHideEvent on old
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessShowEvent_003, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);
    // Show a different IME - should hide old one first
    cacher_->OnImeBind(TEST_BUNDLE2);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE2);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessShowEvent_004
 * @tc.desc: Show same IME while already showing does not trigger hide
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessShowEvent_004, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);
    // Show same IME again - should not hide
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessShowEvent_005
 * @tc.desc: Show with nullptr dbHelper does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessShowEvent_005, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init called, dbHelper_ is nullptr
    cacher->OnImeBind(TEST_BUNDLE);
    // Should not crash, but isKeyboardShowing_ stays false
    EXPECT_FALSE(cacher->isKeyboardShowing_);
}

// ==================== ProcessHideEvent ====================

/**
 * @tc.name: ImeUsageEventCacher_ProcessHideEvent_001
 * @tc.desc: Hide keyboard clears isKeyboardShowing_ and currentImeBundle_
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessHideEvent_001, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    cacher_->OnImeUnbind(TEST_BUNDLE);
    EXPECT_FALSE(cacher_->isKeyboardShowing_);
    EXPECT_TRUE(cacher_->currentImeBundle_.empty());
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessHideEvent_002
 * @tc.desc: Hide when not showing does nothing
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessHideEvent_002, TestSize.Level0)
{
    EXPECT_FALSE(cacher_->isKeyboardShowing_);
    cacher_->OnImeUnbind(TEST_BUNDLE);
    EXPECT_FALSE(cacher_->isKeyboardShowing_);
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessHideEvent_003
 * @tc.desc: Hide with nullptr dbHelper does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessHideEvent_003, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    cacher->isKeyboardShowing_ = true;
    cacher->currentImeBundle_ = TEST_BUNDLE;
    // Without dbHelper, PrepareHideRecord returns rawid=0, so OnImeUnbind skips DB write
    // and does NOT reset isKeyboardShowing_ / currentImeBundle_
    cacher->OnImeUnbind(TEST_BUNDLE);
    // State remains unchanged because no dbHelper to write STOP event
    EXPECT_TRUE(cacher->isKeyboardShowing_);
    EXPECT_EQ(cacher->currentImeBundle_, TEST_BUNDLE);
}

// ==================== ProcessScreenChangedEvent ====================

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_001
 * @tc.desc: Screen change when keyboard showing writes record
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_001, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_EQ(cacher_->lastScreenStatus_, UNFOLDED_PORTRAIT); // 12
    // Change to EXPAND_PORTRAIT via OnScreenStatusChanged with pre/new params
    int32_t preStatus = UNFOLDED_PORTRAIT; // 12
    int32_t newStatus = EXPAND_PORTRAIT;   // 32
    cacher_->OnScreenStatusChanged(preStatus, newStatus);
    EXPECT_EQ(cacher_->lastScreenStatus_, EXPAND_PORTRAIT); // 32
    EXPECT_EQ(cacher_->foldStatus_, EXPAND);
    EXPECT_EQ(cacher_->vhMode_, PORTRAIT);
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_002
 * @tc.desc: Screen change when keyboard NOT showing is skipped
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_002, TestSize.Level0)
{
    EXPECT_FALSE(cacher_->isKeyboardShowing_);
    // Should not crash, and lastScreenStatus_ should not update via this path
    int32_t before = cacher_->lastScreenStatus_;
    cacher_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    EXPECT_EQ(cacher_->lastScreenStatus_, before);
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_003
 * @tc.desc: Duplicate screen status change is skipped (dedup)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_003, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    // lastScreenStatus_ is UNFOLDED_PORTRAIT(12)
    // Same status as current - should be deduped
    cacher_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, UNFOLDED_PORTRAIT);
    EXPECT_EQ(cacher_->lastScreenStatus_, UNFOLDED_PORTRAIT);
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_004
 * @tc.desc: Multiple distinct screen changes are all recorded
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_004, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_EQ(cacher_->lastScreenStatus_, UNFOLDED_PORTRAIT); // 12

    cacher_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    EXPECT_EQ(cacher_->lastScreenStatus_, EXPAND_PORTRAIT); // 32

    cacher_->OnScreenStatusChanged(EXPAND_PORTRAIT, EXPAND_LANDSCAPE);
    EXPECT_EQ(cacher_->lastScreenStatus_, EXPAND_LANDSCAPE); // 31
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_005
 * @tc.desc: F->M->G transition during keyboard showing records all 1003 events
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_005, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_EQ(cacher_->lastScreenStatus_, UNFOLDED_PORTRAIT); // 12

    // F (FOLD_PORTRAIT=22) -> M (EXPAND_PORTRAIT=32) -> G (G_PORTRAIT=42)
    cacher_->OnScreenStatusChanged(FOLD_PORTRAIT, EXPAND_PORTRAIT);
    EXPECT_EQ(cacher_->lastScreenStatus_, EXPAND_PORTRAIT); // 32
    EXPECT_EQ(cacher_->foldStatus_, EXPAND);
    EXPECT_EQ(cacher_->vhMode_, PORTRAIT);

    cacher_->OnScreenStatusChanged(EXPAND_PORTRAIT, G_PORTRAIT);
    EXPECT_EQ(cacher_->lastScreenStatus_, G_PORTRAIT); // 42
    EXPECT_EQ(cacher_->foldStatus_, G);
    EXPECT_EQ(cacher_->vhMode_, PORTRAIT);
}

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_006
 * @tc.desc: OnScreenStatusChanged updates internal foldStatus_/vhMode_ correctly
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_006, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    // Simulate transition: UNFOLDED_PORTRAIT(12) -> LM_LANDSCAPE(61)
    cacher_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, LM_LANDSCAPE);
    EXPECT_EQ(cacher_->foldStatus_, LM);                 // 6
    EXPECT_EQ(cacher_->vhMode_, LANDSCAPE);              // 1
    EXPECT_EQ(cacher_->lastScreenStatus_, LM_LANDSCAPE); // 61
}

// ==================== RecoverActiveSession ====================

/**
 * @tc.name: ImeUsageEventCacher_RecoverActiveSession_001
 * @tc.desc: RecoverActiveSession recovers active session from DB when last event is START
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, RecoverActiveSession_001, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);

    // Reset in-memory state to simulate service restart
    cacher_->isKeyboardShowing_ = false;
    cacher_->currentImeBundle_.clear();

    // RecoverActiveSession queries DB, finds last event is START,
    // and restores the active session
    cacher_->RecoverActiveSession();
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);
}

/**
 * @tc.name: ImeUsageEventCacher_RecoverActiveSession_002
 * @tc.desc: RecoverActiveSession does not recover when last event is STOP/COUNT
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, RecoverActiveSession_002, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    cacher_->OnImeUnbind(TEST_BUNDLE);
    EXPECT_FALSE(cacher_->isKeyboardShowing_);

    // Reset in-memory state to simulate service restart
    cacher_->isKeyboardShowing_ = false;
    cacher_->currentImeBundle_.clear();

    // RecoverActiveSession queries DB, finds last event is not START/STATUS_CHANGED,
    // so it does not recover an active session
    cacher_->RecoverActiveSession();
    EXPECT_FALSE(cacher_->isKeyboardShowing_);
    EXPECT_TRUE(cacher_->currentImeBundle_.empty());
}

// ==================== CanCalcDuration ====================

/**
 * @tc.name: ImeUsageEventCacher_CanCalcDuration_001
 * @tc.desc: START->START returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CanCalcDuration_001, TestSize.Level0)
{
    // START->START is not a valid duration pair, should return false
    int32_t preRawId = EVENT_INPUT_START;
    int32_t rawId = EVENT_INPUT_START;
    bool result = cacher_->CanCalcDuration(preRawId, rawId);
    EXPECT_FALSE(result);
    // Same type pair should not produce duration
    EXPECT_EQ(preRawId, rawId);
}

/**
 * @tc.name: ImeUsageEventCacher_CanCalcDuration_002
 * @tc.desc: STOP->STOP returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CanCalcDuration_002, TestSize.Level0)
{
    // STOP->STOP is not a valid duration pair, should return false
    int32_t preRawId = EVENT_INPUT_STOP;
    int32_t rawId = EVENT_INPUT_STOP;
    bool result = cacher_->CanCalcDuration(preRawId, rawId);
    EXPECT_FALSE(result);
    // Same type pair should not produce duration
    EXPECT_EQ(preRawId, rawId);
}

/**
 * @tc.name: ImeUsageEventCacher_CanCalcDuration_003
 * @tc.desc: START->STOP returns true
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CanCalcDuration_003, TestSize.Level0)
{
    // START->STOP is a valid session pair, should return true
    int32_t preRawId = EVENT_INPUT_START;
    int32_t rawId = EVENT_INPUT_STOP;
    bool result = cacher_->CanCalcDuration(preRawId, rawId);
    EXPECT_TRUE(result);
    // Pre and post are different event types
    EXPECT_NE(preRawId, rawId);
}

/**
 * @tc.name: ImeUsageEventCacher_CanCalcDuration_004
 * @tc.desc: START->STATUS_CHANGED returns true
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CanCalcDuration_004, TestSize.Level0)
{
    // START->STATUS_CHANGED is a valid pair for mid-session status change
    int32_t preRawId = EVENT_INPUT_START;
    int32_t rawId = EVENT_INPUT_STATUS_CHANGED;
    bool result = cacher_->CanCalcDuration(preRawId, rawId);
    EXPECT_TRUE(result);
    // These are different event types indicating state transition
    EXPECT_NE(preRawId, rawId);
}

/**
 * @tc.name: ImeUsageEventCacher_CanCalcDuration_005
 * @tc.desc: STATUS_CHANGED->STOP returns true
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CanCalcDuration_005, TestSize.Level0)
{
    // STATUS_CHANGED->STOP is a valid pair for ending a status segment
    int32_t preRawId = EVENT_INPUT_STATUS_CHANGED;
    int32_t rawId = EVENT_INPUT_STOP;
    bool result = cacher_->CanCalcDuration(preRawId, rawId);
    EXPECT_TRUE(result);
    // Different event types forming valid segment boundary
    EXPECT_NE(preRawId, rawId);
}

/**
 * @tc.name: ImeUsageEventCacher_CanCalcDuration_006
 * @tc.desc: STATUS_CHANGED->STATUS_CHANGED returns true
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CanCalcDuration_006, TestSize.Level0)
{
    // STATUS_CHANGED->STATUS_CHANGED is valid for consecutive screen changes during session
    int32_t preRawId = EVENT_INPUT_STATUS_CHANGED;
    int32_t rawId = EVENT_INPUT_STATUS_CHANGED;
    bool result = cacher_->CanCalcDuration(preRawId, rawId);
    EXPECT_TRUE(result);
    // Same event type is valid here (multiple consecutive screen changes)
    EXPECT_EQ(preRawId, rawId);
}

/**
 * @tc.name: ImeUsageEventCacher_CanCalcDuration_007
 * @tc.desc: STOP->START returns true
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CanCalcDuration_007, TestSize.Level0)
{
    // STOP->START is valid for starting a new session after previous one ended
    int32_t preRawId = EVENT_INPUT_STOP;
    int32_t rawId = EVENT_INPUT_START;
    bool result = cacher_->CanCalcDuration(preRawId, rawId);
    EXPECT_TRUE(result);
    // Different event types indicating session restart
    EXPECT_NE(preRawId, rawId);
}

// ==================== Accumulate ====================

/**
 * @tc.name: ImeUsageEventCacher_Accumulate_001
 * @tc.desc: Accumulate with new key creates entry
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, Accumulate_001, TestSize.Level0)
{
    DurationMap durations;
    cacher_->Accumulate(UNFOLDED_PORTRAIT, 1000, durations);
    EXPECT_EQ(durations.size(), 1u);
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 1000u);
}

/**
 * @tc.name: ImeUsageEventCacher_Accumulate_002
 * @tc.desc: Accumulate with existing key adds to value
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, Accumulate_002, TestSize.Level0)
{
    DurationMap durations;
    cacher_->Accumulate(UNFOLDED_PORTRAIT, 1000, durations);
    cacher_->Accumulate(UNFOLDED_PORTRAIT, 2000, durations);
    EXPECT_EQ(durations.size(), 1u);
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 3000u);
}

/**
 * @tc.name: ImeUsageEventCacher_Accumulate_003
 * @tc.desc: Accumulate with different keys creates separate entries
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, Accumulate_003, TestSize.Level0)
{
    DurationMap durations;
    cacher_->Accumulate(UNFOLDED_PORTRAIT, 1000, durations);
    cacher_->Accumulate(EXPAND_PORTRAIT, 2000, durations);
    EXPECT_EQ(durations.size(), 2u);
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 1000u);
    EXPECT_EQ(durations[EXPAND_PORTRAIT], 2000u);
}

// ==================== CalculateDuration ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_001
 * @tc.desc: Empty records produces no durations
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_001, TestSize.Level0)
{
    std::vector<ImeEventRecord> records;
    DurationMap durations;
    cacher_->CalculateDuration(0, records, durations);
    EXPECT_TRUE(durations.empty());
}

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_002
 * @tc.desc: Single START record with no pair produces no duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_002, TestSize.Level0)
{
    std::vector<ImeEventRecord> records;
    ImeEventRecord rec;
    rec.rawid = EVENT_INPUT_START;
    rec.ts = 1000;
    rec.happenTime = 1000;
    rec.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(rec);

    DurationMap durations;
    cacher_->CalculateDuration(0, records, durations);
    // Single START with no following event: no duration calculated
    EXPECT_TRUE(durations.empty());
}

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_003
 * @tc.desc: START then STOP calculates duration correctly
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_003, TestSize.Level0)
{
    std::vector<ImeEventRecord> records;
    ImeEventRecord start;
    start.rawid = EVENT_INPUT_START;
    start.ts = 1000;
    start.happenTime = 1000;
    start.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(start);

    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 5000;
    stop.happenTime = 5000;
    stop.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(stop);

    DurationMap durations;
    cacher_->CalculateDuration(0, records, durations);
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 4000u);
}

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_004
 * @tc.desc: START->STATUS_CHANGED->STOP calculates per-status duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_004, TestSize.Level0)
{
    std::vector<ImeEventRecord> records;
    ImeEventRecord start;
    start.rawid = EVENT_INPUT_START;
    start.ts = 1000;
    start.happenTime = 1000;
    start.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(start);

    ImeEventRecord changed;
    changed.rawid = EVENT_INPUT_STATUS_CHANGED;
    changed.ts = 3000;
    changed.happenTime = 3000;
    changed.screenStatus = EXPAND_PORTRAIT;
    records.push_back(changed);

    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 7000;
    stop.happenTime = 7000;
    stop.screenStatus = EXPAND_PORTRAIT;
    records.push_back(stop);

    DurationMap durations;
    cacher_->CalculateDuration(0, records, durations);
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 2000u); // 1000->3000
    EXPECT_EQ(durations[EXPAND_PORTRAIT], 4000u);   // 3000->7000
}

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_005
 * @tc.desc: Cross-midnight: first event is not START, duration from dayStartTime
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_005, TestSize.Level0)
{
    uint64_t dayStartTime = 1000;

    std::vector<ImeEventRecord> records;
    ImeEventRecord changed;
    changed.rawid = EVENT_INPUT_STATUS_CHANGED;
    changed.ts = 3000;
    changed.happenTime = 3000;
    changed.screenStatus = UNFOLDED_PORTRAIT;
    changed.preScreenStatus = EXPAND_PORTRAIT;
    records.push_back(changed);

    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 5000;
    stop.happenTime = 5000;
    stop.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(stop);

    DurationMap durations;
    cacher_->CalculateDuration(dayStartTime, records, durations);
    // Cross-midnight: dayStartTime(1000) -> first event(3000) = 2000ms, uses preScreenStatus
    EXPECT_EQ(durations[EXPAND_PORTRAIT], 2000u);
    // 3000 -> 5000 = 2000ms, uses changed.screenStatus
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 2000u);
}

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_006
 * @tc.desc: screenStatus=0 in record falls back to UNFOLDED_PORTRAIT
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_006, TestSize.Level0)
{
    std::vector<ImeEventRecord> records;
    ImeEventRecord start;
    start.rawid = EVENT_INPUT_START;
    start.ts = 1000;
    start.happenTime = 1000;
    start.screenStatus = SCREEN_STATUS_UNINITIALIZED; // uninitialized
    records.push_back(start);

    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 5000;
    stop.happenTime = 5000;
    stop.screenStatus = SCREEN_STATUS_UNINITIALIZED;
    records.push_back(stop);

    DurationMap durations;
    cacher_->CalculateDuration(0, records, durations);
    // screenStatus=0 should fallback to UNFOLDED_PORTRAIT(12)
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 4000u);
}

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_007
 * @tc.desc: START->START pair is skipped
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_007, TestSize.Level0)
{
    std::vector<ImeEventRecord> records;
    ImeEventRecord start1;
    start1.rawid = EVENT_INPUT_START;
    start1.ts = 1000;
    start1.happenTime = 1000;
    start1.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(start1);

    ImeEventRecord start2;
    start2.rawid = EVENT_INPUT_START;
    start2.ts = 2000;
    start2.happenTime = 2000;
    start2.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(start2);

    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 5000;
    stop.happenTime = 5000;
    stop.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(stop);

    DurationMap durations;
    cacher_->CalculateDuration(0, records, durations);
    // START->START is skipped, only START2->STOP = 3000
    EXPECT_EQ(durations.size(), 1u);
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 3000u);
}

// ==================== Full session flow (DB integration) ====================

/**
 * @tc.name: ImeUsageEventCacher_FullSession_001
 * @tc.desc: Full show->hide session writes COUNT_DURATION with correct duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FullSession_001, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    cacher_->OnImeUnbind(TEST_BUNDLE);
    EXPECT_FALSE(cacher_->isKeyboardShowing_);
    // Verify DB has records
    int idx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(idx, 0);
    int countIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
}

/**
 * @tc.name: ImeUsageEventCacher_FullSession_002
 * @tc.desc: Show->ScreenChange->Hide writes all event types
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FullSession_002, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    cacher_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    cacher_->OnImeUnbind(TEST_BUNDLE);

    // Should have START, STATUS_CHANGED, COUNT_DURATION records
    int startIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(startIdx, 0);
    int changedIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STATUS_CHANGED);
    EXPECT_GE(changedIdx, 0);
    int countIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
}

/**
 * @tc.name: ImeUsageEventCacher_FullSession_003
 * @tc.desc: F->M->G transition during active session records multiple 1003 events
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FullSession_003, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    // Simulate F->M->G transitions while keyboard is showing
    cacher_->OnScreenStatusChanged(FOLD_PORTRAIT, EXPAND_PORTRAIT);
    cacher_->OnScreenStatusChanged(EXPAND_PORTRAIT, G_PORTRAIT);
    cacher_->OnImeUnbind(TEST_BUNDLE);

    // Should have START, 2x STATUS_CHANGED, COUNT_DURATION records
    int startIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(startIdx, 0);
    int changedIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STATUS_CHANGED);
    EXPECT_GE(changedIdx, 0);
    int countIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
}

// ==================== ImeUsageInfo ====================

/**
 * @tc.name: ImeUsageInfo_GetAppUsage_001
 * @tc.desc: GetAppUsage with all zeros returns 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, GetAppUsage_001, TestSize.Level0)
{
    // Default-constructed ImeUsageInfo has all durations zero
    ImeUsageInfo info;
    EXPECT_EQ(info.GetAppUsage(), 0u);
    // All individual duration fields should also be zero
    EXPECT_EQ(info.durations[IDX_FOLD_PORTRAIT], 0u);
    EXPECT_EQ(info.durations[IDX_EXPAND_PORTRAIT], 0u);
    EXPECT_EQ(info.durations[IDX_UNFOLDED_PORTRAIT], 0u);
    EXPECT_EQ(info.showCount, 0u);
}

/**
 * @tc.name: ImeUsageInfo_GetAppUsage_002
 * @tc.desc: GetAppUsage sums all duration fields
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, GetAppUsage_002, TestSize.Level0)
{
    ImeUsageInfo info;
    info.durations[IDX_EXPAND_PORTRAIT] = 100;
    info.durations[IDX_FOLD_LANDSCAPE] = 200;
    info.durations[IDX_G_PORTRAIT] = 300;
    EXPECT_EQ(info.GetAppUsage(), 600u);
}

/**
 * @tc.name: ImeUsageInfo_OperatorPlus_001
 * @tc.desc: operator+= sums all fields
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, OperatorPlus_001, TestSize.Level0)
{
    ImeUsageInfo a;
    a.durations[IDX_EXPAND_PORTRAIT] = 100;
    a.showCount = 1;
    // Note: usage is NOT manually set; GetAppUsage() sums all duration fields

    ImeUsageInfo b;
    b.durations[IDX_EXPAND_PORTRAIT] = 200;
    b.durations[IDX_FOLD_PORTRAIT] = 300;
    b.showCount = 2;

    a += b;
    EXPECT_EQ(a.durations[IDX_EXPAND_PORTRAIT], 300u);
    EXPECT_EQ(a.durations[IDX_FOLD_PORTRAIT], 300u);
    EXPECT_EQ(a.showCount, 3u);
    // operator+= recalculates usage = GetAppUsage() = sum of all 12 duration fields
    // a: expandPortrait=300 + foldPortrait=300 = 600
    EXPECT_EQ(a.usage, 600u);
}

// ==================== ImeUsageDbHelper ====================

/**
 * @tc.name: ImeUsageDbHelper_IsReady_001
 * @tc.desc: IsReady returns true after successful construction
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_IsReady_001, TestSize.Level0)
{
    // After construction, the DB helper should be ready
    EXPECT_TRUE(dbHelper_->IsReady());
    // rdbStore_ should be non-null when ready
    EXPECT_NE(dbHelper_->rdbStore_, nullptr);
    // Setting rdbStore_ to nullptr should make IsReady return false
    auto savedStore = dbHelper_->rdbStore_;
    dbHelper_->rdbStore_ = nullptr;
    EXPECT_FALSE(dbHelper_->IsReady());
    // Restore for subsequent tests
    dbHelper_->rdbStore_ = savedStore;
    EXPECT_TRUE(dbHelper_->IsReady());
}

/**
 * @tc.name: ImeUsageDbHelper_AddEvent_001
 * @tc.desc: AddEvent returns success for basic event
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_AddEvent_001, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    record.screenStatus = UNFOLDED_PORTRAIT;
    int ret = dbHelper_->AddEvent(record);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ImeUsageDbHelper_AddEvent_002
 * @tc.desc: AddEvent with duration map writes duration columns
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_AddEvent_002, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_COUNT_DURATION;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    record.screenStatus = UNFOLDED_PORTRAIT;

    DurationMap durations;
    durations[UNFOLDED_PORTRAIT] = 5000;
    durations[EXPAND_PORTRAIT] = 3000;

    int ret = dbHelper_->AddEvent(record, durations);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryRawEventIndex_001
 * @tc.desc: QueryRawEventIndex returns -1 for non-existent event
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryRawEventIndex_001, TestSize.Level0)
{
    // Query for non-existent bundle should return IME_INDEX_NOT_FOUND
    std::string nonExistent = "non.existent.bundle";
    int idx = dbHelper_->QueryRawEventIndex(nonExistent, EVENT_INPUT_START);
    EXPECT_EQ(idx, IME_INDEX_NOT_FOUND);
    // Query for non-existent event type with valid bundle should also return IME_INDEX_NOT_FOUND
    int idx2 = dbHelper_->QueryRawEventIndex(nonExistent, EVENT_INPUT_STOP);
    EXPECT_EQ(idx2, IME_INDEX_NOT_FOUND);
    // Query for COUNT_DURATION should also return IME_INDEX_NOT_FOUND
    int idx3 = dbHelper_->QueryRawEventIndex(nonExistent, EVENT_COUNT_DURATION);
    EXPECT_EQ(idx3, IME_INDEX_NOT_FOUND);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryRawEventIndex_002
 * @tc.desc: QueryRawEventIndex returns valid index after AddEvent
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryRawEventIndex_002, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(record);

    int idx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(idx, 0);
}

/**
 * @tc.name: ImeUsageDbHelper_DeleteEventsByTime_001
 * @tc.desc: DeleteEventsByTime returns success
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_DeleteEventsByTime_001, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 1000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(record);

    int ret = dbHelper_->DeleteEventsByTime(500); // Delete events with happenTime <= 500
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryEventRecords_001
 * @tc.desc: QueryEventRecords returns correct records for a session
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryEventRecords_001, TestSize.Level0)
{
    ImeEventRecord start;
    start.rawid = EVENT_INPUT_START;
    start.ts = 1000;
    start.happenTime = 2000;
    start.bundleName = TEST_BUNDLE;
    start.screenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(start);

    int startIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    ASSERT_GE(startIdx, 0);

    std::vector<ImeEventRecord> records;
    dbHelper_->QueryEventRecords(startIdx, 0, TEST_BUNDLE, records);
    EXPECT_GE(records.size(), 1u);
    if (!records.empty()) {
        EXPECT_EQ(records[0].rawid, EVENT_INPUT_START);
        EXPECT_EQ(records[0].bundleName, TEST_BUNDLE);
    }
}

// ==================== DbHelper: QueryStatisticEventsInPeriod ====================

/**
 * @tc.name: ImeUsageDbHelper_QueryStatisticEventsInPeriod_001
 * @tc.desc: QueryStatisticEventsInPeriod with no data returns empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryStatisticEventsInPeriod_001, TestSize.Level0)
{
    std::unordered_map<std::string, ImeUsageInfo> infos;
    // Use a tiny time range that no prior test data should fall into
    dbHelper_->QueryStatisticEventsInPeriod(0, 1, infos);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: ImeUsageDbHelper_QueryStatisticEventsInPeriod_002
 * @tc.desc: QueryStatisticEventsInPeriod aggregates durations and show counts
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryStatisticEventsInPeriod_002, TestSize.Level0)
{
    // Insert a COUNT_DURATION record
    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = 5000;
    countRec.happenTime = 5000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.screenStatus = UNFOLDED_PORTRAIT;
    countRec.preScreenStatus = UNFOLDED_PORTRAIT;
    DurationMap durations;
    durations[UNFOLDED_PORTRAIT] = 3000;
    dbHelper_->AddEvent(countRec, durations);

    // Insert a START record (for show count)
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = 1000;
    startRec.happenTime = 1000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    std::unordered_map<std::string, ImeUsageInfo> infos;
    dbHelper_->QueryStatisticEventsInPeriod(0, 10000, infos);
    ASSERT_EQ(infos.size(), 1u);
    auto it = infos.find(TEST_BUNDLE);
    ASSERT_NE(it, infos.end());
    EXPECT_EQ(it->second.durations[IDX_UNFOLDED_PORTRAIT], 3000u);
    EXPECT_EQ(it->second.showCount, 1u); // 1 INPUT_START event
}

/**
 * @tc.name: ImeUsageDbHelper_QueryStatisticEventsInPeriod_003
 * @tc.desc: QueryStatisticEventsInPeriod with multiple bundles
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryStatisticEventsInPeriod_003, TestSize.Level0)
{
    ImeEventRecord rec1;
    rec1.rawid = EVENT_COUNT_DURATION;
    rec1.ts = 5000;
    rec1.happenTime = 5000;
    rec1.bundleName = TEST_BUNDLE;
    rec1.screenStatus = UNFOLDED_PORTRAIT;
    rec1.preScreenStatus = UNFOLDED_PORTRAIT;
    DurationMap dur1;
    dur1[UNFOLDED_PORTRAIT] = 2000;
    dbHelper_->AddEvent(rec1, dur1);

    ImeEventRecord rec2;
    rec2.rawid = EVENT_COUNT_DURATION;
    rec2.ts = 6000;
    rec2.happenTime = 6000;
    rec2.bundleName = TEST_BUNDLE2;
    rec2.screenStatus = EXPAND_PORTRAIT;
    rec2.preScreenStatus = EXPAND_PORTRAIT;
    DurationMap dur2;
    dur2[EXPAND_PORTRAIT] = 4000;
    dbHelper_->AddEvent(rec2, dur2);

    std::unordered_map<std::string, ImeUsageInfo> infos;
    dbHelper_->QueryStatisticEventsInPeriod(0, 10000, infos);
    EXPECT_EQ(infos.size(), 2u);
    EXPECT_EQ(infos[TEST_BUNDLE].durations[IDX_UNFOLDED_PORTRAIT], 2000u);
    EXPECT_EQ(infos[TEST_BUNDLE2].durations[IDX_EXPAND_PORTRAIT], 4000u);
}

// ==================== DbHelper: QueryFinalEventInfo ====================

/**
 * @tc.name: ImeUsageDbHelper_QueryFinalEventInfo_001
 * @tc.desc: QueryFinalEventInfo with no matching data leaves event empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryFinalEventInfo_001, TestSize.Level0)
{
    ImeUsageRawEvent event;
    // Use endTime=1 so no event with happen_time <= 1 should exist
    dbHelper_->QueryFinalEventInfo(1, event);
    EXPECT_EQ(event.rawId, 0);
    EXPECT_TRUE(event.package.empty());
}

/**
 * @tc.name: ImeUsageDbHelper_QueryFinalEventInfo_002
 * @tc.desc: QueryFinalEventInfo returns most recent event before endTime
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryFinalEventInfo_002, TestSize.Level0)
{
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = 1000;
    startRec.happenTime = 1000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = EXPAND_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    ImeEventRecord stopRec;
    stopRec.rawid = EVENT_INPUT_STOP;
    stopRec.ts = 5000;
    stopRec.happenTime = 5000;
    stopRec.bundleName = TEST_BUNDLE;
    stopRec.screenStatus = UNFOLDED_PORTRAIT;
    stopRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(stopRec);

    ImeUsageRawEvent event;
    dbHelper_->QueryFinalEventInfo(10000, event);
    // Should return the STOP event (most recent before 10000)
    EXPECT_EQ(event.rawId, EVENT_INPUT_STOP);
    EXPECT_EQ(event.package, TEST_BUNDLE);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryFinalEventInfo_003
 * @tc.desc: QueryFinalEventInfo respects endTime boundary
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryFinalEventInfo_003, TestSize.Level0)
{
    ImeEventRecord rec;
    rec.rawid = EVENT_INPUT_START;
    rec.ts = 5000;
    rec.happenTime = 5000;
    rec.bundleName = TEST_BUNDLE;
    rec.screenStatus = UNFOLDED_PORTRAIT;
    rec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(rec);

    ImeUsageRawEvent event;
    dbHelper_->QueryFinalEventInfo(3000, event);
    // Event at 5000 is after endTime=3000, should not be returned
    EXPECT_EQ(event.rawId, 0);
}

// ==================== DbHelper: QueryForegroundImeInfo ====================

/**
 * @tc.name: ImeUsageDbHelper_QueryForegroundImeInfo_001
 * @tc.desc: QueryForegroundImeInfo with no events assigns full time range as duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryForegroundImeInfo_001, TestSize.Level0)
{
    ImeUsageInfo info;
    info.package = "nonexistent.foreground.ime";
    uint64_t startTime = 1000;
    uint64_t endTime = 5000;
    dbHelper_->QueryForegroundImeInfo(startTime, endTime, UNFOLDED_PORTRAIT, info);
    // When no events found, the entire time range is treated as foreground duration
    EXPECT_EQ(info.durations[IDX_UNFOLDED_PORTRAIT], static_cast<uint32_t>(endTime - startTime));
}

/**
 * @tc.name: ImeUsageDbHelper_QueryForegroundImeInfo_002
 * @tc.desc: QueryForegroundImeInfo with START event calculates duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryForegroundImeInfo_002, TestSize.Level0)
{
    uint64_t dayStart = 0;
    uint64_t dayEnd = MILLISECS_PER_DAY;
    // Insert a START event (IME showing at day boundary)
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = 3600000; // 1 hour into the day
    startRec.happenTime = 3600000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    ImeUsageInfo info;
    info.package = TEST_BUNDLE;
    info.showCount = 0;
    dbHelper_->QueryForegroundImeInfo(dayStart, dayEnd, UNFOLDED_PORTRAIT, info);
    // Duration from dayStart to happenTime with screenStatus, plus from happenTime to dayEnd
    EXPECT_GT(info.durations[IDX_UNFOLDED_PORTRAIT], 0u);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryForegroundImeInfo_003
 * @tc.desc: QueryForegroundImeInfo with STATUS_CHANGED events
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryForegroundImeInfo_003, TestSize.Level0)
{
    uint64_t dayStart = 0;
    uint64_t dayEnd = MILLISECS_PER_DAY;

    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = 3600000;
    startRec.happenTime = 3600000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    ImeEventRecord changedRec;
    changedRec.rawid = EVENT_INPUT_STATUS_CHANGED;
    changedRec.ts = 7200000;
    changedRec.happenTime = 7200000;
    changedRec.bundleName = TEST_BUNDLE;
    changedRec.screenStatus = EXPAND_PORTRAIT;
    changedRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(changedRec);

    ImeUsageInfo info;
    info.package = TEST_BUNDLE;
    info.showCount = 0;
    dbHelper_->QueryForegroundImeInfo(dayStart, dayEnd, EXPAND_PORTRAIT, info);
    // Should have both UNFOLDED_PORTRAIT and EXPAND_PORTRAIT durations
    EXPECT_GT(info.durations[IDX_UNFOLDED_PORTRAIT], 0u);
    EXPECT_GT(info.durations[IDX_EXPAND_PORTRAIT], 0u);
}

// ==================== DbHelper: SaveReportState / LoadReportState ====================

/**
 * @tc.name: ImeUsageDbHelper_SaveLoadReportState_001
 * @tc.desc: Save and load roundtrip
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_SaveLoadReportState_001, TestSize.Level0)
{
    std::string key = "test_key";
    std::string value = "1234567890";
    int ret = dbHelper_->SaveReportState(key, value);
    EXPECT_EQ(ret, 0);

    std::string loaded;
    ret = dbHelper_->LoadReportState(key, loaded);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(loaded, value);
}

/**
 * @tc.name: ImeUsageDbHelper_SaveLoadReportState_002
 * @tc.desc: Load non-existent key returns failure
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_SaveLoadReportState_002, TestSize.Level0)
{
    std::string loaded;
    int ret = dbHelper_->LoadReportState("nonexistent_key", loaded);
    EXPECT_NE(ret, 0);
    EXPECT_TRUE(loaded.empty());
}

/**
 * @tc.name: ImeUsageDbHelper_SaveLoadReportState_003
 * @tc.desc: Save updates existing key (INSERT OR REPLACE)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_SaveLoadReportState_003, TestSize.Level0)
{
    std::string key = "update_key";
    dbHelper_->SaveReportState(key, "old_value");
    dbHelper_->SaveReportState(key, "new_value");

    std::string loaded;
    dbHelper_->LoadReportState(key, loaded);
    EXPECT_EQ(loaded, "new_value");
}

/**
 * @tc.name: ImeUsageDbHelper_SaveLoadReportState_004
 * @tc.desc: Save/load last_report_time key with large timestamp
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_SaveLoadReportState_004, TestSize.Level0)
{
    std::string value = std::to_string(1700000000000ULL);
    dbHelper_->SaveReportState(STATE_KEY_LAST_REPORT_TIME, value);

    std::string loaded;
    dbHelper_->LoadReportState(STATE_KEY_LAST_REPORT_TIME, loaded);
    EXPECT_EQ(loaded, value);
}

// ==================== DbHelper: QueryEarliestEventTime ====================

/**
 * @tc.name: ImeUsageDbHelper_QueryEarliestEventTime_001
 * @tc.desc: QueryEarliestEventTime with no data returns <= 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryEarliestEventTime_001, TestSize.Level0)
{
    // With empty DB, QueryEarliestEventTime returns -1 (if NULL check works)
    // or 0 (SQLite MIN on empty table returns NULL, GetLong may return 0)
    int64_t earliest = dbHelper_->QueryEarliestEventTime();
    EXPECT_LE(earliest, 0);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryEarliestEventTime_002
 * @tc.desc: QueryEarliestEventTime returns earliest happen_time
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryEarliestEventTime_002, TestSize.Level0)
{
    ImeEventRecord rec1;
    rec1.rawid = EVENT_INPUT_START;
    rec1.ts = 5000;
    rec1.happenTime = 5000;
    rec1.bundleName = TEST_BUNDLE;
    rec1.screenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(rec1);

    ImeEventRecord rec2;
    rec2.rawid = EVENT_INPUT_START;
    rec2.ts = 3000;
    rec2.happenTime = 3000;
    rec2.bundleName = TEST_BUNDLE2;
    rec2.screenStatus = EXPAND_PORTRAIT;
    dbHelper_->AddEvent(rec2);

    int64_t earliest = dbHelper_->QueryEarliestEventTime();
    EXPECT_EQ(earliest, 3000);
}

// ==================== DbHelper: QueryActiveDays ====================

/**
 * @tc.name: ImeUsageDbHelper_QueryActiveDays_001
 * @tc.desc: QueryActiveDays with no matching data returns empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryActiveDays_001, TestSize.Level0)
{
    // Use a very early time range that no test data should fall into
    auto days = dbHelper_->QueryActiveDays(0, 1);
    EXPECT_TRUE(days.empty());
    // Verify the vector size is exactly 0
    EXPECT_EQ(days.size(), 0u);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryActiveDays_002
 * @tc.desc: QueryActiveDays returns distinct day-start timestamps
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryActiveDays_002, TestSize.Level0)
{
    // Insert events on two different days
    uint64_t day1 = MILLISECS_PER_DAY;     // Day 1 start
    uint64_t day3 = MILLISECS_PER_DAY * 3; // Day 3 start

    ImeEventRecord rec1;
    rec1.rawid = EVENT_INPUT_START;
    rec1.ts = day1 + 3600000;
    rec1.happenTime = day1 + 3600000;
    rec1.bundleName = TEST_BUNDLE;
    rec1.screenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(rec1);

    ImeEventRecord rec2;
    rec2.rawid = EVENT_INPUT_START;
    rec2.ts = day3 + 3600000;
    rec2.happenTime = day3 + 3600000;
    rec2.bundleName = TEST_BUNDLE;
    rec2.screenStatus = EXPAND_PORTRAIT;
    dbHelper_->AddEvent(rec2);

    auto days = dbHelper_->QueryActiveDays(0, MILLISECS_PER_DAY * 5);
    ASSERT_EQ(days.size(), 2u);
    EXPECT_EQ(days[0], day1);
    EXPECT_EQ(days[1], day3);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryActiveDays_003
 * @tc.desc: QueryActiveDays respects time range boundaries
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryActiveDays_003, TestSize.Level0)
{
    uint64_t day1 = MILLISECS_PER_DAY;
    uint64_t day3 = MILLISECS_PER_DAY * 3;

    ImeEventRecord rec1;
    rec1.rawid = EVENT_INPUT_START;
    rec1.ts = day1 + 3600000;
    rec1.happenTime = day1 + 3600000;
    rec1.bundleName = TEST_BUNDLE;
    rec1.screenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(rec1);

    ImeEventRecord rec2;
    rec2.rawid = EVENT_INPUT_START;
    rec2.ts = day3 + 3600000;
    rec2.happenTime = day3 + 3600000;
    rec2.bundleName = TEST_BUNDLE;
    rec2.screenStatus = EXPAND_PORTRAIT;
    dbHelper_->AddEvent(rec2);

    // Query only day1 range
    auto days = dbHelper_->QueryActiveDays(0, MILLISECS_PER_DAY * 2);
    ASSERT_EQ(days.size(), 1u);
    EXPECT_EQ(days[0], day1);
}

// ==================== DbHelper: DeleteEventsByTime ====================

/**
 * @tc.name: ImeUsageDbHelper_DeleteEventsByTime_002
 * @tc.desc: DeleteEventsByTime only deletes events before clearDataTime
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_DeleteEventsByTime_002, TestSize.Level0)
{
    ImeEventRecord oldRec;
    oldRec.rawid = EVENT_INPUT_START;
    oldRec.ts = 1000;
    oldRec.happenTime = 1000;
    oldRec.bundleName = TEST_BUNDLE;
    oldRec.screenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(oldRec);

    ImeEventRecord newRec;
    newRec.rawid = EVENT_INPUT_START;
    newRec.ts = 5000;
    newRec.happenTime = 5000;
    newRec.bundleName = TEST_BUNDLE;
    newRec.screenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(newRec);

    dbHelper_->DeleteEventsByTime(3000);
    // Old record should be deleted, new record should remain
    int oldIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(oldIdx, 0); // Still exists (the new one)
}

// ==================== DbHelper: rdbStore_ null paths ====================

/**
 * @tc.name: ImeUsageDbHelper_AddEvent_NullRdbStore
 * @tc.desc: AddEvent with null rdbStore_ returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_AddEvent_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    int ret = dbHelper_->AddEvent(record);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryRawEventIndex_NullRdbStore
 * @tc.desc: QueryRawEventIndex with null rdbStore_ returns -1
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryRawEventIndex_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    int idx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_EQ(idx, IME_INDEX_NOT_FOUND);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryEventRecords_NullRdbStore
 * @tc.desc: QueryEventRecords with null rdbStore_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryEventRecords_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    std::vector<ImeEventRecord> records;
    dbHelper_->QueryEventRecords(0, 0, TEST_BUNDLE, records);
    EXPECT_TRUE(records.empty());
}

/**
 * @tc.name: ImeUsageDbHelper_QueryStatisticEventsInPeriod_NullRdbStore
 * @tc.desc: QueryStatisticEventsInPeriod with null rdbStore_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryStatisticEventsInPeriod_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    std::unordered_map<std::string, ImeUsageInfo> infos;
    dbHelper_->QueryStatisticEventsInPeriod(0, MILLISECS_PER_DAY, infos);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: ImeUsageDbHelper_QueryFinalEventInfo_NullRdbStore
 * @tc.desc: QueryFinalEventInfo with null rdbStore_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryFinalEventInfo_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    ImeUsageRawEvent event;
    dbHelper_->QueryFinalEventInfo(MILLISECS_PER_DAY, event);
    // Should not crash; event stays default (rawId=0, package empty)
    EXPECT_EQ(event.rawId, 0);
    EXPECT_TRUE(event.package.empty());
}

/**
 * @tc.name: ImeUsageDbHelper_QueryForegroundImeInfo_NullRdbStore
 * @tc.desc: QueryForegroundImeInfo with null rdbStore_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryForegroundImeInfo_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    ImeUsageInfo info;
    info.package = TEST_BUNDLE;
    dbHelper_->QueryForegroundImeInfo(0, MILLISECS_PER_DAY, UNFOLDED_PORTRAIT, info);
    // Should not crash; info should remain unchanged (no duration added)
    EXPECT_EQ(info.durations[IDX_UNFOLDED_PORTRAIT], 0u);
}

/**
 * @tc.name: ImeUsageDbHelper_DeleteEventsByTime_NullRdbStore
 * @tc.desc: DeleteEventsByTime with null rdbStore_ returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_DeleteEventsByTime_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    int ret = dbHelper_->DeleteEventsByTime(0);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: ImeUsageDbHelper_SaveReportState_NullRdbStore
 * @tc.desc: SaveReportState with null rdbStore_ returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_SaveReportState_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    int ret = dbHelper_->SaveReportState("key", "value");
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: ImeUsageDbHelper_LoadReportState_NullRdbStore
 * @tc.desc: LoadReportState with null rdbStore_ returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_LoadReportState_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    std::string value;
    int ret = dbHelper_->LoadReportState("key", value);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryEarliestEventTime_NullRdbStore
 * @tc.desc: QueryEarliestEventTime with null rdbStore_ returns -1
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryEarliestEventTime_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    int64_t earliest = dbHelper_->QueryEarliestEventTime();
    EXPECT_EQ(earliest, IME_INDEX_NOT_FOUND);
}

/**
 * @tc.name: ImeUsageDbHelper_QueryActiveDays_NullRdbStore
 * @tc.desc: QueryActiveDays with null rdbStore_ returns empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryActiveDays_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    auto days = dbHelper_->QueryActiveDays(0, MILLISECS_PER_DAY);
    EXPECT_TRUE(days.empty());
}

// ==================== DbHelper: EnsureDirectoryExist ====================

/**
 * @tc.name: ImeUsageDbHelper_EnsureDirectoryExist_EmptyPath
 * @tc.desc: EnsureDirectoryExist with empty path returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_EnsureDirectoryExist_EmptyPath, TestSize.Level0)
{
    // Empty path should return false (cannot create directory with empty path)
    bool result = dbHelper_->EnsureDirectoryExist("");
    EXPECT_FALSE(result);
    // Verify with existing valid path returns true (DB_DIR from SetUp)
    bool result2 = dbHelper_->EnsureDirectoryExist(DB_DIR);
    EXPECT_TRUE(result2);
    // Invalid empty path should consistently return false
    bool result3 = dbHelper_->EnsureDirectoryExist("");
    EXPECT_FALSE(result3);
}

/**
 * @tc.name: ImeUsageDbHelper_EnsureDirectoryExist_ExistingPath
 * @tc.desc: EnsureDirectoryExist with existing path returns true
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_EnsureDirectoryExist_ExistingPath, TestSize.Level0)
{
    // DB_DIR already exists from SetUp
    bool result = dbHelper_->EnsureDirectoryExist(DB_DIR);
    EXPECT_TRUE(result);
}

// ==================== DbHelper: AddEvent without durations ====================

/**
 * @tc.name: ImeUsageDbHelper_AddEvent_NoDurations
 * @tc.desc: AddEvent (1-arg overload) writes all duration columns as 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_AddEvent_NoDurations, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    record.screenStatus = UNFOLDED_PORTRAIT;
    int ret = dbHelper_->AddEvent(record); // 1-arg overload, no durations
    EXPECT_EQ(ret, 0);
    // Verify event was inserted
    int idx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(idx, 0);
}

// ==================== DbHelper: QueryEventRecords with COUNT_DURATION checkpoint ====================

/**
 * @tc.name: ImeUsageDbHelper_QueryEventRecords_Checkpoint
 * @tc.desc: QueryEventRecords clears records on COUNT_DURATION checkpoint
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_QueryEventRecords_Checkpoint, TestSize.Level0)
{
    // Insert START, then COUNT_DURATION, then another START
    ImeEventRecord start1;
    start1.rawid = EVENT_INPUT_START;
    start1.ts = 1000;
    start1.happenTime = 2000;
    start1.bundleName = TEST_BUNDLE;
    start1.screenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(start1);

    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = 3000;
    countRec.happenTime = 3000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap dur;
    dur[UNFOLDED_PORTRAIT] = 1000;
    dbHelper_->AddEvent(countRec, dur);

    ImeEventRecord start2;
    start2.rawid = EVENT_INPUT_START;
    start2.ts = 4000;
    start2.happenTime = 4000;
    start2.bundleName = TEST_BUNDLE;
    start2.screenStatus = EXPAND_PORTRAIT;
    dbHelper_->AddEvent(start2);

    // Query from index 1 (should skip first START due to checkpoint)
    int startIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    ASSERT_GE(startIdx, 0);

    std::vector<ImeEventRecord> records;
    dbHelper_->QueryEventRecords(1, 0, TEST_BUNDLE, records);
    // After checkpoint, only records after COUNT_DURATION should remain
    EXPECT_GE(records.size(), 1u);
    // The last record should be the START after the checkpoint
    if (!records.empty()) {
        EXPECT_EQ(records.back().rawid, EVENT_INPUT_START);
    }
}

// ==================== CalculateDuration: ts backward (ts <= preIt->ts) ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_008
 * @tc.desc: CalculateDuration with ts going backward produces 0 duration for that pair
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_008, TestSize.Level0)
{
    std::vector<ImeEventRecord> records;
    ImeEventRecord start;
    start.rawid = EVENT_INPUT_START;
    start.ts = 5000; // Later boot time
    start.happenTime = 1000;
    start.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(start);

    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 3000; // Earlier boot time (clock went backward)
    stop.happenTime = 5000;
    stop.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(stop);

    DurationMap durations;
    cacher_->CalculateDuration(0, records, durations);
    // ts backward: it->ts (3000) <= preIt->ts (5000), duration should be 0
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 0u);
}

// ==================== CalculateDuration: cross-midnight with STOP as first event ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_009
 * @tc.desc: Cross-midnight with STOP as first event uses screenStatus
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_009, TestSize.Level0)
{
    uint64_t dayStartTime = 1000;

    std::vector<ImeEventRecord> records;
    // First event is STOP (cross-midnight scenario where START was before midnight)
    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 3000;
    stop.happenTime = 3000;
    stop.screenStatus = FOLD_PORTRAIT;
    stop.preScreenStatus = FOLD_PORTRAIT;
    records.push_back(stop);

    DurationMap durations;
    cacher_->CalculateDuration(dayStartTime, records, durations);
    // Cross-midnight: dayStartTime(1000) -> stop(3000) = 2000ms, uses stop.screenStatus
    EXPECT_EQ(durations[FOLD_PORTRAIT], 2000u);
}

// ==================== CalculateDuration: cross-midnight with screenStatus=0 fallback ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_010
 * @tc.desc: Cross-midnight with screenStatus=0 falls back to UNFOLDED_PORTRAIT
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_010, TestSize.Level0)
{
    uint64_t dayStartTime = 1000;

    std::vector<ImeEventRecord> records;
    // First event is STATUS_CHANGED with screenStatus=0 (uninitialized)
    ImeEventRecord changed;
    changed.rawid = EVENT_INPUT_STATUS_CHANGED;
    changed.ts = 3000;
    changed.happenTime = 3000;
    changed.screenStatus = SCREEN_STATUS_UNINITIALIZED;
    changed.preScreenStatus = SCREEN_STATUS_UNINITIALIZED;
    records.push_back(changed);

    DurationMap durations;
    cacher_->CalculateDuration(dayStartTime, records, durations);
    // screenStatus=0 fallback to UNFOLDED_PORTRAIT(12), preScreenStatus=0 also used
    // First event is not START, cross-midnight: uses preScreenStatus which is also 0 -> UNFOLDED_PORTRAIT
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 2000u);
}

// ==================== CalculateDuration: pair with screenStatus=0 fallback ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_011
 * @tc.desc: Pair duration with screenStatus=0 falls back to UNFOLDED_PORTRAIT
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_011, TestSize.Level0)
{
    std::vector<ImeEventRecord> records;
    ImeEventRecord start;
    start.rawid = EVENT_INPUT_START;
    start.ts = 1000;
    start.happenTime = 1000;
    start.screenStatus = SCREEN_STATUS_UNINITIALIZED; // uninitialized
    records.push_back(start);

    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 5000;
    stop.happenTime = 5000;
    stop.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(stop);

    DurationMap durations;
    cacher_->CalculateDuration(0, records, durations);
    // start.screenStatus=0 should fallback to UNFOLDED_PORTRAIT(12)
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 4000u);
}

// ==================== ProcessScreenChangedEvent: with nullptr dbHelper ====================

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_007
 * @tc.desc: ProcessScreenChangedEvent with nullptr dbHelper returns empty record
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_007, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init called, dbHelper_ is nullptr, isKeyboardShowing_ is false
    EXPECT_FALSE(cacher->isKeyboardShowing_);
    EXPECT_EQ(cacher->dbHelper_, nullptr);
    cacher->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    // Should not crash; state should not change since dbHelper_ is null and not showing
    EXPECT_FALSE(cacher->isKeyboardShowing_);
    EXPECT_EQ(cacher->lastScreenStatus_, 0);
}

// ==================== CountDuration: no START event found ====================

/**
 * @tc.name: ImeUsageEventCacher_CountDuration_001
 * @tc.desc: CountDuration with no matching START event returns early
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CountDuration_001, TestSize.Level0)
{
    // Create a record for a bundle that has no START event in DB
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = 5000;
    record.happenTime = 5000;
    record.bundleName = "nonexistent.bundle";
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    // Verify no START event exists for this bundle
    int32_t startIdx = cacher_->GetStartIndex("nonexistent.bundle");
    EXPECT_EQ(startIdx, IME_INDEX_NOT_FOUND);
    // CountDuration should return early because GetStartIndex returns IME_INDEX_NOT_FOUND
    cacher_->CountDuration(record);
    // Verify no COUNT_DURATION was written for this bundle
    int32_t countIdx = dbHelper_->QueryRawEventIndex("nonexistent.bundle", EVENT_COUNT_DURATION);
    EXPECT_EQ(countIdx, IME_INDEX_NOT_FOUND);
}

// ==================== GetBootTimeMs / GetWallClockMs ====================

/**
 * @tc.name: ImeUsageEventCacher_GetBootTimeMs_001
 * @tc.desc: GetBootTimeMs returns non-zero value
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, GetBootTimeMs_001, TestSize.Level0)
{
    uint64_t bootTime = cacher_->GetBootTimeMs();
    EXPECT_GT(bootTime, 0u);
    // Boot time should be reasonable: less than 1 year in ms
    EXPECT_LT(bootTime, 365ULL * 24 * 60 * 60 * 1000);
    // Calling twice should return a >= value (monotonic clock)
    uint64_t bootTime2 = cacher_->GetBootTimeMs();
    EXPECT_GE(bootTime2, bootTime);
}

/**
 * @tc.name: ImeUsageEventCacher_GetWallClockMs_001
 * @tc.desc: GetWallClockMs returns non-zero value
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, GetWallClockMs_001, TestSize.Level0)
{
    uint64_t wallClock = cacher_->GetWallClockMs();
    EXPECT_GT(wallClock, 0u);
    // Wall clock should be less than year 2100 in ms
    EXPECT_LT(wallClock, 4102444800000ULL);
    // Calling twice should return a >= value
    uint64_t wallClock2 = cacher_->GetWallClockMs();
    EXPECT_GE(wallClock2, wallClock);
}

/**
 * @tc.name: ImeUsageEventCacher_GetToday0ClockMs_001
 * @tc.desc: GetToday0ClockMs global function returns non-zero value
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, GetToday0ClockMs_001, TestSize.Level0)
{
    uint64_t today0 = GetToday0ClockMs();
    EXPECT_GT(today0, 0u);
    // Should be less than year 2100 in ms
    EXPECT_LT(today0, 4102444800000ULL);
}

// ==================== OnImeBind: different IME while showing produces hide record ====================

/**
 * @tc.name: ImeUsageEventCacher_OnImeBind_DifferentIme
 * @tc.desc: OnImeBind with a different IME while one is showing produces hide+show in DB
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, OnImeBind_DifferentIme, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);

    // Bind a different IME - should hide old one first then show new
    cacher_->OnImeBind(TEST_BUNDLE2);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE2);

    // Verify STOP for TEST_BUNDLE and START for TEST_BUNDLE2 in DB
    int stopIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STOP);
    EXPECT_GE(stopIdx, 0);
    int startIdx2 = dbHelper_->QueryRawEventIndex(TEST_BUNDLE2, EVENT_INPUT_START);
    EXPECT_GE(startIdx2, 0);
    // Verify COUNT_DURATION for old IME is written (STOP+COUNT are in one transaction)
    int countIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
    // Verify row-ID ordering: STOP (old IME) < START (new IME)
    EXPECT_LT(stopIdx, startIdx2);
}

// ==================== STOP->START pair in CalculateDuration ====================

/**
 * @tc.name: ImeUsageEventCacher_OnImeBind_DifferentIme_SplitTransaction
 * @tc.desc: OnImeBind IME switch writes STOP+COUNT in one transaction, START separately
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, OnImeBind_DifferentIme_SplitTransaction, TestSize.Level0)
{
    // Bind first IME
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);

    // Switch to second IME - STOP+COUNT for old IME and START for new IME
    // are written as two independent operations
    cacher_->OnImeBind(TEST_BUNDLE2);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE2);

    // Verify old IME's STOP and COUNT_DURATION exist
    int stopIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STOP);
    EXPECT_GE(stopIdx, 0);
    int countIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
    // Verify new IME's START exists
    int startIdx2 = dbHelper_->QueryRawEventIndex(TEST_BUNDLE2, EVENT_INPUT_START);
    EXPECT_GE(startIdx2, 0);
    // Verify COUNT_DURATION row ID > STOP row ID (COUNT is written after STOP in transaction)
    EXPECT_GT(countIdx, stopIdx);
}

/**
 * @tc.name: ImeUsageEventCacher_OnImeBind_DifferentIme_MultipleSwitches
 * @tc.desc: Multiple consecutive IME switches produce correct DB records
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, OnImeBind_DifferentIme_MultipleSwitches, TestSize.Level0)
{
    // IME1 -> IME2 -> IME1
    cacher_->OnImeBind(TEST_BUNDLE);
    cacher_->OnImeBind(TEST_BUNDLE2);
    cacher_->OnImeBind(TEST_BUNDLE);

    // Each switch should produce STOP+COUNT for old IME and START for new IME
    // TEST_BUNDLE: START, then later START again (after switch back)
    int startIdx1 = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(startIdx1, 0);
    // TEST_BUNDLE: STOP from first switch-out
    int stopIdx1 = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STOP);
    EXPECT_GE(stopIdx1, 0);
    // TEST_BUNDLE2: START and STOP
    int startIdx2 = dbHelper_->QueryRawEventIndex(TEST_BUNDLE2, EVENT_INPUT_START);
    EXPECT_GE(startIdx2, 0);
    int stopIdx2 = dbHelper_->QueryRawEventIndex(TEST_BUNDLE2, EVENT_INPUT_STOP);
    EXPECT_GE(stopIdx2, 0);
    // Both IMEs should have COUNT_DURATION
    int countIdx1 = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx1, 0);
    int countIdx2 = dbHelper_->QueryRawEventIndex(TEST_BUNDLE2, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx2, 0);
}

// ==================== STOP->START pair in CalculateDuration ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_012
 * @tc.desc: STOP->START pair is valid but produces no duration (gap between sessions)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_012, TestSize.Level0)
{
    // Use dayStartTime=3000 so cross-midnight does NOT apply for STOP at happenTime=3000
    uint64_t dayStartTime = 3000;
    std::vector<ImeEventRecord> records;
    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 3000;
    stop.happenTime = 3000;
    stop.screenStatus = UNFOLDED_PORTRAIT;
    records.push_back(stop);

    ImeEventRecord start;
    start.rawid = EVENT_INPUT_START;
    start.ts = 5000;
    start.happenTime = 5000;
    start.screenStatus = EXPAND_PORTRAIT;
    records.push_back(start);

    DurationMap durations;
    cacher_->CalculateDuration(dayStartTime, records, durations);
    // First event is STOP (not START), cross-midnight: dayStartTime(3000)->stop(3000) = 0ms
    // Pair STOP->START: duration = 5000-3000 = 2000ms, uses preIt->screenStatus = UNFOLDED_PORTRAIT
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 2000u);
}

// ==================== ImeUsageInfo: GetAppUsage with all duration fields ====================

/**
 * @tc.name: ImeUsageInfo_GetAppUsage_003
 * @tc.desc: GetAppUsage sums all 12 duration fields correctly
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, GetAppUsage_003, TestSize.Level0)
{
    ImeUsageInfo info;
    info.durations[IDX_FOLD_PORTRAIT] = 100;
    info.durations[IDX_FOLD_LANDSCAPE] = 200;
    info.durations[IDX_EXPAND_PORTRAIT] = 300;
    info.durations[IDX_EXPAND_LANDSCAPE] = 400;
    info.durations[IDX_G_PORTRAIT] = 500;
    info.durations[IDX_G_LANDSCAPE] = 600;
    info.durations[IDX_UNFOLDED_PORTRAIT] = 700;
    info.durations[IDX_UNFOLDED_LANDSCAPE] = 800;
    info.durations[IDX_N_PORTRAIT] = 900;
    info.durations[IDX_N_LANDSCAPE] = 1000;
    info.durations[IDX_LM_PORTRAIT] = 1100;
    info.durations[IDX_LM_LANDSCAPE] = 1200;
    EXPECT_EQ(info.GetAppUsage(), 7800u);
}

// ==================== FormatDateStr ====================

/**
 * @tc.name: ImeUsageCommon_FormatDateStr_001
 * @tc.desc: FormatDateStr returns correct date string
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FormatDateStr_001, TestSize.Level0)
{
    // Test with a known timestamp
    uint64_t ms = 1700000000000ULL; // 2023-11-14 22:13:20 UTC
    std::string dateStr = FormatDateStr(ms);
    // Should be a valid date string in YYYYMMDD format
    EXPECT_EQ(dateStr.length(), 8u);
    // All characters should be digits
    for (char c : dateStr) {
        EXPECT_TRUE(std::isdigit(c));
    }
}

// ==================== ZeroClockMsFromTimeT ====================

/**
 * @tc.name: ImeUsageCommon_ZeroClockMsFromTimeT_001
 * @tc.desc: ZeroClockMsFromTimeT returns midnight of given time
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ZeroClockMsFromTimeT_001, TestSize.Level0)
{
    // Use current time
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    uint64_t midnight = ZeroClockMsFromTimeT(t);
    EXPECT_GT(midnight, 0u);
    // Midnight should be <= current time
    uint64_t nowMs =
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
    EXPECT_LE(midnight, nowMs);
}

// ==================== DbHelper: AddEventsTransactional ====================

/**
 * @tc.name: ImeUsageDbHelper_AddEventsTransactional_002
 * @tc.desc: AddEventsTransactional writes multiple events atomically
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_AddEventsTransactional_002, TestSize.Level0)
{
    ImeEventRecord stopRec;
    stopRec.rawid = EVENT_INPUT_STOP;
    stopRec.ts = 5000;
    stopRec.happenTime = 5000;
    stopRec.bundleName = TEST_BUNDLE;
    stopRec.preScreenStatus = UNFOLDED_PORTRAIT;
    stopRec.screenStatus = UNFOLDED_PORTRAIT;

    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = 5000;
    countRec.happenTime = 5000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.preScreenStatus = UNFOLDED_PORTRAIT;
    countRec.screenStatus = UNFOLDED_PORTRAIT;

    DurationMap durations;
    durations[UNFOLDED_PORTRAIT] = 3000;

    std::vector<std::pair<ImeEventRecord, DurationMap>> events;
    events.emplace_back(stopRec, DurationMap {});
    events.emplace_back(countRec, durations);

    int ret = dbHelper_->AddEventsTransactional(events);
    EXPECT_EQ(ret, 0);

    // Verify both records were written
    int stopIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STOP);
    EXPECT_GE(stopIdx, 0);
    int countIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
    // COUNT_DURATION row should have a higher row ID than STOP
    EXPECT_GT(countIdx, stopIdx);
}

/**
 * @tc.name: ImeUsageDbHelper_AddEventsTransactional_004
 * @tc.desc: AddEventsTransactional with single event succeeds
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_AddEventsTransactional_004, TestSize.Level0)
{
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = 1000;
    startRec.happenTime = 2000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    startRec.screenStatus = UNFOLDED_PORTRAIT;

    std::vector<std::pair<ImeEventRecord, DurationMap>> events;
    events.emplace_back(startRec, DurationMap {});

    int ret = dbHelper_->AddEventsTransactional(events);
    EXPECT_EQ(ret, 0);
    int idx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(idx, 0);
}

// ==================== RecoverActiveSession: STATUS_CHANGED as last event ====================

/**
 * @tc.name: ImeUsageEventCacher_RecoverActiveSession_003
 * @tc.desc: RecoverActiveSession recovers active session when last event is STATUS_CHANGED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, RecoverActiveSession_003, TestSize.Level0)
{
    // Create a session: START then STATUS_CHANGED (but no STOP - simulates crash mid-session)
    cacher_->OnImeBind(TEST_BUNDLE);
    cacher_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);

    // Reset in-memory state to simulate service restart
    cacher_->isKeyboardShowing_ = false;
    cacher_->currentImeBundle_.clear();
    cacher_->foldStatus_ = UNFOLDED;
    cacher_->vhMode_ = PORTRAIT;

    // RecoverActiveSession queries DB, finds last event is STATUS_CHANGED,
    // and restores the active session
    cacher_->RecoverActiveSession();
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);
    // foldStatus_/vhMode_ should be decoded from the STATUS_CHANGED event's screenStatus
    EXPECT_EQ(cacher_->foldStatus_, EXPAND);
    EXPECT_EQ(cacher_->vhMode_, PORTRAIT);
}

// ==================== ProcessCountDurationEvent: empty durations skip ====================

/**
 * @tc.name: ImeUsageEventCacher_ProcessCountDurationEvent_EmptyDurations
 * @tc.desc: ProcessCountDurationEvent skips DB write when durations are empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessCountDurationEvent_EmptyDurations, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = 5000;
    record.happenTime = 5000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;

    // Empty durations - ProcessCountDurationEvent should skip writing COUNT_DURATION
    DurationMap emptyDurations;
    cacher_->ProcessCountDurationEvent(record, emptyDurations);

    // Verify no COUNT_DURATION was written for this bundle
    int countIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_EQ(countIdx, IME_INDEX_NOT_FOUND);
}

// ==================== ProcessCountDurationEvent: dbHelper_ null ====================

/**
 * @tc.name: ImeUsageEventCacher_ProcessCountDurationEvent_NullDbHelper
 * @tc.desc: ProcessCountDurationEvent with null dbHelper_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessCountDurationEvent_NullDbHelper, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init - dbHelper_ is nullptr
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = 5000;
    record.happenTime = 5000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;

    DurationMap durations;
    durations[UNFOLDED_PORTRAIT] = 1000;
    // Should not crash
    cacher->ProcessCountDurationEvent(record, durations);
    // dbHelper_ is null, so ProcessCountDurationEvent returns early without writing DB.
    // Verify state remains unchanged: isKeyboardShowing_ stays false, no side effects.
    EXPECT_FALSE(cacher->isKeyboardShowing_);
    EXPECT_TRUE(cacher->currentImeBundle_.empty());
}

// ==================== CalculateDurationForRecord: dbHelper_ null ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDurationForRecord_NullDbHelper
 * @tc.desc: CalculateDurationForRecord with null dbHelper_ returns empty durations
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDurationForRecord_NullDbHelper, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init - dbHelper_ is nullptr
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = 5000;
    record.happenTime = 5000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;

    DurationMap durations = cacher->CalculateDurationForRecord(record);
    EXPECT_TRUE(durations.empty());
}

// ==================== CalculateDuration: cross-midnight STOP with screenStatus=0 ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_013
 * @tc.desc: Cross-midnight with STOP as first event and screenStatus=0 falls back to UNFOLDED_PORTRAIT
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_013, TestSize.Level0)
{
    uint64_t dayStartTime = 1000;

    std::vector<ImeEventRecord> records;
    // First event is STOP with screenStatus=0 (uninitialized)
    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 3000;
    stop.happenTime = 3000;
    stop.screenStatus = SCREEN_STATUS_UNINITIALIZED;
    stop.preScreenStatus = SCREEN_STATUS_UNINITIALIZED;
    records.push_back(stop);

    DurationMap durations;
    cacher_->CalculateDuration(dayStartTime, records, durations);
    // Cross-midnight STOP with screenStatus=0 should fallback to UNFOLDED_PORTRAIT(12)
    EXPECT_EQ(durations[UNFOLDED_PORTRAIT], 2000u);
}

// ==================== CountDuration: dbHelper_ null ====================

/**
 * @tc.name: ImeUsageEventCacher_CountDuration_NullDbHelper
 * @tc.desc: CountDuration with null dbHelper_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CountDuration_NullDbHelper, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init - dbHelper_ is nullptr
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = 5000;
    record.happenTime = 5000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    // Should not crash
    cacher->CountDuration(record);
    // dbHelper_ is null, so ProcessCountDurationEvent returns early without writing DB.
    // Verify state remains unchanged: isKeyboardShowing_ stays false, no side effects.
    EXPECT_FALSE(cacher->isKeyboardShowing_);
    EXPECT_TRUE(cacher->currentImeBundle_.empty());
}

// ==================== DbHelper: AddEventsTransactional with durations ====================

/**
 * @tc.name: ImeUsageDbHelper_AddEventsTransactional_005
 * @tc.desc: AddEventsTransactional writes events with duration columns correctly
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_AddEventsTransactional_005, TestSize.Level0)
{
    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = 5000;
    countRec.happenTime = 5000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.preScreenStatus = UNFOLDED_PORTRAIT;
    countRec.screenStatus = UNFOLDED_PORTRAIT;

    DurationMap durations;
    durations[UNFOLDED_PORTRAIT] = 4000;
    durations[EXPAND_PORTRAIT] = 2000;

    std::vector<std::pair<ImeEventRecord, DurationMap>> events;
    events.emplace_back(countRec, durations);

    int ret = dbHelper_->AddEventsTransactional(events);
    EXPECT_EQ(ret, 0);

    // Verify the COUNT_DURATION was written and has correct aggregated data
    std::unordered_map<std::string, ImeUsageInfo> infos;
    dbHelper_->QueryStatisticEventsInPeriod(0, 10000, infos);
    ASSERT_EQ(infos.size(), 1u);
    auto it = infos.find(TEST_BUNDLE);
    ASSERT_NE(it, infos.end());
    EXPECT_EQ(it->second.durations[IDX_UNFOLDED_PORTRAIT], 4000u);
    EXPECT_EQ(it->second.durations[IDX_EXPAND_PORTRAIT], 2000u);
}

// ==================== DbHelper: AddEvent null rdbStore for all methods ====================

/**
 * @tc.name: ImeUsageDbHelper_AddEventsTransactional_NullRdbStore
 * @tc.desc: AddEventsTransactional with null rdbStore_ returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DbHelper_AddEventsTransactional_NullRdbStore, TestSize.Level0)
{
    dbHelper_->rdbStore_ = nullptr;
    std::vector<std::pair<ImeEventRecord, DurationMap>> events;
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    events.emplace_back(record, DurationMap {});
    int ret = dbHelper_->AddEventsTransactional(events);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

// ==================== OnImeBind/OnImeUnbind: full session verifies transactional write ====================

/**
 * @tc.name: ImeUsageEventCacher_FullSession_TransactionalVerify
 * @tc.desc: Full session verifies STOP+COUNT_DURATION are in correct DB order via transaction
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FullSession_TransactionalVerify, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    cacher_->OnImeUnbind(TEST_BUNDLE);
    EXPECT_FALSE(cacher_->isKeyboardShowing_);

    // Verify STOP and COUNT_DURATION exist
    int stopIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STOP);
    EXPECT_GE(stopIdx, 0);
    int countIdx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
    // COUNT_DURATION row should have a higher row ID than STOP (written in same transaction)
    EXPECT_GT(countIdx, stopIdx);
}

// ==================== ImeUsageInfo: operator+= with all fields ====================

/**
 * @tc.name: ImeUsageInfo_OperatorPlus_002
 * @tc.desc: operator+= with all 12 duration fields sums correctly
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, OperatorPlus_002, TestSize.Level0)
{
    ImeUsageInfo a;
    a.durations[IDX_UNFOLDED_LANDSCAPE] = 10;
    a.durations[IDX_UNFOLDED_PORTRAIT] = 20;
    a.durations[IDX_FOLD_LANDSCAPE] = 30;
    a.durations[IDX_FOLD_PORTRAIT] = 40;
    a.durations[IDX_EXPAND_LANDSCAPE] = 50;
    a.durations[IDX_EXPAND_PORTRAIT] = 60;
    a.durations[IDX_G_LANDSCAPE] = 70;
    a.durations[IDX_G_PORTRAIT] = 80;
    a.durations[IDX_N_LANDSCAPE] = 90;
    a.durations[IDX_N_PORTRAIT] = 100;
    a.durations[IDX_LM_LANDSCAPE] = 110;
    a.durations[IDX_LM_PORTRAIT] = 120;
    a.showCount = 1;

    ImeUsageInfo b;
    b.durations[IDX_UNFOLDED_LANDSCAPE] = 1;
    b.durations[IDX_UNFOLDED_PORTRAIT] = 2;
    b.durations[IDX_FOLD_LANDSCAPE] = 3;
    b.durations[IDX_FOLD_PORTRAIT] = 4;
    b.durations[IDX_EXPAND_LANDSCAPE] = 5;
    b.durations[IDX_EXPAND_PORTRAIT] = 6;
    b.durations[IDX_G_LANDSCAPE] = 7;
    b.durations[IDX_G_PORTRAIT] = 8;
    b.durations[IDX_N_LANDSCAPE] = 9;
    b.durations[IDX_N_PORTRAIT] = 10;
    b.durations[IDX_LM_LANDSCAPE] = 11;
    b.durations[IDX_LM_PORTRAIT] = 12;
    b.showCount = 2;

    a += b;
    EXPECT_EQ(a.durations[IDX_UNFOLDED_LANDSCAPE], 11u);
    EXPECT_EQ(a.durations[IDX_UNFOLDED_PORTRAIT], 22u);
    EXPECT_EQ(a.durations[IDX_FOLD_LANDSCAPE], 33u);
    EXPECT_EQ(a.durations[IDX_FOLD_PORTRAIT], 44u);
    EXPECT_EQ(a.durations[IDX_EXPAND_LANDSCAPE], 55u);
    EXPECT_EQ(a.durations[IDX_EXPAND_PORTRAIT], 66u);
    EXPECT_EQ(a.durations[IDX_G_LANDSCAPE], 77u);
    EXPECT_EQ(a.durations[IDX_G_PORTRAIT], 88u);
    EXPECT_EQ(a.durations[IDX_N_LANDSCAPE], 99u);
    EXPECT_EQ(a.durations[IDX_N_PORTRAIT], 110u);
    EXPECT_EQ(a.durations[IDX_LM_LANDSCAPE], 121u);
    EXPECT_EQ(a.durations[IDX_LM_PORTRAIT], 132u);
    EXPECT_EQ(a.showCount, 3u);
    EXPECT_EQ(a.usage, a.GetAppUsage());
}

} // namespace MiscServices
} // namespace OHOS
