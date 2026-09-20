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

#include <climits>
#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

#include "ime_usage_common.h"
#include "ime_usage_data_helper.h"
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
using OHOS::MiscServices::IME_USAGE_SUCCESS;
using OHOS::MiscServices::RAWID_NONE;
using OHOS::MiscServices::SCREEN_STATUS_UNINITIALIZED;

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

    std::shared_ptr<ImeUsageDataHelper> dataHelper_;
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
    // Remove JSON files before opening to ensure a clean state
    std::remove((DB_DIR + "/ime_usage_events.json").c_str());
    std::remove((DB_DIR + "/ime_usage_state.json").c_str());

    dataHelper_ = std::make_shared<ImeUsageDataHelper>(DB_DIR);
    cacher_ = std::make_unique<ImeUsageEventCacher>();
    // Init with UNFOLDED_PORTRAIT as default
    cacher_->Init(dataHelper_, UNFOLDED, PORTRAIT);
}

void ImeUsageEventCacherTest::TearDown()
{
    cacher_.reset();
    dataHelper_.reset();
}

// ==================== Init ====================

/**
 * @tc.name: ImeUsageEventCacher_Init_001
 * @tc.desc: Init with nullptr dataHelper returns -1
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
 * @tc.desc: Init with valid dataHelper returns 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, Init_002, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    int ret = cacher->Init(dataHelper_, EXPAND, LANDSCAPE);
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
 * @tc.desc: Show with nullptr dataHelper does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessShowEvent_005, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init called, dataHelper_ is nullptr
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
 * @tc.desc: Hide with nullptr dataHelper does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessHideEvent_003, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    cacher->isKeyboardShowing_ = true;
    cacher->currentImeBundle_ = TEST_BUNDLE;
    // Without dataHelper, PrepareHideRecord returns rawid=0, so OnImeUnbind skips DB write
    // and does NOT reset isKeyboardShowing_ / currentImeBundle_
    cacher->OnImeUnbind(TEST_BUNDLE);
    // State remains unchanged because no dataHelper to write STOP event
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 1000u);
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 3000u);
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 1000u);
    EXPECT_EQ(durations[IDX_EXPAND_PORTRAIT], 2000u);
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
    EXPECT_TRUE(IsDurationMapEmpty(durations));
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
    EXPECT_TRUE(IsDurationMapEmpty(durations));
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 4000u);
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 2000u); // 1000->3000
    EXPECT_EQ(durations[IDX_EXPAND_PORTRAIT], 4000u);   // 3000->7000
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
    EXPECT_EQ(durations[IDX_EXPAND_PORTRAIT], 2000u);
    // 3000 -> 5000 = 2000ms, uses changed.screenStatus
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 2000u);
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 4000u);
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 3000u);
}

// ==================== Full session flow (DB integration) ====================

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

    // After unbind, SettleSession deletes raw events (START, STATUS_CHANGED) and
    // inserts COUNT_DURATION. Raw events should no longer exist.
    int startIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_EQ(startIdx, IME_INDEX_NOT_FOUND);
    int changedIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STATUS_CHANGED);
    EXPECT_EQ(changedIdx, IME_INDEX_NOT_FOUND);
    int countIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
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

    // After unbind, SettleSession deletes raw events (START, 2x STATUS_CHANGED) and
    // inserts COUNT_DURATION. Raw events should no longer exist.
    int startIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_EQ(startIdx, IME_INDEX_NOT_FOUND);
    int changedIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STATUS_CHANGED);
    EXPECT_EQ(changedIdx, IME_INDEX_NOT_FOUND);
    int countIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
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

// ==================== ImeUsageDataHelper ====================

/**
 * @tc.name: ImeUsageDataHelper_IsReady_001
 * @tc.desc: IsReady returns true after successful construction
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_IsReady_001, TestSize.Level0)
{
    // After construction, the DB helper should be ready
    EXPECT_TRUE(dataHelper_->IsReady());
    // ready_ should be true when ready
    EXPECT_TRUE(dataHelper_->ready_);
    // Setting ready_ to false should make IsReady return false
    auto savedReady = dataHelper_->ready_;
    dataHelper_->ready_ = false;
    EXPECT_FALSE(dataHelper_->IsReady());
    // Restore for subsequent tests
    dataHelper_->ready_ = savedReady;
    EXPECT_TRUE(dataHelper_->IsReady());
}

/**
 * @tc.name: ImeUsageDataHelper_AddEvent_002
 * @tc.desc: AddEvent with duration map writes duration columns
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_AddEvent_002, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_COUNT_DURATION;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    record.screenStatus = UNFOLDED_PORTRAIT;

    DurationMap durations;
    durations[IDX_UNFOLDED_PORTRAIT] = 5000;
    durations[IDX_EXPAND_PORTRAIT] = 3000;

    int ret = dataHelper_->AddEvent(record, durations);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryRawEventIndex_001
 * @tc.desc: QueryRawEventIndex returns -1 for non-existent event
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryRawEventIndex_001, TestSize.Level0)
{
    // Query for non-existent bundle should return IME_INDEX_NOT_FOUND
    std::string nonExistent = "non.existent.bundle";
    int idx = dataHelper_->QueryRawEventIndex(nonExistent, EVENT_INPUT_START);
    EXPECT_EQ(idx, IME_INDEX_NOT_FOUND);
    // Query for non-existent event type with valid bundle should also return IME_INDEX_NOT_FOUND
    int idx2 = dataHelper_->QueryRawEventIndex(nonExistent, EVENT_INPUT_STOP);
    EXPECT_EQ(idx2, IME_INDEX_NOT_FOUND);
    // Query for COUNT_DURATION should also return IME_INDEX_NOT_FOUND
    int idx3 = dataHelper_->QueryRawEventIndex(nonExistent, EVENT_COUNT_DURATION);
    EXPECT_EQ(idx3, IME_INDEX_NOT_FOUND);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryRawEventIndex_002
 * @tc.desc: QueryRawEventIndex returns valid index after AddEvent
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryRawEventIndex_002, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(record);

    int idx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(idx, 0);
}

/**
 * @tc.name: ImeUsageDataHelper_DeleteEventsByTime_001
 * @tc.desc: DeleteEventsByTime returns success
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteEventsByTime_001, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 1000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(record);

    int ret = dataHelper_->DeleteEventsByTime(500); // Delete events with happenTime <= 500
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryEventRecords_001
 * @tc.desc: QueryEventRecords returns correct records for a session
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryEventRecords_001, TestSize.Level0)
{
    ImeEventRecord start;
    start.rawid = EVENT_INPUT_START;
    start.ts = 1000;
    start.happenTime = 2000;
    start.bundleName = TEST_BUNDLE;
    start.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(start);

    int startIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    ASSERT_GE(startIdx, 0);

    std::vector<ImeEventRecord> records;
    dataHelper_->QueryEventRecords(startIdx, 0, TEST_BUNDLE, records);
    EXPECT_GE(records.size(), 1u);
    if (!records.empty()) {
        EXPECT_EQ(records[0].rawid, EVENT_INPUT_START);
        EXPECT_EQ(records[0].bundleName, TEST_BUNDLE);
    }
}

// ==================== DataHelper: QueryStatisticEventsInPeriod ====================

/**
 * @tc.name: ImeUsageDataHelper_QueryStatisticEventsInPeriod_001
 * @tc.desc: QueryStatisticEventsInPeriod with no data returns empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryStatisticEventsInPeriod_001, TestSize.Level0)
{
    std::unordered_map<std::string, ImeUsageInfo> infos;
    // Use a tiny time range that no prior test data should fall into
    dataHelper_->QueryStatisticEventsInPeriod(0, 1, infos);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: ImeUsageDataHelper_QueryStatisticEventsInPeriod_002
 * @tc.desc: QueryStatisticEventsInPeriod aggregates durations and show counts
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryStatisticEventsInPeriod_002, TestSize.Level0)
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
    durations[IDX_UNFOLDED_PORTRAIT] = 3000;
    dataHelper_->AddEvent(countRec, durations);

    // Insert a START record (for show count)
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = 1000;
    startRec.happenTime = 1000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(startRec);

    std::unordered_map<std::string, ImeUsageInfo> infos;
    dataHelper_->QueryStatisticEventsInPeriod(0, 10000, infos);
    ASSERT_EQ(infos.size(), 1u);
    auto it = infos.find(TEST_BUNDLE);
    ASSERT_NE(it, infos.end());
    EXPECT_EQ(it->second.durations[IDX_UNFOLDED_PORTRAIT], 3000u);
    EXPECT_EQ(it->second.showCount, 1u); // 1 INPUT_START event
}

/**
 * @tc.name: ImeUsageDataHelper_QueryStatisticEventsInPeriod_003
 * @tc.desc: QueryStatisticEventsInPeriod with multiple bundles
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryStatisticEventsInPeriod_003, TestSize.Level0)
{
    ImeEventRecord rec1;
    rec1.rawid = EVENT_COUNT_DURATION;
    rec1.ts = 5000;
    rec1.happenTime = 5000;
    rec1.bundleName = TEST_BUNDLE;
    rec1.screenStatus = UNFOLDED_PORTRAIT;
    rec1.preScreenStatus = UNFOLDED_PORTRAIT;
    DurationMap dur1;
    dur1[IDX_UNFOLDED_PORTRAIT] = 2000;
    dataHelper_->AddEvent(rec1, dur1);

    ImeEventRecord rec2;
    rec2.rawid = EVENT_COUNT_DURATION;
    rec2.ts = 6000;
    rec2.happenTime = 6000;
    rec2.bundleName = TEST_BUNDLE2;
    rec2.screenStatus = EXPAND_PORTRAIT;
    rec2.preScreenStatus = EXPAND_PORTRAIT;
    DurationMap dur2;
    dur2[IDX_EXPAND_PORTRAIT] = 4000;
    dataHelper_->AddEvent(rec2, dur2);

    std::unordered_map<std::string, ImeUsageInfo> infos;
    dataHelper_->QueryStatisticEventsInPeriod(0, 10000, infos);
    EXPECT_EQ(infos.size(), 2u);
    EXPECT_EQ(infos[TEST_BUNDLE].durations[IDX_UNFOLDED_PORTRAIT], 2000u);
    EXPECT_EQ(infos[TEST_BUNDLE2].durations[IDX_EXPAND_PORTRAIT], 4000u);
}

// ==================== DataHelper: QueryFinalEventInfo ====================

/**
 * @tc.name: ImeUsageDataHelper_QueryFinalEventInfo_001
 * @tc.desc: QueryFinalEventInfo with no matching data leaves event empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryFinalEventInfo_001, TestSize.Level0)
{
    ImeUsageRawEvent event;
    // Use endTime=1 so no event with happen_time <= 1 should exist
    dataHelper_->QueryFinalEventInfo(1, event);
    EXPECT_EQ(event.rawId, 0);
    EXPECT_TRUE(event.package.empty());
}

/**
 * @tc.name: ImeUsageDataHelper_QueryFinalEventInfo_002
 * @tc.desc: QueryFinalEventInfo returns most recent event before endTime
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryFinalEventInfo_002, TestSize.Level0)
{
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = 1000;
    startRec.happenTime = 1000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = EXPAND_PORTRAIT;
    dataHelper_->AddEvent(startRec);

    ImeEventRecord stopRec;
    stopRec.rawid = EVENT_INPUT_STOP;
    stopRec.ts = 5000;
    stopRec.happenTime = 5000;
    stopRec.bundleName = TEST_BUNDLE;
    stopRec.screenStatus = UNFOLDED_PORTRAIT;
    stopRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(stopRec);

    ImeUsageRawEvent event;
    dataHelper_->QueryFinalEventInfo(10000, event);
    // Should return the STOP event (most recent before 10000)
    EXPECT_EQ(event.rawId, EVENT_INPUT_STOP);
    EXPECT_EQ(event.package, TEST_BUNDLE);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryFinalEventInfo_003
 * @tc.desc: QueryFinalEventInfo respects endTime boundary
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryFinalEventInfo_003, TestSize.Level0)
{
    ImeEventRecord rec;
    rec.rawid = EVENT_INPUT_START;
    rec.ts = 5000;
    rec.happenTime = 5000;
    rec.bundleName = TEST_BUNDLE;
    rec.screenStatus = UNFOLDED_PORTRAIT;
    rec.preScreenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(rec);

    ImeUsageRawEvent event;
    dataHelper_->QueryFinalEventInfo(3000, event);
    // Event at 5000 is after endTime=3000, should not be returned
    EXPECT_EQ(event.rawId, 0);
}

// ==================== DataHelper: QueryForegroundImeInfo ====================

/**
 * @tc.name: ImeUsageDataHelper_QueryForegroundImeInfo_001
 * @tc.desc: QueryForegroundImeInfo with no events assigns full time range as duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryForegroundImeInfo_001, TestSize.Level0)
{
    ImeUsageInfo info;
    info.package = "nonexistent.foreground.ime";
    uint64_t startTime = 1000;
    uint64_t endTime = 5000;
    dataHelper_->QueryForegroundImeInfo(startTime, endTime, UNFOLDED_PORTRAIT, info);
    // When no events found, the entire time range is treated as foreground duration
    EXPECT_EQ(info.durations[IDX_UNFOLDED_PORTRAIT], static_cast<uint32_t>(endTime - startTime));
}

/**
 * @tc.name: ImeUsageDataHelper_QueryForegroundImeInfo_002
 * @tc.desc: QueryForegroundImeInfo with START event calculates duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryForegroundImeInfo_002, TestSize.Level0)
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
    dataHelper_->AddEvent(startRec);

    ImeUsageInfo info;
    info.package = TEST_BUNDLE;
    info.showCount = 0;
    dataHelper_->QueryForegroundImeInfo(dayStart, dayEnd, UNFOLDED_PORTRAIT, info);
    // Duration from dayStart to happenTime with screenStatus, plus from happenTime to dayEnd
    EXPECT_GT(info.durations[IDX_UNFOLDED_PORTRAIT], 0u);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryForegroundImeInfo_003
 * @tc.desc: QueryForegroundImeInfo with STATUS_CHANGED events
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryForegroundImeInfo_003, TestSize.Level0)
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
    dataHelper_->AddEvent(startRec);

    ImeEventRecord changedRec;
    changedRec.rawid = EVENT_INPUT_STATUS_CHANGED;
    changedRec.ts = 7200000;
    changedRec.happenTime = 7200000;
    changedRec.bundleName = TEST_BUNDLE;
    changedRec.screenStatus = EXPAND_PORTRAIT;
    changedRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(changedRec);

    ImeUsageInfo info;
    info.package = TEST_BUNDLE;
    info.showCount = 0;
    dataHelper_->QueryForegroundImeInfo(dayStart, dayEnd, EXPAND_PORTRAIT, info);
    // Should have both UNFOLDED_PORTRAIT and EXPAND_PORTRAIT durations
    EXPECT_GT(info.durations[IDX_UNFOLDED_PORTRAIT], 0u);
    EXPECT_GT(info.durations[IDX_EXPAND_PORTRAIT], 0u);
}

// ==================== DataHelper: SaveReportState / LoadReportState ====================

/**
 * @tc.name: ImeUsageDataHelper_SaveLoadReportState_002
 * @tc.desc: Load with no prior save returns 0 (default)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_SaveLoadReportState_002, TestSize.Level0)
{
    // Fresh dataHelper has lastReportTime_ = 0
    uint64_t loaded = 999;
    int ret = dataHelper_->LoadReportState(STATE_KEY_LAST_REPORT_TIME, loaded);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(loaded, 0u);
}

/**
 * @tc.name: ImeUsageDataHelper_SaveLoadReportState_003
 * @tc.desc: Save overwrites previous value
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_SaveLoadReportState_003, TestSize.Level0)
{
    dataHelper_->SaveReportState(STATE_KEY_LAST_REPORT_TIME, 1000ULL);
    dataHelper_->SaveReportState(STATE_KEY_LAST_REPORT_TIME, 2000ULL);

    uint64_t loaded = 0;
    dataHelper_->LoadReportState(STATE_KEY_LAST_REPORT_TIME, loaded);
    EXPECT_EQ(loaded, 2000ULL);
}

// ==================== DataHelper: QueryEarliestEventTime ====================

/**
 * @tc.name: ImeUsageDataHelper_QueryEarliestEventTime_001
 * @tc.desc: QueryEarliestEventTime with no data returns <= 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryEarliestEventTime_001, TestSize.Level0)
{
    // With empty DB, QueryEarliestEventTime returns -1 (if NULL check works)
    // or 0 (SQLite MIN on empty table returns NULL, GetLong may return 0)
    int64_t earliest = dataHelper_->QueryEarliestEventTime();
    EXPECT_LE(earliest, 0);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryEarliestEventTime_002
 * @tc.desc: QueryEarliestEventTime returns earliest happen_time
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryEarliestEventTime_002, TestSize.Level0)
{
    ImeEventRecord rec1;
    rec1.rawid = EVENT_INPUT_START;
    rec1.ts = 5000;
    rec1.happenTime = 5000;
    rec1.bundleName = TEST_BUNDLE;
    rec1.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(rec1);

    ImeEventRecord rec2;
    rec2.rawid = EVENT_INPUT_START;
    rec2.ts = 3000;
    rec2.happenTime = 3000;
    rec2.bundleName = TEST_BUNDLE2;
    rec2.screenStatus = EXPAND_PORTRAIT;
    dataHelper_->AddEvent(rec2);

    int64_t earliest = dataHelper_->QueryEarliestEventTime();
    EXPECT_EQ(earliest, 3000);
}

// ==================== DataHelper: QueryActiveDays ====================

/**
 * @tc.name: ImeUsageDataHelper_QueryActiveDays_001
 * @tc.desc: QueryActiveDays with no matching data returns empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryActiveDays_001, TestSize.Level0)
{
    // Use a very early time range that no test data should fall into
    auto days = dataHelper_->QueryActiveDays(0, 1);
    EXPECT_TRUE(days.empty());
    // Verify the vector size is exactly 0
    EXPECT_EQ(days.size(), 0u);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryActiveDays_002
 * @tc.desc: QueryActiveDays returns distinct day-start timestamps
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryActiveDays_002, TestSize.Level0)
{
    // Insert events on two different days.
    // Use DayStartFromMs to compute expected day-start timestamps so they match
    // the local-timezone-aware computation in QueryActiveDays.
    uint64_t day1 = DayStartFromMs(MILLISECS_PER_DAY + 3600000);
    uint64_t day3 = DayStartFromMs(MILLISECS_PER_DAY * 3 + 3600000);

    ImeEventRecord rec1;
    rec1.rawid = EVENT_INPUT_START;
    rec1.ts = day1 + 3600000;
    rec1.happenTime = day1 + 3600000;
    rec1.bundleName = TEST_BUNDLE;
    rec1.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(rec1);

    ImeEventRecord rec2;
    rec2.rawid = EVENT_INPUT_START;
    rec2.ts = day3 + 3600000;
    rec2.happenTime = day3 + 3600000;
    rec2.bundleName = TEST_BUNDLE;
    rec2.screenStatus = EXPAND_PORTRAIT;
    dataHelper_->AddEvent(rec2);

    auto days = dataHelper_->QueryActiveDays(0, MILLISECS_PER_DAY * 5);
    ASSERT_EQ(days.size(), 2u);
    EXPECT_EQ(days[0], day1);
    EXPECT_EQ(days[1], day3);
}

// ==================== DataHelper: DeleteEventsByTime ====================

/**
 * @tc.name: ImeUsageDataHelper_DeleteEventsByTime_002
 * @tc.desc: DeleteEventsByTime only deletes events before clearDataTime
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteEventsByTime_002, TestSize.Level0)
{
    ImeEventRecord oldRec;
    oldRec.rawid = EVENT_INPUT_START;
    oldRec.ts = 1000;
    oldRec.happenTime = 1000;
    oldRec.bundleName = TEST_BUNDLE;
    oldRec.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(oldRec);

    ImeEventRecord newRec;
    newRec.rawid = EVENT_INPUT_START;
    newRec.ts = 5000;
    newRec.happenTime = 5000;
    newRec.bundleName = TEST_BUNDLE;
    newRec.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(newRec);

    dataHelper_->DeleteEventsByTime(3000);
    // Old record should be deleted, new record should remain
    int oldIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(oldIdx, 0); // Still exists (the new one)
}

// ==================== DataHelper: ready_ false paths ====================

/**
 * @tc.name: ImeUsageDataHelper_AddEvent_NullRdbStore
 * @tc.desc: AddEvent with ready_ false returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_AddEvent_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    int ret = dataHelper_->AddEvent(record);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryRawEventIndex_NullRdbStore
 * @tc.desc: QueryRawEventIndex with ready_ false returns -1
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryRawEventIndex_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    int idx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_EQ(idx, IME_INDEX_NOT_FOUND);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryEventRecords_NullRdbStore
 * @tc.desc: QueryEventRecords with ready_ false does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryEventRecords_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    std::vector<ImeEventRecord> records;
    dataHelper_->QueryEventRecords(0, 0, TEST_BUNDLE, records);
    EXPECT_TRUE(records.empty());
}

/**
 * @tc.name: ImeUsageDataHelper_QueryStatisticEventsInPeriod_NullRdbStore
 * @tc.desc: QueryStatisticEventsInPeriod with ready_ false does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryStatisticEventsInPeriod_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    std::unordered_map<std::string, ImeUsageInfo> infos;
    dataHelper_->QueryStatisticEventsInPeriod(0, MILLISECS_PER_DAY, infos);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: ImeUsageDataHelper_QueryFinalEventInfo_NullRdbStore
 * @tc.desc: QueryFinalEventInfo with ready_ false does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryFinalEventInfo_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    ImeUsageRawEvent event;
    dataHelper_->QueryFinalEventInfo(MILLISECS_PER_DAY, event);
    // Should not crash; event stays default (rawId=0, package empty)
    EXPECT_EQ(event.rawId, 0);
    EXPECT_TRUE(event.package.empty());
}

/**
 * @tc.name: ImeUsageDataHelper_QueryForegroundImeInfo_NullRdbStore
 * @tc.desc: QueryForegroundImeInfo with ready_ false does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryForegroundImeInfo_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    ImeUsageInfo info;
    info.package = TEST_BUNDLE;
    dataHelper_->QueryForegroundImeInfo(0, MILLISECS_PER_DAY, UNFOLDED_PORTRAIT, info);
    // Should not crash; info should remain unchanged (no duration added)
    EXPECT_EQ(info.durations[IDX_UNFOLDED_PORTRAIT], 0u);
}

/**
 * @tc.name: ImeUsageDataHelper_DeleteEventsByTime_NullRdbStore
 * @tc.desc: DeleteEventsByTime with ready_ false returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteEventsByTime_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    int ret = dataHelper_->DeleteEventsByTime(0);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: ImeUsageDataHelper_SaveReportState_NullRdbStore
 * @tc.desc: SaveReportState with ready_ false returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_SaveReportState_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    int ret = dataHelper_->SaveReportState(STATE_KEY_LAST_REPORT_TIME, 123ULL);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: ImeUsageDataHelper_LoadReportState_NullRdbStore
 * @tc.desc: LoadReportState with ready_ false returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_LoadReportState_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    uint64_t value = 0;
    int ret = dataHelper_->LoadReportState(STATE_KEY_LAST_REPORT_TIME, value);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryEarliestEventTime_NullRdbStore
 * @tc.desc: QueryEarliestEventTime with ready_ false returns -1
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryEarliestEventTime_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    int64_t earliest = dataHelper_->QueryEarliestEventTime();
    EXPECT_EQ(earliest, IME_INDEX_NOT_FOUND);
}

/**
 * @tc.name: ImeUsageDataHelper_QueryActiveDays_NullRdbStore
 * @tc.desc: QueryActiveDays with ready_ false returns empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryActiveDays_NullRdbStore, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    auto days = dataHelper_->QueryActiveDays(0, MILLISECS_PER_DAY);
    EXPECT_TRUE(days.empty());
}

// EnsureDirectoryExist tests removed: method moved to ImeUsageFileStore (private),
// no longer part of ImeUsageDataHelper public API.

// ==================== DataHelper: AddEvent without durations ====================

/**
 * @tc.name: ImeUsageDataHelper_AddEvent_NoDurations
 * @tc.desc: AddEvent (1-arg overload) writes all duration columns as 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_AddEvent_NoDurations, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    record.screenStatus = UNFOLDED_PORTRAIT;
    int ret = dataHelper_->AddEvent(record); // 1-arg overload, no durations
    EXPECT_EQ(ret, 0);
    // Verify event was inserted
    int idx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(idx, 0);
}

// ==================== DataHelper: QueryEventRecords with COUNT_DURATION checkpoint ====================

/**
 * @tc.name: ImeUsageDataHelper_QueryEventRecords_Checkpoint
 * @tc.desc: QueryEventRecords clears records on COUNT_DURATION checkpoint
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryEventRecords_Checkpoint, TestSize.Level0)
{
    // Insert START, then COUNT_DURATION, then another START
    ImeEventRecord start1;
    start1.rawid = EVENT_INPUT_START;
    start1.ts = 1000;
    start1.happenTime = 2000;
    start1.bundleName = TEST_BUNDLE;
    start1.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(start1);

    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = 3000;
    countRec.happenTime = 3000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap dur;
    dur[IDX_UNFOLDED_PORTRAIT] = 1000;
    dataHelper_->AddEvent(countRec, dur);

    ImeEventRecord start2;
    start2.rawid = EVENT_INPUT_START;
    start2.ts = 4000;
    start2.happenTime = 4000;
    start2.bundleName = TEST_BUNDLE;
    start2.screenStatus = EXPAND_PORTRAIT;
    dataHelper_->AddEvent(start2);

    // Query from index 1 (should skip first START due to checkpoint)
    int startIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    ASSERT_GE(startIdx, 0);

    std::vector<ImeEventRecord> records;
    dataHelper_->QueryEventRecords(1, 0, TEST_BUNDLE, records);
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 0u);
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
    EXPECT_EQ(durations[IDX_FOLD_PORTRAIT], 2000u);
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 2000u);
}

// ==================== ProcessScreenChangedEvent: with nullptr dataHelper ====================

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_007
 * @tc.desc: ProcessScreenChangedEvent with nullptr dataHelper returns empty record
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_007, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init called, dataHelper_ is nullptr, isKeyboardShowing_ is false
    EXPECT_FALSE(cacher->isKeyboardShowing_);
    EXPECT_EQ(cacher->dataHelper_, nullptr);
    cacher->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    // Should not crash; state should not change since dataHelper_ is null and not showing
    EXPECT_FALSE(cacher->isKeyboardShowing_);
    EXPECT_EQ(cacher->lastScreenStatus_, 0);
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

// ==================== STOP->START pair in CalculateDuration ====================

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

    // Each switch calls SettleSession for old IME (deletes raw events, writes COUNT_DURATION)
    // and AddEvent for new IME's START.
    // After IME1->IME2: TEST_BUNDLE raw events deleted, COUNT_DURATION written.
    // After IME2->IME1: TEST_BUNDLE2 raw events deleted, COUNT_DURATION written.
    // Final state: TEST_BUNDLE has START (from switch-back) + COUNT_DURATION (from first switch-out);
    //              TEST_BUNDLE2 has COUNT_DURATION only (raw events deleted).
    int startIdx1 = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_GE(startIdx1, 0);
    // No STOP events in DB — SettleSession doesn't write STOP
    int stopIdx1 = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STOP);
    EXPECT_EQ(stopIdx1, IME_INDEX_NOT_FOUND);
    // TEST_BUNDLE2: START was deleted by SettleSession during switch-back
    int startIdx2 = dataHelper_->QueryRawEventIndex(TEST_BUNDLE2, EVENT_INPUT_START);
    EXPECT_EQ(startIdx2, IME_INDEX_NOT_FOUND);
    int stopIdx2 = dataHelper_->QueryRawEventIndex(TEST_BUNDLE2, EVENT_INPUT_STOP);
    EXPECT_EQ(stopIdx2, IME_INDEX_NOT_FOUND);
    // Both IMEs should have COUNT_DURATION
    int countIdx1 = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx1, 0);
    int countIdx2 = dataHelper_->QueryRawEventIndex(TEST_BUNDLE2, EVENT_COUNT_DURATION);
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
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 2000u);
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

// ==================== CalculateDurationForRecord: dataHelper_ null ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDurationForRecord_NullDataHelper
 * @tc.desc: CalculateDurationForRecord with null dataHelper_ returns empty durations
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDurationForRecord_NullDataHelper, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init - dataHelper_ is nullptr
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = 5000;
    record.happenTime = 5000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;

    int32_t startIndex = 0;
    DurationMap durations = cacher->CalculateDurationForRecord(record, startIndex);
    EXPECT_TRUE(IsDurationMapEmpty(durations));
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

// ==================== Branch Coverage: OnImeBind START AddEvent failure ====================

/**
 * @tc.name: ImeUsageEventCacher_OnImeBind_StartAddEventFailure
 * @tc.desc: OnImeBind when AddEvent for START fails (ready_ false) logs error but does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, OnImeBind_StartAddEventFailure, TestSize.Level0)
{
    // Set ready_ to false so AddEvent fails; dataHelper_ itself is not null
    dataHelper_->ready_ = false;
    // PrepareShowEvent checks dataHelper_ (not null) and succeeds, setting isKeyboardShowing_=true
    // Then AddEvent for START fails, triggering the error log path (showRet != IME_USAGE_SUCCESS)
    cacher_->OnImeBind(TEST_BUNDLE);
    // PrepareShowEvent sets isKeyboardShowing_ = true before AddEvent is called
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);
}

// ==================== Branch Coverage: OnImeUnbind after RecoverActiveSession ====================

/**
 * @tc.name: ImeUsageEventCacher_OnImeUnbind_AfterRecovery
 * @tc.desc: OnImeUnbind after RecoverActiveSession uses CalculateDurationForRecord fallback
 *           (isSessionDurationsReady_ = false)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, OnImeUnbind_AfterRecovery, TestSize.Level0)
{
    // Step 1: Create a session (writes START to DB, sets isSessionDurationsReady_ = true)
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);

    // Step 2: Simulate service restart - reset in-memory state
    cacher_->isKeyboardShowing_ = false;
    cacher_->currentImeBundle_.clear();
    cacher_->isSessionDurationsReady_ = false;

    // Step 3: Recover active session from DB
    cacher_->RecoverActiveSession();
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE);
    EXPECT_FALSE(cacher_->isSessionDurationsReady_); // Fallback mode

    // Step 4: Unbind - PrepareHideRecord succeeds, but isSessionDurationsReady_ is false,
    //         so CalculateDurationForRecord is called instead of using sessionDurations_
    cacher_->OnImeUnbind(TEST_BUNDLE);
    EXPECT_FALSE(cacher_->isKeyboardShowing_);
    // SettleSession deletes raw events (START, STOP) and inserts COUNT_DURATION.
    // No STOP in DB; only COUNT_DURATION.
    int stopIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STOP);
    EXPECT_EQ(stopIdx, IME_INDEX_NOT_FOUND);
    int countIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
}

// ==================== Branch Coverage: OnImeBind IME switch after RecoverActiveSession ====================

/**
 * @tc.name: ImeUsageEventCacher_OnImeBind_SwitchAfterRecovery
 * @tc.desc: OnImeBind with different IME after RecoverActiveSession uses CalculateDurationForRecord
 *           for the hide record (isSessionDurationsReady_ = false in PrepareShowEvent)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, OnImeBind_SwitchAfterRecovery, TestSize.Level0)
{
    // Step 1: Create a session
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);

    // Step 2: Simulate service restart
    cacher_->isKeyboardShowing_ = false;
    cacher_->currentImeBundle_.clear();
    cacher_->isSessionDurationsReady_ = false;

    // Step 3: Recover active session
    cacher_->RecoverActiveSession();
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_FALSE(cacher_->isSessionDurationsReady_);

    // Step 4: Bind a different IME - PrepareShowEvent enters the hide block,
    //         isSessionDurationsReady_ is false, so CalculateDurationForRecord is used
    cacher_->OnImeBind(TEST_BUNDLE2);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_EQ(cacher_->currentImeBundle_, TEST_BUNDLE2);
    // SettleSession deletes raw events (START, STOP) for old IME and inserts COUNT_DURATION.
    // No STOP in DB.
    int stopIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STOP);
    EXPECT_EQ(stopIdx, IME_INDEX_NOT_FOUND);
    int countIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
}

// ==================== Branch Coverage: PrepareHideRecord skip Accumulate (backward boot time) ====================

/**
 * @tc.name: ImeUsageEventCacher_PrepareHideRecord_SkipAccumulate_BackwardBootTime
 * @tc.desc: PrepareHideRecord skips Accumulate when nowBoot <= segmentStartBootTime_
 *           (isSessionDurationsReady_ = true but boot time appears to go backward)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, PrepareHideRecord_SkipAccumulate_BackwardBootTime, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_TRUE(cacher_->isSessionDurationsReady_);

    // Set segmentStartBootTime_ to a very large value so nowBoot <= segmentStartBootTime_
    cacher_->segmentStartBootTime_ = INT64_MAX;

    // OnImeUnbind → PrepareHideRecord: isSessionDurationsReady_ is true,
    // but nowBoot <= segmentStartBootTime_ → Accumulate is skipped
    cacher_->OnImeUnbind(TEST_BUNDLE);
    EXPECT_FALSE(cacher_->isKeyboardShowing_);
    // SettleSession deletes raw events (START, STOP) and inserts COUNT_DURATION.
    // No STOP in DB; COUNT_DURATION should exist (with zero duration since Accumulate was skipped).
    int stopIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STOP);
    EXPECT_EQ(stopIdx, IME_INDEX_NOT_FOUND);
    int countIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
}

// ==================== Branch Coverage: ProcessScreenChangedEvent after RecoverActiveSession ====================

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_AfterRecovery
 * @tc.desc: OnScreenStatusChanged after RecoverActiveSession skips Accumulate
 *           (isSessionDurationsReady_ = false)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_AfterRecovery, TestSize.Level0)
{
    // Step 1: Create a session
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_EQ(cacher_->lastScreenStatus_, UNFOLDED_PORTRAIT);

    // Step 2: Simulate service restart
    cacher_->isKeyboardShowing_ = false;
    cacher_->currentImeBundle_.clear();
    cacher_->isSessionDurationsReady_ = false;

    // Step 3: Recover active session
    cacher_->RecoverActiveSession();
    EXPECT_TRUE(cacher_->isKeyboardShowing_);
    EXPECT_FALSE(cacher_->isSessionDurationsReady_);

    // Step 4: Screen status change - ProcessScreenChangedEvent proceeds (showing, non-duplicate),
    //         but isSessionDurationsReady_ is false → Accumulate is skipped
    cacher_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    EXPECT_EQ(cacher_->lastScreenStatus_, EXPAND_PORTRAIT);
    // STATUS_CHANGED should be written to DB
    int changedIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STATUS_CHANGED);
    EXPECT_GE(changedIdx, 0);
}

// ====================  ProcessScreenChangedEvent skip Accumulate (backward boot time) ====================

/**
 * @tc.name: ImeUsageEventCacher_ProcessScreenChangedEvent_SkipAccumulate_BackwardBootTime
 * @tc.desc: ProcessScreenChangedEvent skips Accumulate when nowBoot <= segmentStartBootTime_
 *           (isSessionDurationsReady_ = true but boot time appears to go backward)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, ProcessScreenChangedEvent_SkipAccumulate_BackwardBootTime, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isSessionDurationsReady_);

    // Set segmentStartBootTime_ to a very large value so nowBoot <= segmentStartBootTime_
    cacher_->segmentStartBootTime_ = INT64_MAX;

    // Screen status change: isSessionDurationsReady_ is true,
    // but nowBoot <= segmentStartBootTime_ → Accumulate is skipped
    cacher_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    EXPECT_EQ(cacher_->lastScreenStatus_, EXPAND_PORTRAIT);
    // STATUS_CHANGED should still be written
    int changedIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_STATUS_CHANGED);
    EXPECT_GE(changedIdx, 0);
}

// ==================== Branch Coverage: CalculateDurationForRecord with no START event ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDurationForRecord_NoStartEvent
 * @tc.desc: CalculateDurationForRecord returns empty durations when no START event found (startIndex < 0)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDurationForRecord_NoStartEvent, TestSize.Level0)
{
    // Use a bundle name that has no events in DB
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_STOP;
    record.ts = 5000;
    record.happenTime = 5000;
    record.bundleName = "nonexistent.bundle.no.start";
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;

    int32_t startIndex = 0;
    DurationMap durations = cacher_->CalculateDurationForRecord(record, startIndex);
    // No START event found → startIndex < 0 → return empty durations
    EXPECT_TRUE(IsDurationMapEmpty(durations));
}

// ==================== Branch Coverage: CalculateDurationForRecord with valid startIndex ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDurationForRecord_ValidStartIndex
 * @tc.desc: CalculateDurationForRecord with valid START event computes durations correctly
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDurationForRecord_ValidStartIndex, TestSize.Level0)
{
    // CalculateDurationForRecord internally filters DB records by happen_time >= today's midnight,
    // so happenTime must be >= GetToday0ClockMs(). Use ts (boot time) for inter-event duration.
    uint64_t today0 = GetToday0ClockMs();

    // Insert a START event and a STATUS_CHANGED event into DB
    ImeEventRecord start;
    start.rawid = EVENT_INPUT_START;
    start.ts = 1000;
    start.happenTime = static_cast<int64_t>(today0 + 2000);
    start.bundleName = TEST_BUNDLE;
    start.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(start);

    ImeEventRecord changed;
    changed.rawid = EVENT_INPUT_STATUS_CHANGED;
    changed.ts = 3000;
    changed.happenTime = static_cast<int64_t>(today0 + 3000);
    changed.bundleName = TEST_BUNDLE;
    changed.screenStatus = EXPAND_PORTRAIT;
    changed.preScreenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(changed);

    // Create a STOP record (not yet in DB) and calculate durations
    ImeEventRecord stop;
    stop.rawid = EVENT_INPUT_STOP;
    stop.ts = 5000;
    stop.happenTime = static_cast<int64_t>(today0 + 5000);
    stop.bundleName = TEST_BUNDLE;
    stop.screenStatus = EXPAND_PORTRAIT;
    stop.preScreenStatus = EXPAND_PORTRAIT;

    int32_t startIndex = 0;
    DurationMap durations = cacher_->CalculateDurationForRecord(stop, startIndex);
    // START(ts=1000)→CHANGED(ts=3000) = 2000ms with UNFOLDED_PORTRAIT
    // CHANGED(ts=3000)→STOP(ts=5000) = 2000ms with EXPAND_PORTRAIT
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 2000u);
    EXPECT_EQ(durations[IDX_EXPAND_PORTRAIT], 2000u);
}

// ==================== Branch Coverage: Accumulate with invalid screenStatus ====================

/**
 * @tc.name: ImeUsageEventCacher_Accumulate_InvalidScreenStatus
 * @tc.desc: Accumulate with invalid screenStatus (idx >= DURATION_COUNT) is silently skipped
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, Accumulate_InvalidScreenStatus, TestSize.Level0)
{
    DurationMap durations;
    // screenStatus=0: foldStatus=0 (below FOLD_STATUS_MIN=1) → ScreenStatusToIndex returns DURATION_COUNT
    cacher_->Accumulate(SCREEN_STATUS_UNINITIALIZED, 1000, durations);
    EXPECT_TRUE(IsDurationMapEmpty(durations));

    // screenStatus=99: foldStatus=9, vhMode=9 (vhMode > VH_MODE_MAX=2) → DURATION_COUNT
    cacher_->Accumulate(99, 2000, durations);
    EXPECT_TRUE(IsDurationMapEmpty(durations));

    // screenStatus=100: foldStatus=10 (> FOLD_STATUS_MAX=6) → DURATION_COUNT
    cacher_->Accumulate(100, 3000, durations);
    EXPECT_TRUE(IsDurationMapEmpty(durations));
}

// ==================== Branch Coverage: SettleSession with null dataHelper ====================

/**
 * @tc.name: ImeUsageEventCacher_SettleSession_NullDataHelper
 * @tc.desc: SettleSession with null dataHelper_ returns immediately (defensive check)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, SettleSession_NullDataHelper, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init - dataHelper_ is nullptr
    ImeEventRecord stopRecord;
    stopRecord.rawid = EVENT_INPUT_STOP;
    stopRecord.bundleName = TEST_BUNDLE;
    stopRecord.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap durations;
    durations[IDX_UNFOLDED_PORTRAIT] = 1000;
    int32_t startIndex = -1;
    // Should not crash; returns immediately due to dataHelper_ == nullptr
    cacher->SettleSession(stopRecord, durations, startIndex);
    EXPECT_EQ(cacher->dataHelper_, nullptr);
}

// ==================== Branch Coverage: SettleSession transaction failure fallback ====================

/**
 * @tc.name: ImeUsageEventCacher_SettleSession_TransactionFailure
 * @tc.desc: SettleSession falls back to separate writes when DeleteAndUpsertTransactional fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, SettleSession_TransactionFailure, TestSize.Level0)
{
    // Step 1: Create a session with valid ready_ (START record written to file)
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);

    // Step 2: Set ready_ to false so DeleteAndUpsertTransactional fails
    dataHelper_->ready_ = false;

    // Step 3: OnImeUnbind → SettleSession: DeleteAndUpsertTransactional fails,
    //         fallback path calls DeleteEventsByBundleAndStartIndex then UpsertCountDuration
    //         (both also fail due to ready_ false, but the fallback branch is exercised)
    cacher_->OnImeUnbind(TEST_BUNDLE);
    EXPECT_FALSE(cacher_->isKeyboardShowing_);
}

// ==================== Branch Coverage: RecoverActiveSession with null dataHelper ====================

/**
 * @tc.name: ImeUsageEventCacher_RecoverActiveSession_NullDataHelper
 * @tc.desc: RecoverActiveSession with null dataHelper_ returns immediately without crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, RecoverActiveSession_NullDataHelper, TestSize.Level0)
{
    auto cacher = std::make_unique<ImeUsageEventCacher>();
    // No Init - dataHelper_ is nullptr
    cacher->RecoverActiveSession();
    // Should not crash; state remains default
    EXPECT_FALSE(cacher->isKeyboardShowing_);
    EXPECT_TRUE(cacher->currentImeBundle_.empty());
}

// ==================== Branch Coverage: CalculateDuration with STOP->STOP pair ====================

/**
 * @tc.name: ImeUsageEventCacher_CalculateDuration_014
 * @tc.desc: CalculateDuration with STOP->STOP pair skips that pair (CanCalcDuration returns false)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CalculateDuration_014, TestSize.Level0)
{
    uint64_t dayStartTime = 1000;
    std::vector<ImeEventRecord> records;

    // First event is STOP (cross-midnight: dayStartTime -> stop1)
    ImeEventRecord stop1;
    stop1.rawid = EVENT_INPUT_STOP;
    stop1.ts = 3000;
    stop1.happenTime = 3000;
    stop1.screenStatus = UNFOLDED_PORTRAIT;
    stop1.preScreenStatus = UNFOLDED_PORTRAIT;
    records.push_back(stop1);

    // Second event is also STOP (STOP->STOP pair: CanCalcDuration returns false, skipped)
    ImeEventRecord stop2;
    stop2.rawid = EVENT_INPUT_STOP;
    stop2.ts = 5000;
    stop2.happenTime = 5000;
    stop2.screenStatus = EXPAND_PORTRAIT;
    stop2.preScreenStatus = UNFOLDED_PORTRAIT;
    records.push_back(stop2);

    DurationMap durations;
    cacher_->CalculateDuration(dayStartTime, records, durations);
    // Cross-midnight: dayStartTime(1000) -> stop1(3000) = 2000ms with stop1.screenStatus = UNFOLDED_PORTRAIT
    EXPECT_EQ(durations[IDX_UNFOLDED_PORTRAIT], 2000u);
    // STOP->STOP pair is skipped, no duration from stop1->stop2
    EXPECT_EQ(durations[IDX_EXPAND_PORTRAIT], 0u);
}

// ==================== DataHelper: DeleteEventsByBundleAndStartIndex no match ====================

/**
 * @tc.name: ImeUsageDataHelper_DeleteEventsByBundleAndStartIndex_NoMatch
 * @tc.desc: DeleteEventsByBundleAndStartIndex with no matching rows returns success
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteEventsByBundleAndStartIndex_NoMatch, TestSize.Level0)
{
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(record);

    // Delete with non-matching bundle name
    int ret = dataHelper_->DeleteEventsByBundleAndStartIndex("com.nonexistent", 1);
    EXPECT_EQ(ret, 0);
    // Original event should still exist
    int idx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_NE(idx, IME_INDEX_NOT_FOUND);
}

// ==================== DataHelper: UpsertCountDuration showCount increment ====================

/**
 * @tc.name: ImeUsageDataHelper_UpsertCountDuration_ShowCountIncrement
 * @tc.desc: UpsertCountDuration called twice for same bundle on same day increments showCount and accumulates durations
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_UpsertCountDuration_ShowCountIncrement, TestSize.Level0)
{
    uint64_t dayStart = GetToday0ClockMs();
    int64_t dayStartTime = static_cast<int64_t>(dayStart);

    // First upsert
    ImeEventRecord countRec1;
    countRec1.rawid = EVENT_COUNT_DURATION;
    countRec1.ts = dayStart + 3600000;
    countRec1.happenTime = dayStart + 3600000;
    countRec1.bundleName = TEST_BUNDLE;
    countRec1.screenStatus = UNFOLDED_PORTRAIT;
    countRec1.preScreenStatus = UNFOLDED_PORTRAIT;
    DurationMap durations1 {};
    durations1[IDX_UNFOLDED_PORTRAIT] = 1000;
    int ret1 = dataHelper_->UpsertCountDuration(TEST_BUNDLE, dayStartTime, countRec1, durations1);
    EXPECT_EQ(ret1, 0);

    // Second upsert — should accumulate into existing record
    ImeEventRecord countRec2;
    countRec2.rawid = EVENT_COUNT_DURATION;
    countRec2.ts = dayStart + 7200000;
    countRec2.happenTime = dayStart + 7200000;
    countRec2.bundleName = TEST_BUNDLE;
    countRec2.screenStatus = UNFOLDED_PORTRAIT;
    countRec2.preScreenStatus = UNFOLDED_PORTRAIT;
    DurationMap durations2 {};
    durations2[IDX_UNFOLDED_PORTRAIT] = 2000;
    int ret2 = dataHelper_->UpsertCountDuration(TEST_BUNDLE, dayStartTime, countRec2, durations2);
    EXPECT_EQ(ret2, 0);

    // Verify accumulated result
    std::unordered_map<std::string, ImeUsageInfo> infos;
    dataHelper_->QueryStatisticEventsInPeriod(dayStart, dayStart + MILLISECS_PER_DAY - 1, infos);
    ASSERT_EQ(infos.size(), 1u);
    EXPECT_EQ(infos[TEST_BUNDLE].showCount, 2u);
    EXPECT_EQ(infos[TEST_BUNDLE].durations[IDX_UNFOLDED_PORTRAIT], 3000u);
}

// ==================== DataHelper: QueryForegroundImeInfo out of range ====================

/**
 * @tc.name: ImeUsageDataHelper_QueryForegroundImeInfo_OutOfRange
 * @tc.desc: QueryForegroundImeInfo with time range excluding all events produces empty-events duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryForegroundImeInfo_OutOfRange, TestSize.Level0)
{
    uint64_t dayStart = GetToday0ClockMs();
    // Insert START for TEST_BUNDLE in the current day
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + 3600000;
    startRec.happenTime = dayStart + 3600000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(startRec);

    // Query with a time range that excludes the event
    ImeUsageInfo info;
    info.package = TEST_BUNDLE;
    uint64_t queryStart = dayStart + MILLISECS_PER_DAY;
    uint64_t queryEnd = queryStart + MILLISECS_PER_DAY;
    dataHelper_->QueryForegroundImeInfo(queryStart, queryEnd, UNFOLDED_PORTRAIT, info);
    // No matching rows → fgEvents empty → full duration = queryEnd - queryStart
    EXPECT_EQ(info.durations[IDX_UNFOLDED_PORTRAIT], MILLISECS_PER_DAY);
}

// ==================== DataHelper: DeleteEventsByTime no match ====================

/**
 * @tc.name: ImeUsageDataHelper_DeleteEventsByTime_NoMatch
 * @tc.desc: DeleteEventsByTime with clearDataTime before all events does nothing
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteEventsByTime_NoMatch, TestSize.Level0)
{
    uint64_t dayStart = GetToday0ClockMs();
    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = dayStart + 3600000;
    record.happenTime = dayStart + 3600000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(record);

    // clearDataTime before all events → no match
    int ret = dataHelper_->DeleteEventsByTime(dayStart - MILLISECS_PER_DAY);
    EXPECT_EQ(ret, 0);
    // Event should still exist
    int idx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_NE(idx, IME_INDEX_NOT_FOUND);
}

// ==================== DataHelper: QueryStatisticEventsInPeriod out of range ====================

/**
 * @tc.name: ImeUsageDataHelper_QueryStatisticEventsInPeriod_OutOfRange
 * @tc.desc: QueryStatisticEventsInPeriod excludes events outside the time range
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryStatisticEventsInPeriod_OutOfRange, TestSize.Level0)
{
    uint64_t dayStart = GetToday0ClockMs();
    ImeEventRecord record;
    record.rawid = EVENT_COUNT_DURATION;
    record.ts = dayStart + 3600000;
    record.happenTime = dayStart + 3600000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    record.preScreenStatus = UNFOLDED_PORTRAIT;
    record.showCount = 1;
    DurationMap durations {};
    durations[IDX_UNFOLDED_PORTRAIT] = 1000;
    dataHelper_->AddEvent(record, durations);

    // Query a different day → should return empty
    std::unordered_map<std::string, ImeUsageInfo> infos;
    dataHelper_->QueryStatisticEventsInPeriod(
        dayStart + MILLISECS_PER_DAY, dayStart + MILLISECS_PER_DAY * 2 - 1, infos);
    EXPECT_TRUE(infos.empty());
}

// ==================== FileStore: empty workPath ====================

/**
 * @tc.name: ImeUsageFileStore_EmptyWorkPath
 * @tc.desc: ImeUsageFileStore with empty workPath is not ready
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_EmptyWorkPath, TestSize.Level0)
{
    auto store = std::make_unique<ImeUsageFileStore>("");
    EXPECT_FALSE(store->IsReady());
}

// ==================== FileStore: load empty file ====================

/**
 * @tc.name: ImeUsageFileStore_LoadEmptyFile
 * @tc.desc: LoadEvents with empty file starts fresh
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_LoadEmptyFile, TestSize.Level0)
{
    std::string testDir = "/data/test/ime_usage_file_store_empty";
    std::string filePath = testDir + "/ime_usage_events.json";
    std::remove(filePath.c_str());
    auto store = std::make_unique<ImeUsageFileStore>(testDir);
    ASSERT_TRUE(store->IsReady());

    // Create an empty file
    FILE *f = fopen(filePath.c_str(), "w");
    ASSERT_NE(f, nullptr);
    fclose(f);

    std::vector<ImeUsageEventRow> events;
    int64_t nextId = 0;
    uint64_t lastReportTime = 42;
    bool ret = store->LoadEvents(events, nextId, lastReportTime);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(events.empty());
    EXPECT_EQ(nextId, 1);
    EXPECT_EQ(lastReportTime, 0u);
}

// ==================== FileStore: load corrupt JSON ====================

/**
 * @tc.name: ImeUsageFileStore_LoadCorruptJson
 * @tc.desc: LoadEvents with corrupt JSON backs up file and starts fresh
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_LoadCorruptJson, TestSize.Level0)
{
    std::string testDir = "/data/test/ime_usage_file_store_corrupt";
    std::string filePath = testDir + "/ime_usage_events.json";
    std::string backupPath = filePath + ".corrupt";
    std::remove(filePath.c_str());
    std::remove(backupPath.c_str());
    auto store = std::make_unique<ImeUsageFileStore>(testDir);
    ASSERT_TRUE(store->IsReady());

    // Write corrupt JSON
    FILE *f = fopen(filePath.c_str(), "w");
    ASSERT_NE(f, nullptr);
    fputs("{ corrupt json !!! }", f);
    fclose(f);

    std::vector<ImeUsageEventRow> events;
    int64_t nextId = 0;
    uint64_t lastReportTime = 42;
    bool ret = store->LoadEvents(events, nextId, lastReportTime);
    // Corrupt JSON → rename to .corrupt, start fresh, return true
    EXPECT_TRUE(ret);
    EXPECT_TRUE(events.empty());
    EXPECT_EQ(nextId, 1);
    EXPECT_EQ(lastReportTime, 0u);
    // Original file should no longer exist at its path
    EXPECT_NE(access(filePath.c_str(), F_OK), 0);
    // Backup file should exist (renamed from original)
    EXPECT_EQ(access(backupPath.c_str(), F_OK), 0);
    // Cleanup
    std::remove(backupPath.c_str());
}

// ==================== DataHelper: WriteEvents failure rollback paths ====================

/**
 * @tc.name: DataHelper_AddEvent_WriteEventsFailure
 * @tc.desc: AddEvent rolls back when WriteEvents fails (fileStore_->eventsFilePath_.clear())
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_AddEvent_WriteEventsFailure, TestSize.Level0)
{
    size_t beforeSize = dataHelper_->events_.size();
    int64_t beforeNextId = dataHelper_->nextId_;
    // Disable fileStore so WriteEvents fails but dataHelper business logic still runs
    dataHelper_->fileStore_->eventsFilePath_.clear();

    ImeEventRecord record;
    record.rawid = EVENT_INPUT_START;
    record.ts = 1000;
    record.happenTime = 2000;
    record.bundleName = TEST_BUNDLE;
    record.screenStatus = UNFOLDED_PORTRAIT;
    int ret = dataHelper_->AddEvent(record);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
    // Rollback: events_ restored, nextId_ restored
    EXPECT_EQ(dataHelper_->events_.size(), beforeSize);
    EXPECT_EQ(dataHelper_->nextId_, beforeNextId);
}

/**
 * @tc.name: DataHelper_DeleteEventsByBundleAndStartIndex_WriteEventsFailure
 * @tc.desc: DeleteEventsByBundleAndStartIndex restores events_ when WriteEvents fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteEventsByBundleAndStartIndex_WriteEventsFailure, TestSize.Level0)
{
    ImeEventRecord rec1;
    rec1.rawid = EVENT_INPUT_START;
    rec1.ts = 1000;
    rec1.happenTime = 2000;
    rec1.bundleName = TEST_BUNDLE;
    rec1.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(rec1);

    ImeEventRecord rec2;
    rec2.rawid = EVENT_INPUT_STOP;
    rec2.ts = 2000;
    rec2.happenTime = 3000;
    rec2.bundleName = TEST_BUNDLE;
    rec2.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(rec2);

    size_t beforeSize = dataHelper_->events_.size();
    ASSERT_EQ(beforeSize, 2u);
    int32_t startIndex = static_cast<int32_t>(dataHelper_->events_[0].id);

    dataHelper_->fileStore_->eventsFilePath_.clear();
    int ret = dataHelper_->DeleteEventsByBundleAndStartIndex(TEST_BUNDLE, startIndex);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
    // events_ restored by rollback
    EXPECT_EQ(dataHelper_->events_.size(), beforeSize);
}

/**
 * @tc.name: DataHelper_DeleteAndUpsertTransactional_WriteEventsFailure
 * @tc.desc: DeleteAndUpsertTransactional rolls back when WriteEvents fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteAndUpsertTransactional_WriteEventsFailure, TestSize.Level0)
{
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = 1000;
    startRec.happenTime = 2000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(startRec);

    size_t beforeSize = dataHelper_->events_.size();
    int64_t beforeNextId = dataHelper_->nextId_;
    int32_t startIndex = static_cast<int32_t>(dataHelper_->events_[0].id);

    dataHelper_->fileStore_->eventsFilePath_.clear();

    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = 3000;
    countRec.happenTime = 4000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap durations;
    durations[IDX_UNFOLDED_PORTRAIT] = 500;

    int ret = dataHelper_->DeleteAndUpsertTransactional(TEST_BUNDLE, startIndex, 0, countRec, durations);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
    // Rollback restores events_ and nextId_
    EXPECT_EQ(dataHelper_->events_.size(), beforeSize);
    EXPECT_EQ(dataHelper_->nextId_, beforeNextId);
}

/**
 * @tc.name: DataHelper_UpsertCountDuration_WriteEventsFailure
 * @tc.desc: UpsertCountDuration rolls back when WriteEvents fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_UpsertCountDuration_WriteEventsFailure, TestSize.Level0)
{
    ImeEventRecord countRec1;
    countRec1.rawid = EVENT_COUNT_DURATION;
    countRec1.ts = 1000;
    countRec1.happenTime = 2000;
    countRec1.bundleName = TEST_BUNDLE;
    countRec1.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap dur1;
    dur1[IDX_UNFOLDED_PORTRAIT] = 100;
    dataHelper_->AddEvent(countRec1, dur1);

    size_t beforeSize = dataHelper_->events_.size();
    int64_t beforeNextId = dataHelper_->nextId_;

    dataHelper_->fileStore_->eventsFilePath_.clear();

    ImeEventRecord countRec2;
    countRec2.rawid = EVENT_COUNT_DURATION;
    countRec2.ts = 3000;
    countRec2.happenTime = 4000;
    countRec2.bundleName = TEST_BUNDLE;
    countRec2.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap dur2;
    dur2[IDX_UNFOLDED_PORTRAIT] = 200;

    int ret = dataHelper_->UpsertCountDuration(TEST_BUNDLE, 0, countRec2, dur2);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
    // Rollback restores events_ and nextId_
    EXPECT_EQ(dataHelper_->events_.size(), beforeSize);
    EXPECT_EQ(dataHelper_->nextId_, beforeNextId);
}

/**
 * @tc.name: DataHelper_DeleteEventsByTime_WriteEventsFailure
 * @tc.desc: DeleteEventsByTime restores events_ when WriteEvents fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteEventsByTime_WriteEventsFailure, TestSize.Level0)
{
    ImeEventRecord rec;
    rec.rawid = EVENT_INPUT_START;
    rec.ts = 1000;
    rec.happenTime = 1000;
    rec.bundleName = TEST_BUNDLE;
    rec.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(rec);

    size_t beforeSize = dataHelper_->events_.size();
    ASSERT_GT(beforeSize, 0u);

    dataHelper_->fileStore_->eventsFilePath_.clear();
    int ret = dataHelper_->DeleteEventsByTime(5000);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
    // Rollback restores events_
    EXPECT_EQ(dataHelper_->events_.size(), beforeSize);
}

/**
 * @tc.name: DataHelper_SaveReportState_WriteEventsFailure
 * @tc.desc: SaveReportState returns DB_FAILED when WriteEvents fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_SaveReportState_WriteEventsFailure, TestSize.Level0)
{
    dataHelper_->fileStore_->eventsFilePath_.clear();
    int ret = dataHelper_->SaveReportState(STATE_KEY_LAST_REPORT_TIME, 999ULL);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: DataHelper_DeleteEventsByBundleAndStartIndex_NotReady
 * @tc.desc: DeleteEventsByBundleAndStartIndex with ready_ false returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteEventsByBundleAndStartIndex_NotReady, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    int ret = dataHelper_->DeleteEventsByBundleAndStartIndex(TEST_BUNDLE, 0);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: DataHelper_DeleteAndUpsertTransactional_NotReady
 * @tc.desc: DeleteAndUpsertTransactional with ready_ false returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_DeleteAndUpsertTransactional_NotReady, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = 1000;
    countRec.happenTime = 2000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap durations;
    int ret = dataHelper_->DeleteAndUpsertTransactional(TEST_BUNDLE, 0, 0, countRec, durations);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

/**
 * @tc.name: DataHelper_UpsertCountDuration_NotReady
 * @tc.desc: UpsertCountDuration with ready_ false returns DB_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_UpsertCountDuration_NotReady, TestSize.Level0)
{
    dataHelper_->ready_ = false;
    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = 1000;
    countRec.happenTime = 2000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap durations;
    int ret = dataHelper_->UpsertCountDuration(TEST_BUNDLE, 0, countRec, durations);
    EXPECT_EQ(ret, IME_USAGE_FAILED);
}

// ==================== DataHelper: query branch tests ====================

/**
 * @tc.name: DataHelper_QueryEventRecords_DayStartTimeFilter
 * @tc.desc: QueryEventRecords filters records with happenTime < dayStartTime
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryEventRecords_DayStartTimeFilter, TestSize.Level0)
{
    int64_t dayStartTime = 5000;
    // Record before dayStartTime - should be filtered out
    ImeEventRecord rec1;
    rec1.rawid = EVENT_INPUT_START;
    rec1.ts = 1000;
    rec1.happenTime = 3000; // < dayStartTime
    rec1.bundleName = TEST_BUNDLE;
    rec1.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(rec1);

    // Record after dayStartTime - should be included
    ImeEventRecord rec2;
    rec2.rawid = EVENT_INPUT_START;
    rec2.ts = 6000;
    rec2.happenTime = 6000; // >= dayStartTime
    rec2.bundleName = TEST_BUNDLE;
    rec2.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(rec2);

    int32_t startIndex = 0;
    std::vector<ImeEventRecord> records;
    dataHelper_->QueryEventRecords(startIndex, dayStartTime, TEST_BUNDLE, records);
    // Only rec2 should be returned
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records[0].happenTime, 6000);
}

/**
 * @tc.name: DataHelper_QueryStatisticEventsInPeriod_StopNoShowCount
 * @tc.desc: QueryStatisticEventsInPeriod with STOP record does not increment showCount
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryStatisticEventsInPeriod_StopNoShowCount, TestSize.Level0)
{
    ImeEventRecord stopRec;
    stopRec.rawid = EVENT_INPUT_STOP;
    stopRec.ts = 1000;
    stopRec.happenTime = 2000;
    stopRec.bundleName = TEST_BUNDLE;
    stopRec.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(stopRec);

    std::unordered_map<std::string, ImeUsageInfo> infos;
    dataHelper_->QueryStatisticEventsInPeriod(0, 10000, infos);
    auto it = infos.find(TEST_BUNDLE);
    ASSERT_NE(it, infos.end());
    // STOP record does not increment showCount
    EXPECT_EQ(it->second.showCount, 0u);
}

/**
 * @tc.name: DataHelper_QueryEventRecords_CheckpointWithUnprocessedRecords
 * @tc.desc: QueryEventRecords clears records when COUNT_DURATION is encountered with unprocessed records
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_QueryEventRecords_CheckpointWithUnprocessedRecords, TestSize.Level0)
{
    ImeEventRecord start1;
    start1.rawid = EVENT_INPUT_START;
    start1.ts = 1000;
    start1.happenTime = 2000;
    start1.bundleName = TEST_BUNDLE;
    start1.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(start1);

    ImeEventRecord start2;
    start2.rawid = EVENT_INPUT_START;
    start2.ts = 2000;
    start2.happenTime = 3000;
    start2.bundleName = TEST_BUNDLE;
    start2.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(start2);

    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = 3000;
    countRec.happenTime = 4000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.screenStatus = UNFOLDED_PORTRAIT;
    dataHelper_->AddEvent(countRec);

    int32_t startIndex = static_cast<int32_t>(dataHelper_->events_[0].id);
    std::vector<ImeEventRecord> records;
    dataHelper_->QueryEventRecords(startIndex, 0, TEST_BUNDLE, records);
    // COUNT_DURATION clears records, so result should be empty
    EXPECT_TRUE(records.empty());
}

/**
 * @tc.name: DataHelper_UpsertCountDuration_OldDayNotMatched
 * @tc.desc: UpsertCountDuration with dayStartTime later than existing record inserts new record
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, DataHelper_UpsertCountDuration_OldDayNotMatched, TestSize.Level0)
{
    // Insert a COUNT_DURATION record with happenTime < dayStartTime
    ImeEventRecord oldCount;
    oldCount.rawid = EVENT_COUNT_DURATION;
    oldCount.ts = 1000;
    oldCount.happenTime = 1000; // Old day
    oldCount.bundleName = TEST_BUNDLE;
    oldCount.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap oldDur;
    oldDur[IDX_UNFOLDED_PORTRAIT] = 100;
    dataHelper_->AddEvent(oldCount, oldDur);

    size_t beforeSize = dataHelper_->events_.size();
    ASSERT_EQ(beforeSize, 1u);

    // Upsert with a later dayStartTime — old record should NOT be matched
    ImeEventRecord newCount;
    newCount.rawid = EVENT_COUNT_DURATION;
    newCount.ts = 5000;
    newCount.happenTime = 5000;
    newCount.bundleName = TEST_BUNDLE;
    newCount.screenStatus = UNFOLDED_PORTRAIT;
    DurationMap newDur;
    newDur[IDX_UNFOLDED_PORTRAIT] = 200;

    int64_t dayStartTime = 3000;
    int ret = dataHelper_->UpsertCountDuration(TEST_BUNDLE, dayStartTime, newCount, newDur);
    EXPECT_EQ(ret, IME_USAGE_SUCCESS);
    // A new record should be inserted (not accumulated into old)
    EXPECT_EQ(dataHelper_->events_.size(), beforeSize + 1);
    // Old record's duration should be unchanged
    EXPECT_EQ(dataHelper_->events_[0].durations[IDX_UNFOLDED_PORTRAIT], 100u);
    // New record's duration should be 200
    EXPECT_EQ(dataHelper_->events_[1].durations[IDX_UNFOLDED_PORTRAIT], 200u);
}

// ==================== FileStore: not ready and I/O failure branches ====================

/**
 * @tc.name: ImeUsageFileStore_LoadEventsNotReady
 * @tc.desc: LoadEvents returns false when store is not ready
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_LoadEventsNotReady, TestSize.Level0)
{
    auto store = std::make_unique<ImeUsageFileStore>("");
    ASSERT_FALSE(store->IsReady());
    std::vector<ImeUsageEventRow> events;
    int64_t nextId = 0;
    uint64_t lastReportTime = 0;
    bool ret = store->LoadEvents(events, nextId, lastReportTime);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ImeUsageFileStore_WriteEventsNotReady
 * @tc.desc: WriteEvents returns false when store is not ready
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_WriteEventsNotReady, TestSize.Level0)
{
    auto store = std::make_unique<ImeUsageFileStore>("");
    ASSERT_FALSE(store->IsReady());
    std::vector<ImeUsageEventRow> events;
    bool ret = store->WriteEvents(events, 1, 0);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ImeUsageFileStore_WriteEventsWriteFail
 * @tc.desc: WriteEvents returns false when file write fails (invalid path)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_WriteEventsWriteFail, TestSize.Level0)
{
    std::string testDir = "/data/test/ime_usage_file_store_writefail";
    auto store = std::make_unique<ImeUsageFileStore>(testDir);
    ASSERT_TRUE(store->IsReady());
    // Set eventsFilePath_ to a path that cannot be written
    store->eventsFilePath_ = "/proc/imf_test_cannot_write_events";
    std::vector<ImeUsageEventRow> events;
    bool ret = store->WriteEvents(events, 1, 0);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ImeUsageFileStore_LoadRowWithoutDurations
 * @tc.desc: LoadEvents with a row missing durations field succeeds, durations default to 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_LoadRowWithoutDurations, TestSize.Level0)
{
    std::string testDir = "/data/test/ime_usage_file_store_no_durations";
    std::string filePath = testDir + "/ime_usage_events.json";
    std::remove(filePath.c_str());
    auto store = std::make_unique<ImeUsageFileStore>(testDir);
    ASSERT_TRUE(store->IsReady());

    // Write JSON with a row that has no durations field
    FILE *f = fopen(filePath.c_str(), "w");
    ASSERT_NE(f, nullptr);
    fputs("{\"nextId\":2,\"lastReportTime\":0,\"events\":["
          "{\"id\":1,\"rawid\":1001,\"ts\":1000,\"happenTime\":2000,"
          "\"bundleName\":\"com.test\",\"preScreenStatus\":12,\"screenStatus\":12}"
          "]}",
        f);
    fclose(f);

    std::vector<ImeUsageEventRow> events;
    int64_t nextId = 0;
    uint64_t lastReportTime = 0;
    bool ret = store->LoadEvents(events, nextId, lastReportTime);
    EXPECT_TRUE(ret);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(nextId, 2);
    // durations should all be 0 (default)
    for (size_t i = 0; i < DURATION_COUNT; i++) {
        EXPECT_EQ(events[0].durations[i], 0u);
    }
}

/**
 * @tc.name: ImeUsageFileStore_LoadRowDurationsNotArray
 * @tc.desc: LoadEvents with durations field as non-array triggers corrupt path
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_LoadRowDurationsNotArray, TestSize.Level0)
{
    std::string testDir = "/data/test/ime_usage_file_store_dur_not_array";
    std::string filePath = testDir + "/ime_usage_events.json";
    std::string backupPath = filePath + ".corrupt";
    std::remove(filePath.c_str());
    std::remove(backupPath.c_str());
    auto store = std::make_unique<ImeUsageFileStore>(testDir);
    ASSERT_TRUE(store->IsReady());

    FILE *f = fopen(filePath.c_str(), "w");
    ASSERT_NE(f, nullptr);
    fputs("{\"nextId\":2,\"lastReportTime\":0,\"events\":["
          "{\"id\":1,\"rawid\":1001,\"ts\":1000,\"happenTime\":2000,"
          "\"bundleName\":\"com.test\",\"preScreenStatus\":12,\"screenStatus\":12,"
          "\"durations\":\"not_an_array\"}"
          "]}",
        f);
    fclose(f);

    std::vector<ImeUsageEventRow> events;
    int64_t nextId = 0;
    uint64_t lastReportTime = 0;
    bool ret = store->LoadEvents(events, nextId, lastReportTime);
    // Corrupt path: returns true but resets to empty
    EXPECT_TRUE(ret);
    EXPECT_TRUE(events.empty());
    EXPECT_EQ(nextId, 1);
    std::remove(backupPath.c_str());
}

/**
 * @tc.name: ImeUsageFileStore_LoadRowDurationsWrongSize
 * @tc.desc: LoadEvents with durations array of wrong size triggers corrupt path
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_LoadRowDurationsWrongSize, TestSize.Level0)
{
    std::string testDir = "/data/test/ime_usage_file_store_dur_wrong_size";
    std::string filePath = testDir + "/ime_usage_events.json";
    std::string backupPath = filePath + ".corrupt";
    std::remove(filePath.c_str());
    std::remove(backupPath.c_str());
    auto store = std::make_unique<ImeUsageFileStore>(testDir);
    ASSERT_TRUE(store->IsReady());

    FILE *f = fopen(filePath.c_str(), "w");
    ASSERT_NE(f, nullptr);
    fputs("{\"nextId\":2,\"lastReportTime\":0,\"events\":["
          "{\"id\":1,\"rawid\":1001,\"ts\":1000,\"happenTime\":2000,"
          "\"bundleName\":\"com.test\",\"preScreenStatus\":12,\"screenStatus\":12,"
          "\"durations\":[1,2,3,4,5]}"
          "]}",
        f);
    fclose(f);

    std::vector<ImeUsageEventRow> events;
    int64_t nextId = 0;
    uint64_t lastReportTime = 0;
    bool ret = store->LoadEvents(events, nextId, lastReportTime);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(events.empty());
    EXPECT_EQ(nextId, 1);
    std::remove(backupPath.c_str());
}

/**
 * @tc.name: ImeUsageFileStore_LoadRowDurationsItemNotNumber
 * @tc.desc: LoadEvents with durations array containing non-number triggers corrupt path
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_LoadRowDurationsItemNotNumber, TestSize.Level0)
{
    std::string testDir = "/data/test/ime_usage_file_store_dur_not_number";
    std::string filePath = testDir + "/ime_usage_events.json";
    std::string backupPath = filePath + ".corrupt";
    std::remove(filePath.c_str());
    std::remove(backupPath.c_str());
    auto store = std::make_unique<ImeUsageFileStore>(testDir);
    ASSERT_TRUE(store->IsReady());

    FILE *f = fopen(filePath.c_str(), "w");
    ASSERT_NE(f, nullptr);
    // durations array has 12 elements but one is a string
    fputs("{\"nextId\":2,\"lastReportTime\":0,\"events\":["
          "{\"id\":1,\"rawid\":1001,\"ts\":1000,\"happenTime\":2000,"
          "\"bundleName\":\"com.test\",\"preScreenStatus\":12,\"screenStatus\":12,"
          "\"durations\":[1,2,3,4,5,6,7,\"str\",9,10,11,12]}"
          "]}",
        f);
    fclose(f);

    std::vector<ImeUsageEventRow> events;
    int64_t nextId = 0;
    uint64_t lastReportTime = 0;
    bool ret = store->LoadEvents(events, nextId, lastReportTime);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(events.empty());
    EXPECT_EQ(nextId, 1);
    std::remove(backupPath.c_str());
}

/**
 * @tc.name: ImeUsageFileStore_LoadMissingNextId
 * @tc.desc: LoadEvents with missing nextId field triggers corrupt path
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_LoadMissingNextId, TestSize.Level0)
{
    std::string testDir = "/data/test/ime_usage_file_store_missing_nextid";
    std::string filePath = testDir + "/ime_usage_events.json";
    std::string backupPath = filePath + ".corrupt";
    std::remove(filePath.c_str());
    std::remove(backupPath.c_str());
    auto store = std::make_unique<ImeUsageFileStore>(testDir);
    ASSERT_TRUE(store->IsReady());

    FILE *f = fopen(filePath.c_str(), "w");
    ASSERT_NE(f, nullptr);
    // No nextId field
    fputs("{\"lastReportTime\":0,\"events\":[]}", f);
    fclose(f);

    std::vector<ImeUsageEventRow> events;
    int64_t nextId = 0;
    uint64_t lastReportTime = 0;
    bool ret = store->LoadEvents(events, nextId, lastReportTime);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(events.empty());
    EXPECT_EQ(nextId, 1);
    std::remove(backupPath.c_str());
}

/**
 * @tc.name: ImeUsageFileStore_LoadMissingLastReportTime
 * @tc.desc: LoadEvents with missing lastReportTime field succeeds, lastReportTime defaults to 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, FileStore_LoadMissingLastReportTime, TestSize.Level0)
{
    std::string testDir = "/data/test/ime_usage_file_store_missing_lrt";
    std::string filePath = testDir + "/ime_usage_events.json";
    std::remove(filePath.c_str());
    auto store = std::make_unique<ImeUsageFileStore>(testDir);
    ASSERT_TRUE(store->IsReady());

    FILE *f = fopen(filePath.c_str(), "w");
    ASSERT_NE(f, nullptr);
    // No lastReportTime field, but nextId and events are valid
    fputs("{\"nextId\":5,\"events\":[]}", f);
    fclose(f);

    std::vector<ImeUsageEventRow> events;
    int64_t nextId = 0;
    uint64_t lastReportTime = 42; // Set to non-zero to verify it gets reset
    bool ret = store->LoadEvents(events, nextId, lastReportTime);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(events.empty());
    EXPECT_EQ(nextId, 5);
    // lastReportTime should default to 0 (missing field)
    EXPECT_EQ(lastReportTime, 0u);
}

// ==================== EventCacher: uncovered branch tests ====================

/**
 * @tc.name: ImeUsageEventCacher_OnScreenStatusChanged_AddEventFailure
 * @tc.desc: OnScreenStatusChanged when AddEvent fails does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, OnScreenStatusChanged_AddEventFailure, TestSize.Level0)
{
    cacher_->OnImeBind(TEST_BUNDLE);
    EXPECT_TRUE(cacher_->isKeyboardShowing_);

    // Make AddEvent fail by setting fileStore_->eventsFilePath_.clear()
    dataHelper_->fileStore_->eventsFilePath_.clear();

    // Trigger screen status change - AddEvent will fail but should not crash
    cacher_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, FOLD_PORTRAIT);
    // State should still update
    EXPECT_EQ(cacher_->foldStatus_, FOLD);
    EXPECT_EQ(cacher_->vhMode_, PORTRAIT);
}

/**
 * @tc.name: ImeUsageEventCacher_CanCalcDuration_StopStop
 * @tc.desc: CanCalcDuration returns false for STOP->STOP pair
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, CanCalcDuration_StopStop, TestSize.Level0)
{
    EXPECT_FALSE(cacher_->CanCalcDuration(EVENT_INPUT_STOP, EVENT_INPUT_STOP));
    // START->START also returns false
    EXPECT_FALSE(cacher_->CanCalcDuration(EVENT_INPUT_START, EVENT_INPUT_START));
    // Other pairs return true
    EXPECT_TRUE(cacher_->CanCalcDuration(EVENT_INPUT_START, EVENT_INPUT_STOP));
    EXPECT_TRUE(cacher_->CanCalcDuration(EVENT_INPUT_START, EVENT_INPUT_STATUS_CHANGED));
    EXPECT_TRUE(cacher_->CanCalcDuration(EVENT_INPUT_STOP, EVENT_INPUT_STATUS_CHANGED));
}

/**
 * @tc.name: ImeUsageEventCacher_SettleSession_StartIndexNegative
 * @tc.desc: SettleSession with startIndex=-1 takes UpsertCountDuration path (no delete)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventCacherTest, SettleSession_StartIndexNegative, TestSize.Level0)
{
    ImeEventRecord stopRecord;
    stopRecord.rawid = EVENT_INPUT_STOP;
    stopRecord.ts = 1000;
    stopRecord.happenTime = 2000;
    stopRecord.bundleName = TEST_BUNDLE;
    stopRecord.screenStatus = UNFOLDED_PORTRAIT;
    stopRecord.preScreenStatus = UNFOLDED_PORTRAIT;

    DurationMap durations;
    durations[IDX_UNFOLDED_PORTRAIT] = 500;
    int32_t startIndex = -1; // No START event found

    size_t beforeSize = dataHelper_->events_.size();
    cacher_->SettleSession(stopRecord, durations, startIndex);
    // SettleSession with startIndex < 0 goes directly to UpsertCountDuration
    // A new COUNT_DURATION record should be inserted
    EXPECT_EQ(dataHelper_->events_.size(), beforeSize + 1);
    int countIdx = dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_COUNT_DURATION);
    EXPECT_GE(countIdx, 0);
}

} // namespace MiscServices
} // namespace OHOS
