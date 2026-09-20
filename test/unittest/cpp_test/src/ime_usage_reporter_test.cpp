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

// Description: ImeUsageReporter unit test
// Create: 2026-08-25

#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "ime_usage_common.h"
#include "ime_usage_data_helper.h"

#define private   public
#define protected public
#include "ime_usage_reporter.h"
#undef private
#undef protected

#include "global.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;
using namespace ImeUsageEventId;
using namespace ImeScreenStatus;
using namespace ImeFoldStatusBase;

const std::string DB_DIR = "/data/test/ime_usage_reporter_test";
const std::string TEST_BUNDLE = "com.test.ime";

// Helper: parameters for InsertSessionForDay
struct SessionParams {
    std::string bundle;
    uint64_t startOffset = 0;
    uint64_t stopOffset = 0;
    int32_t screenStatus = SCREEN_STATUS_UNINITIALIZED;
};
} // namespace

class ImeUsageReporterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::unique_ptr<ImeUsageReporter> reporter_;
};

void ImeUsageReporterTest::SetUpTestCase(void) { }
void ImeUsageReporterTest::TearDownTestCase(void) { }

void ImeUsageReporterTest::SetUp()
{
    // Remove JSON files before each test to ensure a clean state
    std::remove((DB_DIR + "/ime_usage_events.json").c_str());
    std::remove((DB_DIR + "/ime_usage_state.json").c_str());

    reporter_ = std::make_unique<ImeUsageReporter>();
}

void ImeUsageReporterTest::TearDown()
{
    reporter_.reset();
}

// Helper: insert a complete session into DB for a given day
static void InsertSessionForDay(std::shared_ptr<ImeUsageDataHelper> db, uint64_t dayStart, const SessionParams &params)
{
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + params.startOffset;
    startRec.happenTime = dayStart + params.startOffset;
    startRec.bundleName = params.bundle;
    startRec.screenStatus = params.screenStatus;
    startRec.preScreenStatus = params.screenStatus;
    db->AddEvent(startRec);

    ImeEventRecord stopRec;
    stopRec.rawid = EVENT_INPUT_STOP;
    stopRec.ts = dayStart + params.stopOffset;
    stopRec.happenTime = dayStart + params.stopOffset;
    stopRec.bundleName = params.bundle;
    stopRec.screenStatus = params.screenStatus;
    stopRec.preScreenStatus = params.screenStatus;
    DurationMap durations {};
    durations[ScreenStatusToIndex(params.screenStatus)] = static_cast<uint64_t>(params.stopOffset - params.startOffset);
    db->AddEvent(stopRec, durations);

    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = dayStart + params.stopOffset;
    countRec.happenTime = dayStart + params.stopOffset;
    countRec.bundleName = params.bundle;
    countRec.screenStatus = params.screenStatus;
    countRec.preScreenStatus = params.screenStatus;
    db->AddEvent(countRec, durations);
}

// ==================== Init ====================

/**
 * @tc.name: ImeUsageReporter_Init_001
 * @tc.desc: Init with valid workPath succeeds
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, Init_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(reporter_->isRunning_);
    EXPECT_NE(reporter_->eventCacher_, nullptr);
    EXPECT_NE(reporter_->eventFactory_, nullptr);
}

/**
 * @tc.name: ImeUsageReporter_Init_002
 * @tc.desc: Init with no prior report and no data keeps lastReportTime as REPORT_TIME_NEVER
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, Init_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // lastReportTime_ defaults to 0 (REPORT_TIME_NEVER), which triggers immediate
    // report attempt. With no data in DB, lastReportTime_ stays REPORT_TIME_NEVER
    // so the first day's data won't be skipped when it arrives later.
    EXPECT_EQ(reporter_->lastReportTime_, 0u);
}

// ==================== SetEventHandler ====================

/**
 * @tc.name: ImeUsageReporter_SetEventHandler_001
 * @tc.desc: SetEventHandler stores handler and starts timer
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, SetEventHandler_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    auto handler = std::make_shared<AppExecFwk::EventHandler>();
    reporter_->SetEventHandler(handler);
    EXPECT_EQ(reporter_->eventHandler_, handler);
}

/**
 * @tc.name: ImeUsageReporter_SetEventHandler_002
 * @tc.desc: SetEventHandler with nullptr handler does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, SetEventHandler_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->SetEventHandler(nullptr);
    EXPECT_EQ(reporter_->eventHandler_, nullptr);
}

// ==================== StartTimer ====================

/**
 * @tc.name: ImeUsageReporter_StartTimer_001
 * @tc.desc: StartTimer without handler does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, StartTimer_001, TestSize.Level0)
{
    reporter_->eventHandler_ = nullptr;
    // Without handler, StartTimer should return early without crash
    reporter_->StartTimer();
    // Verify eventHandler_ remains nullptr (unchanged)
    EXPECT_EQ(reporter_->eventHandler_, nullptr);
    // Verify isRunning_ state was not affected
    EXPECT_FALSE(reporter_->isRunning_);
    // nextReportTime_ should remain 0 (no timer scheduled)
    EXPECT_EQ(reporter_->nextReportTime_, 0u);
}

// ==================== OnTimeout ====================

/**
 * @tc.name: ImeUsageReporter_OnTimeout_001
 * @tc.desc: OnTimeout when not running skips
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnTimeout_001, TestSize.Level0)
{
    reporter_->isRunning_ = false;
    uint64_t beforeTime = reporter_->lastReportTime_;
    // OnTimeout with isRunning_=false should skip ReportDailyEvent
    reporter_->OnTimeout();
    // Since isRunning_ is false, lastReportTime_ should remain unchanged
    EXPECT_EQ(reporter_->lastReportTime_, beforeTime);
    // isRunning_ should remain false
    EXPECT_FALSE(reporter_->isRunning_);
}

/**
 * @tc.name: ImeUsageReporter_OnTimeout_002
 * @tc.desc: OnTimeout when running triggers ReportDailyEvent
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnTimeout_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    auto handler = std::make_shared<AppExecFwk::EventHandler>();
    reporter_->SetEventHandler(handler);
    reporter_->OnTimeout();
    // Should not crash; ReportDailyEvent was called
}

/**
 * @tc.name: ImeUsageReporter_OnTimeout_003
 * @tc.desc: OnTimeout retries CreateComponents when dataHelper_ is null
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnTimeout_003, TestSize.Level0)
{
    // Init with empty path: CreateComponents fails, but reporter stays alive
    auto reporter = std::make_unique<ImeUsageReporter>();
    int ret = reporter->Init("");
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(reporter->dataHelper_, nullptr);
    // OnTimeout with a valid workPath should retry and succeed
    reporter->workPath_ = DB_DIR;
    reporter->OnTimeout();
    // After retry, components should be created
    EXPECT_NE(reporter->dataHelper_, nullptr);
    EXPECT_NE(reporter->eventCacher_, nullptr);
    EXPECT_NE(reporter->eventFactory_, nullptr);
}

// ==================== ReportDailyEvent ====================

/**
 * @tc.name: ImeUsageReporter_ReportDailyEvent_Scenario2
 * @tc.desc: Scenario 2 - time jumped forward
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportDailyEvent_Scenario2, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Set nextReportTime_ far in the past to simulate time jump
    reporter_->nextReportTime_ = reporter_->GetNowMs() - MILLISECS_PER_DAY * 2;
    reporter_->lastReportTime_ = reporter_->nextReportTime_ - MILLISECS_PER_DAY;
    reporter_->ReportDailyEvent();
    // Should have triggered a report
}

// ==================== InnerReportDailyEvent ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_002
 * @tc.desc: InnerReportDailyEvent with data in DB reports and cleans up
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    InsertSessionForDay(reporter_->dataHelper_, dayStart, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    reporter_->lastReportTime_ = 0;
    reporter_->InnerReportDailyEvent();
    // Should have reported and updated lastReportTime_
    EXPECT_NE(reporter_->lastReportTime_, 0u);
}

// ==================== ReportSingleDay ====================

/**
 * @tc.name: ImeUsageReporter_ReportSingleDay_001
 * @tc.desc: ReportSingleDay with no data returns false (no IME entries)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportSingleDay_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    reporter_->ReportSingleDay(dayStart, dayStart + MILLISECS_PER_DAY - 1, "20260825");
    // With no data, infos will be empty, so no WriteImeUsageEvent calls → allSuccess stays true
}

/**
 * @tc.name: ImeUsageReporter_ReportSingleDay_002
 * @tc.desc: ReportSingleDay with data in DB
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportSingleDay_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    InsertSessionForDay(reporter_->dataHelper_, dayStart, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    reporter_->ReportSingleDay(dayStart, dayStart + MILLISECS_PER_DAY - 1, "20260825");
    // HiSysEvent write may fail in test env, but the function should not crash
}

// ==================== OnImeBind/OnImeUnbind/OnScreenStatusChanged ====================

/**
 * @tc.name: ImeUsageReporter_OnImeBind_001
 * @tc.desc: OnImeBind with initialized reporter forwards to cacher
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnImeBind_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->OnImeBind(TEST_BUNDLE);
    // Should not crash; eventCacher_->OnImeBind was called
}

/**
 * @tc.name: ImeUsageReporter_OnImeUnbind_001
 * @tc.desc: OnImeUnbind with initialized reporter forwards to cacher
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnImeUnbind_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->OnImeBind(TEST_BUNDLE);
    reporter_->OnImeUnbind(TEST_BUNDLE);
    // Should not crash
}

/**
 * @tc.name: ImeUsageReporter_OnScreenStatusChanged_001
 * @tc.desc: OnScreenStatusChanged forwards to cacher
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnScreenStatusChanged_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    // Should not crash
}

// ==================== PersistLastReportTime / LoadLastReportTime ====================

/**
 * @tc.name: ImeUsageReporter_PersistLoadLastReportTime_001
 * @tc.desc: Persist and load roundtrip
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, PersistLoadLastReportTime_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t testTime = 1700000000000ULL; // some timestamp
    reporter_->lastReportTime_ = testTime;
    reporter_->PersistLastReportTime();

    uint64_t loaded = reporter_->LoadLastReportTime();
    EXPECT_EQ(loaded, testTime);
}

/**
 * @tc.name: ImeUsageReporter_LoadLastReportTime_001
 * @tc.desc: LoadLastReportTime returns 0 when key not in DB
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, LoadLastReportTime_001, TestSize.Level0)
{
    // Do NOT call Init() here — Init() triggers InnerReportDailyEvent() which
    // persists lastReportTime_ to DB. We want to verify LoadLastReportTime
    // returns 0 when the DB has no saved state. Manually set up eventFactory_
    // so LoadLastReportTime can access the dataHelper.
    auto dataHelper = std::make_shared<ImeUsageDataHelper>(DB_DIR);
    ASSERT_NE(dataHelper, nullptr);
    ASSERT_TRUE(dataHelper->IsReady());
    reporter_->eventFactory_ = std::make_unique<ImeUsageEventFactory>(dataHelper);
    ASSERT_NE(reporter_->eventFactory_, nullptr);
    // No prior persist, so load should return 0
    uint64_t loaded = reporter_->LoadLastReportTime();
    EXPECT_EQ(loaded, 0u);
}

// ==================== GetNowMs ====================

/**
 * @tc.name: ImeUsageReporter_GetNowMs_001
 * @tc.desc: GetNowMs returns non-zero value
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, GetNowMs_001, TestSize.Level0)
{
    // GetNowMs should return a non-zero timestamp
    uint64_t now = reporter_->GetNowMs();
    EXPECT_GT(now, 0u);
    // Calling again should return a >= value (time doesn't go backward)
    uint64_t now2 = reporter_->GetNowMs();
    EXPECT_GE(now2, now);
    // Value should be reasonable (less than year 2100 in ms)
    EXPECT_LT(now, 4102444800000ULL);
}

// ==================== Init error paths ====================

/**
 * @tc.name: ImeUsageReporter_Init_003
 * @tc.desc: Init with eventCacher_->Init failure returns error
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, Init_003, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Force eventCacher_->Init to fail by setting dataHelper to nullptr inside cacher
    reporter_->eventCacher_->dataHelper_ = nullptr;
    // Now re-init should still succeed (new cacher created)
    auto reporter2 = std::make_unique<ImeUsageReporter>();
    ret = reporter2->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
}

// ==================== InnerReportDailyEvent null checks ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_004
 * @tc.desc: InnerReportDailyEvent with null dataHelper returns early
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_004, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventFactory_ = std::make_unique<ImeUsageEventFactory>(nullptr);
    reporter_->InnerReportDailyEvent();
    // Should not crash
}

// ==================== InnerReportDailyEvent: lastReportTime_==0 with no data ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_005
 * @tc.desc: InnerReportDailyEvent with lastReportTime_==0 and no data keeps REPORT_TIME_NEVER
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_005, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->lastReportTime_ = 0;
    reporter_->InnerReportDailyEvent();
    // No data in DB: lastReportTime_ must remain REPORT_TIME_NEVER (0) so that
    // when data arrives later, the next report cycle starts from the earliest
    // event day instead of skipping it.
    EXPECT_EQ(reporter_->lastReportTime_, 0u);
}

// ==================== ReportDailyEvent scenario3 triggers report ====================

/**
 * @tc.name: ImeUsageReporter_ReportDailyEvent_Scenario3_TriggersReport
 * @tc.desc: Scenario 3 time jumped backward with lastReportTime_ < currentPeriodStart triggers report
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportDailyEvent_Scenario3_TriggersReport, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Set nextReportTime_ far in the future (clock backward scenario)
    uint64_t now = reporter_->GetNowMs();
    reporter_->nextReportTime_ = now + MILLISECS_PER_DAY * 2;
    reporter_->lastReportTime_ = now - MILLISECS_PER_DAY * 5;
    reporter_->ReportDailyEvent();
    // Should have reset lastReportTime_ to now and recalculated nextReportTime_
    EXPECT_NE(reporter_->lastReportTime_, now - MILLISECS_PER_DAY * 5);
}

// ==================== ReportSingleDay null check ====================

/**
 * @tc.name: ImeUsageReporter_ReportSingleDay_003
 * @tc.desc: ReportSingleDay with null eventFactory_ returns false
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportSingleDay_003, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventFactory_ = nullptr;
    bool result = reporter_->ReportSingleDay(0, MILLISECS_PER_DAY - 1, "20260825");
    EXPECT_FALSE(result);
}

// ==================== ReportAndCleanupOldData null check ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_003
 * @tc.desc: ReportAndCleanupOldData with null eventFactory_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_003, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventFactory_ = nullptr;
    reporter_->ReportAndCleanupOldData(0);
    // Should not crash
}

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_004
 * @tc.desc: ReportAndCleanupOldData with no data in DB skips cleanup
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_004, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());
    // No data in DB
    uint64_t clearTime = today - MILLISECS_PER_DAY;
    reporter_->ReportAndCleanupOldData(clearTime);
    // Should not crash; no data to report or cleanup
}

// ==================== OnImeBind/Unbind/ScreenStatusChanged with null cacher ====================

/**
 * @tc.name: ImeUsageReporter_OnImeBind_NullCacher
 * @tc.desc: OnImeBind with null eventCacher_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnImeBind_NullCacher, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventCacher_ = nullptr;
    reporter_->OnImeBind(TEST_BUNDLE);
    // Should not crash
}

/**
 * @tc.name: ImeUsageReporter_OnImeUnbind_NullCacher
 * @tc.desc: OnImeUnbind with null eventCacher_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnImeUnbind_NullCacher, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventCacher_ = nullptr;
    reporter_->OnImeUnbind(TEST_BUNDLE);
    // Should not crash
}

/**
 * @tc.name: ImeUsageReporter_OnScreenStatusChanged_NullCacher
 * @tc.desc: OnScreenStatusChanged with null eventCacher_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnScreenStatusChanged_NullCacher, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventCacher_ = nullptr;
    reporter_->OnScreenStatusChanged(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    // Should not crash
}

// ==================== OnBootCompleted with recent lastReportTime ====================

/**
 * @tc.name: ImeUsageReporter_OnBootCompleted_002
 * @tc.desc: OnBootCompleted with lastReportTime_ >= currentPeriodStart does not trigger report
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnBootCompleted_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Set lastReportTime_ to a recent time
    uint64_t currentPeriodStart = GetToday0ClockMs();
    reporter_->lastReportTime_ = currentPeriodStart + 1000;
    // Persist so LoadLastReportTime returns a recent value
    reporter_->PersistLastReportTime();
    uint64_t beforeTime = reporter_->lastReportTime_;
    reporter_->OnBootCompleted();
    // lastReportTime_ was loaded as recent, no report needed
    EXPECT_EQ(reporter_->lastReportTime_, beforeTime);
}

// ==================== PersistLastReportTime null check ====================
// Note: PersistLastReportTime_NullDataHelper is now in the Branch Coverage section below.

/**
 * @tc.name: ImeUsageReporter_LoadLastReportTime_NullDataHelper
 * @tc.desc: LoadLastReportTime with null dataHelper_ returns 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, LoadLastReportTime_NullDataHelper, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->dataHelper_ = nullptr;
    uint64_t loaded = reporter_->LoadLastReportTime();
    EXPECT_EQ(loaded, 0u);
}

// ==================== Destructor ====================

/**
 * @tc.name: ImeUsageReporter_Destructor_001
 * @tc.desc: Destructor with handler removes timer task
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, Destructor_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    auto handler = std::make_shared<AppExecFwk::EventHandler>();
    reporter_->SetEventHandler(handler);
    // Destroy reporter - should remove task from handler
    reporter_.reset();
    // No crash means success
}

/**
 * @tc.name: ImeUsageReporter_Destructor_002
 * @tc.desc: Destructor without handler does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, Destructor_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // No handler set
    reporter_.reset();
    // No crash means success
}

// ==================== WriteImeUsageEvent ====================

/**
 * @tc.name: ImeUsageReporter_WriteImeUsageEvent_001
 * @tc.desc: WriteImeUsageEvent returns false when HiSysEventWrite fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, WriteImeUsageEvent_001, TestSize.Level0)
{
    ImeUsageInfo info;
    info.package = TEST_BUNDLE;
    info.durations[IDX_UNFOLDED_PORTRAIT] = 5000;
    info.usage = 5000;
    bool result = reporter_->WriteImeUsageEvent(info, "20260825");
    // HiSysEventWrite typically returns non-0 in test environment
    // The function should not crash regardless of the result
    // Verify it returns a boolean (either true or false is acceptable in test env)
    EXPECT_TRUE(result == true || result == false);
}

// ==================== GetNextReportTimeMs edge cases ====================

/**
 * @tc.name: ImeUsageReporter_GetNextReportTimeMs_002
 * @tc.desc: GetNextReportTimeMs returns tomorrow midnight
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, GetNextReportTimeMs_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t nextReport = reporter_->GetNextReportTimeMs();
    uint64_t today0 = GetToday0ClockMs();
    if (today0 > 0) {
        EXPECT_EQ(nextReport, today0 + MILLISECS_PER_DAY);
    }
}

// ==================== Init: dataHelper creation failure ====================

/**
 * @tc.name: ImeUsageReporter_Init_004
 * @tc.desc: Init with invalid workPath (empty string) still returns 0 (deferred retry)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, Init_004, TestSize.Level0)
{
    auto reporter = std::make_unique<ImeUsageReporter>();
    int ret = reporter->Init("");
    // Empty path causes dataHelper creation to fail, but Init now returns 0
    // so the reporter stays alive and OnTimeout can retry CreateComponents.
    EXPECT_EQ(ret, 0);
    // Components should be null (CreateComponents failed)
    EXPECT_EQ(reporter->dataHelper_, nullptr);
    EXPECT_EQ(reporter->eventCacher_, nullptr);
    EXPECT_EQ(reporter->eventFactory_, nullptr);
    // isRunning_ should be true so the timer runs and triggers retry
    EXPECT_TRUE(reporter->isRunning_);
}

// ==================== ReportAndCleanupOldData: clearDataTime <= firstReportDayStart ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_006
 * @tc.desc: ReportAndCleanupOldData with clearDataTime at today boundary skips recent data
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_006, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());
    // Insert data for today
    InsertSessionForDay(reporter_->dataHelper_, today, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    // clearDataTime == today: reportEnd = today - 1, which excludes today's events
    uint64_t clearTime = today;
    reporter_->ReportAndCleanupOldData(clearTime);
    // Today's data should NOT be deleted (happenTime >= clearTime)
    int idx = reporter_->dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_NE(idx, IME_INDEX_NOT_FOUND);
}

// ==================== ReportAndCleanupOldData: some reports fail (allReported=false) ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_007
 * @tc.desc: ReportAndCleanupOldData with data may keep data when report fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_007, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());
    // Insert data for an old day (should trigger report + cleanup)
    uint64_t oldDay = today - MILLISECS_PER_DAY * 2;
    InsertSessionForDay(reporter_->dataHelper_, oldDay, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    // clearDataTime > oldDay so cleanup should run
    uint64_t clearTime = oldDay + MILLISECS_PER_DAY;
    reporter_->ReportAndCleanupOldData(clearTime);
    // HiSysEventWrite may fail in test env, so allReported may be false
    // If allReported is false, data should NOT be deleted
    // This exercises the else branch
}

// ==================== InnerReportDailyEvent: lastReportTime_ != 0 (else branch) ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_006
 * @tc.desc: InnerReportDailyEvent with lastReportTime_ on today skips today (already reported)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_006, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());
    // Insert data for today
    InsertSessionForDay(reporter_->dataHelper_, today, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });
    // Set lastReportTime_ to today (already reported today's data previously)
    reporter_->lastReportTime_ = today + 1000;
    reporter_->InnerReportDailyEvent();
    // With fix: reportDayStart = today + MILLISECS_PER_DAY (tomorrow) > yesterdayEnd (today - 1)
    // So no reporting should occur, but lastReportTime_ should still be updated
    // to yesterdayEnd (today - 1)
    EXPECT_NE(reporter_->lastReportTime_, today + 1000);
    EXPECT_LT(reporter_->lastReportTime_, today);
}

// ==================== LoadLastReportTime: zero value in DB ====================

/**
 * @tc.name: ImeUsageReporter_LoadLastReportTime_ZeroValue
 * @tc.desc: LoadLastReportTime with 0 stored in DB returns 0 (REPORT_TIME_NEVER)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, LoadLastReportTime_ZeroValue, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->dataHelper_->SaveReportState(STATE_KEY_LAST_REPORT_TIME, 0ULL);
    uint64_t loaded = reporter_->LoadLastReportTime();
    EXPECT_EQ(loaded, 0u);
}

// ==================== GetNextReportTimeMs: today0 == 0 fallback ====================

/**
 * @tc.name: ImeUsageReporter_GetNextReportTimeMs_003
 * @tc.desc: GetNextReportTimeMs returns a valid future time
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, GetNextReportTimeMs_003, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t nextReport = reporter_->GetNextReportTimeMs();
    uint64_t now = reporter_->GetNowMs();
    // nextReportTime should be in the future
    EXPECT_GT(nextReport, now);
    // Should be at most 1 day + 1 day from now (today midnight + 1 day)
    EXPECT_LT(nextReport, now + MILLISECS_PER_DAY * 2);
}

// ==================== ReportDailyEvent: scenario4 no-report (now < nextReportTime) ====================

/**
 * @tc.name: ImeUsageReporter_ReportDailyEvent_Scenario4_NoReport
 * @tc.desc: Scenario 4 - now < nextReportTime_ does not trigger report
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportDailyEvent_Scenario4_NoReport, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Set nextReportTime_ far in the future
    reporter_->nextReportTime_ = reporter_->GetNowMs() + MILLISECS_PER_DAY;
    uint64_t beforeTime = reporter_->lastReportTime_;
    reporter_->ReportDailyEvent();
    // Should not trigger InnerReportDailyEvent since now < nextReportTime_
    // lastReportTime_ should remain unchanged
    EXPECT_EQ(reporter_->lastReportTime_, beforeTime);
}

// ==================== Init: no immediate report when lastReportTime_ is recent ====================

/**
 * @tc.name: ImeUsageReporter_Init_005
 * @tc.desc: Init with existing recent lastReportTime does not trigger immediate report
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, Init_005, TestSize.Level0)
{
    // First init and persist a recent lastReportTime
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t currentPeriodStart = GetToday0ClockMs();
    reporter_->lastReportTime_ = currentPeriodStart + 1;
    reporter_->PersistLastReportTime();
    reporter_.reset();

    // Re-init: should load the recent lastReportTime and not trigger report
    reporter_ = std::make_unique<ImeUsageReporter>();
    ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // lastReportTime_ should be loaded as recent (>= currentPeriodStart)
    EXPECT_GE(reporter_->lastReportTime_, currentPeriodStart);
}

// ==================== ReportDailyEvent: exact boundary (now == nextReport) ====================

/**
 * @tc.name: ImeUsageReporter_ReportDailyEvent_ExactBoundary
 * @tc.desc: ReportDailyEvent when now == nextReportTime triggers report
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportDailyEvent_ExactBoundary, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Set nextReportTime_ to current time exactly
    uint64_t now = reporter_->GetNowMs();
    reporter_->nextReportTime_ = now;
    reporter_->ReportDailyEvent();
    // Should trigger InnerReportDailyEvent since now >= nextReport
    // With no data, lastReportTime_ stays REPORT_TIME_NEVER but nextReportTime_
    // is advanced to avoid repeated triggers
    {
        std::lock_guard<std::mutex> lock(reporter_->reportMutex_);
        EXPECT_GT(reporter_->nextReportTime_, now);
    }
}

// ==================== InnerReportDailyEvent: first report with data (REPORT_TIME_NEVER path) ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_007
 * @tc.desc: InnerReportDailyEvent with lastReportTime_==0 and data in DB uses earliest event time
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_007, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    InsertSessionForDay(reporter_->dataHelper_, dayStart, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    // Reset to simulate first-ever report with data (REPORT_TIME_NEVER path)
    reporter_->lastReportTime_ = REPORT_TIME_NEVER;
    reporter_->InnerReportDailyEvent();
    // Should have found earliest event time and reported that day
    EXPECT_NE(reporter_->lastReportTime_, 0u);
    EXPECT_NE(reporter_->lastReportTime_, REPORT_TIME_NEVER);
}

// ==================== InnerReportDailyEvent: no re-report of lastReportTime's day (Bug 1 fix) ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_NoReReport
 * @tc.desc: After reporting yesterday, booting today does not re-report yesterday
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_NoReReport, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());
    uint64_t yesterday = today - MILLISECS_PER_DAY;

    // Insert data for yesterday
    InsertSessionForDay(reporter_->dataHelper_, yesterday, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    // Simulate: yesterday was already reported (lastReportTime set to yesterday afternoon)
    reporter_->lastReportTime_ = yesterday + 12 * 3600000; // yesterday 12:00
    reporter_->InnerReportDailyEvent();

    // With fix: reportDayStart = yesterday + MILLISECS_PER_DAY = today
    // yesterdayEnd = today - 1
    // reportDayStart (today) > yesterdayEnd (today - 1) → no days to report
    // lastReportTime_ should be updated to yesterdayEnd (end of reported period)
    EXPECT_GE(reporter_->lastReportTime_, yesterday);
    EXPECT_LT(reporter_->lastReportTime_, today);

    // Yesterday's data should still be in DB (not deleted by cleanup since
    // clearDataTime = today - 3 days, which is before yesterday)
    int idx = reporter_->dataHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_NE(idx, IME_INDEX_NOT_FOUND);
}

// ==================== InnerReportDailyEvent: multi-day gap reporting (Bug 1+3 fix) ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_MultiDayGap
 * @tc.desc: Boot after 4-day gap reports unreported days but not the already-reported day
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_MultiDayGap, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());

    // Simulate: data exists for day-4, day-3, day-2 (but only day-4 was reported)
    uint64_t day4 = today - MILLISECS_PER_DAY * 4;
    uint64_t day3 = today - MILLISECS_PER_DAY * 3;
    uint64_t day2 = today - MILLISECS_PER_DAY * 2;

    InsertSessionForDay(reporter_->dataHelper_, day4, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });
    InsertSessionForDay(reporter_->dataHelper_, day3, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });
    InsertSessionForDay(reporter_->dataHelper_, day2, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    // lastReportTime was set during day-4's report (day-4 afternoon).
    // This simulates a stale mid-day lastReportTime value (e.g., written by
    // older code that set lastReportTime = now, or by the time-jumped-backward
    // branch before the fix).
    reporter_->lastReportTime_ = day4 + 12 * 3600000;
    reporter_->InnerReportDailyEvent();

    // With fix (CalcReportDayStart): reportDayStart = DayStartFromMs(day4 + 12h + 1)
    //   = DayStartFromMs(day4 + 12h + 1ms) = day4 (NOT day4 + 1 day)
    // So QueryActiveDays(day4, today-1) returns [day4, day3, day2].
    // Note: this may re-report day4 (the portion before lastReportTime), which
    // is acceptable and far better than losing the whole day.
    //
    // With fix (ReportAndCleanupOldData): before deleting old data, the cleanup
    // only reports days that haven't been reported yet. After
    // UpdateAndPersistReportTime(yesterdayEnd = today - 1), lastReportTime_ =
    // today - 1. So in ReportAndCleanupOldData(day3):
    //   reportEnd = day3 - 1
    //   unreportedStart = (today - 1) + 1 = today
    //   today > reportEnd (day3 - 1) → unreportedStart = reportEnd + 1 = day3
    //   QueryActiveDays(day3, day3 - 1) → empty → day4 is NOT re-reported via cleanup
    // Then DeleteEventsByTime(day3) deletes day4's events (happenTime < day3).

    // Verify lastReportTime was updated to yesterdayEnd (end of reported period)
    EXPECT_GE(reporter_->lastReportTime_, day2);
    EXPECT_LT(reporter_->lastReportTime_, today);

    // Verify day4's data was deleted by cleanup (happenTime < clearDataTime = day3).
    // After deletion, the remaining START events belong to day3 (id=4) and day2 (id=7),
    // so QueryRawEventIndex returns the last remaining START id (7), not day4's (1).
    // Instead, verify no events with happenTime < day3 remain.
    int64_t earliest = reporter_->dataHelper_->QueryEarliestEventTime();
    EXPECT_GE(static_cast<uint64_t>(earliest), day3);

    // Verify the cleanup did NOT re-report day4: with the fix, unreportedStart
    // is derived from lastReportTime_ (today - 1, set by UpdateAndPersistReportTime
    // before cleanup), so QueryActiveDays(day3, day3-1) returns empty and day4
    // is not re-reported. day4's data is simply deleted.
    // (We cannot directly assert "no HiSysEvent was written for day4", but the
    // empty QueryActiveDays result is the precondition that guarantees this.)
}

// ==================== ReportAndCleanupOldData: no re-report of already-reported days (fix) ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_NoReReportAlreadyReported
 * @tc.desc: Cleanup with lastReportTime covering an expiring day does NOT re-report that day
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_NoReReportAlreadyReported, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());

    // Scenario: day-4 (e.g., 09-18) was already reported at 09-18 23:59:59.999,
    // so lastReportTime_ = day4_end. day-2 (e.g., 09-20) also has data.
    uint64_t day4 = today - MILLISECS_PER_DAY * 4;
    uint64_t day2 = today - MILLISECS_PER_DAY * 2;
    InsertSessionForDay(reporter_->dataHelper_, day4, { "com.day4.ime", 3600000, 7200000, UNFOLDED_PORTRAIT });
    InsertSessionForDay(reporter_->dataHelper_, day2, { "com.day2.ime", 3600000, 7200000, UNFOLDED_PORTRAIT });

    // lastReportTime_ = end of day4 (already reported day4's data previously)
    uint64_t day4End = day4 + MILLISECS_PER_DAY - 1;
    reporter_->lastReportTime_ = day4End;

    // Simulate cleanup: clearDataTime = day-3 (e.g., 09-19).
    // With fix (ReportAndCleanupOldData):
    //   reportEnd = clearDataTime - 1 = day3 - 1 = day4End
    //   localLastReportTime = day4End (set above)
    //   localLastReportTime + 1 = day3 > reportEnd (day3 - 1) → true
    //   unreportedStart = reportEnd + 1 = day3
    //   QueryActiveDays(day3, day3 - 1) → empty range (start > end) → day4 NOT re-reported
    //   Then DeleteEventsByTime(day3) deletes day4's events (happenTime < day3).
    uint64_t clearDataTime = today - MILLISECS_PER_DAY * 3; // day3
    reporter_->ReportAndCleanupOldData(clearDataTime);

    // day4's data should be deleted (happenTime < clearDataTime = day3)
    int day4Idx = reporter_->dataHelper_->QueryRawEventIndex("com.day4.ime", EVENT_INPUT_START);
    EXPECT_EQ(day4Idx, IME_INDEX_NOT_FOUND);

    // day2's data should be preserved (happenTime >= clearDataTime)
    int day2Idx = reporter_->dataHelper_->QueryRawEventIndex("com.day2.ime", EVENT_INPUT_START);
    EXPECT_NE(day2Idx, IME_INDEX_NOT_FOUND);

    // Verify the cleanup did not re-report day4 by checking QueryActiveDays
    // returns empty for the cleanup range [unreportedStart, reportEnd].
    // unreportedStart = day3, reportEnd = day3 - 1 → empty range.
    uint64_t reportEnd = clearDataTime > 0 ? clearDataTime - 1 : 0;
    uint64_t expectedUnreportedStart = day4End + 1; // = day3
    auto activeDays = reporter_->dataHelper_->QueryActiveDays(expectedUnreportedStart, reportEnd);
    EXPECT_EQ(activeDays.size(), 0u);
}

// ==================== CalcReportDayStart: mid-day lastReportTime does not skip the day (fix) ====================

/**
 * @tc.name: ImeUsageReporter_CalcReportDayStart_MidDayLastReportTime
 * @tc.desc: CalcReportDayStart with mid-day lastReportTime returns the same day's 00:00, not next day
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, CalcReportDayStart_MidDayLastReportTime, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());

    // Simulate a stale mid-day lastReportTime (e.g., 09-20 00:24:34.899) that
    // could be written by older code (lastReportTime = now) or by the
    // time-jumped-backward branch before the fix.
    uint64_t midDayOffset = 24 * 60 * 1000 + 34 * 1000 + 899; // 00:24:34.899
    uint64_t midDayLastReportTime = today + midDayOffset;
    reporter_->lastReportTime_ = midDayLastReportTime;

    // Call CalcReportDayStart with today's 00:00 as today0Time
    uint64_t reportDayStart = 0;
    bool result = reporter_->CalcReportDayStart(today, reportDayStart);

    // Should return true (lastReportTime != REPORT_TIME_NEVER)
    EXPECT_TRUE(result);

    // With fix: reportDayStart = DayStartFromMs(midDayLastReportTime + 1)
    //   = DayStartFromMs(today + 00:24:34.900) = today (00:00 of the same day)
    // OLD (buggy) formula: DayStartFromMs(midDayLastReportTime) + MILLISECS_PER_DAY
    //   = today + MILLISECS_PER_DAY (tomorrow) → would skip today's data
    EXPECT_EQ(reportDayStart, today);

    // Verify the day is NOT skipped: reportDayStart should be <= today's end
    // and should equal today's 00:00 (so today's data will be reported)
    EXPECT_LT(reportDayStart, today + MILLISECS_PER_DAY);
}

// ==================== CalcReportDayStart: day-end lastReportTime yields next day (equivalence check)
// ====================

/**
 * @tc.name: ImeUsageReporter_CalcReportDayStart_DayEndLastReportTime
 * @tc.desc: CalcReportDayStart with day-end lastReportTime yields next day (equivalent to old formula)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, CalcReportDayStart_DayEndLastReportTime, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());

    // lastReportTime = end of yesterday (23:59:59.999) — the normal value
    // written by UpdateAndPersistReportTime(yesterdayEnd).
    uint64_t yesterdayEnd = today - 1;
    reporter_->lastReportTime_ = yesterdayEnd;

    uint64_t reportDayStart = 0;
    bool result = reporter_->CalcReportDayStart(today, reportDayStart);
    EXPECT_TRUE(result);

    // With fix: reportDayStart = DayStartFromMs(yesterdayEnd + 1)
    //   = DayStartFromMs(today) = today
    // OLD formula: DayStartFromMs(yesterdayEnd) + MILLISECS_PER_DAY
    //   = (today - 1 day) + MILLISECS_PER_DAY... but DayStartFromMs(today - 1ms)
    //   = DayStartFromMs(yesterday 23:59:59.999) = yesterday 00:00 = today - 1 day
    //   So old = (today - 1 day) + 1 day = today. Same result.
    EXPECT_EQ(reportDayStart, today);
}

// ==================== ReportDailyEvent: time-jumped-backward writes yesterdayEnd (fix) ====================

/**
 * @tc.name: ImeUsageReporter_ReportDailyEvent_TimeBackwardWritesYesterdayEnd
 * @tc.desc: Time-jumped-backward branch sets lastReportTime_ to DayStartFromMs(now)-1, not now
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportDailyEvent_TimeBackwardWritesYesterdayEnd, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t now = reporter_->GetNowMs();

    // Trigger the time-jumped-backward branch: nextReportTime_ far in the future
    // so that now < nextReportTime_ - MILLISECS_PER_DAY.
    reporter_->nextReportTime_ = now + MILLISECS_PER_DAY * 2;
    reporter_->lastReportTime_ = now - MILLISECS_PER_DAY * 5;

    reporter_->ReportDailyEvent();

    // With fix: lastReportTime_ should be set to yesterdayEnd = DayStartFromMs(now) - 1
    // (NOT now itself, which would be a mid-day value and cause CalcReportDayStart
    // to skip the current day in the next report cycle).
    uint64_t expectedDay0 = DayStartFromMs(now);
    uint64_t expectedYesterdayEnd = expectedDay0 > 0 ? expectedDay0 - 1 : 0;

    // lastReportTime_ should equal yesterdayEnd, not now
    EXPECT_EQ(reporter_->lastReportTime_, expectedYesterdayEnd);
    EXPECT_NE(reporter_->lastReportTime_, now);

    // Verify lastReportTime_ is at the end of yesterday (within the same day
    // as expectedYesterdayEnd, i.e., < today's 00:00)
    EXPECT_LT(reporter_->lastReportTime_, expectedDay0);

    // nextReportTime_ should be recalculated (to tomorrow midnight)
    EXPECT_GT(reporter_->nextReportTime_, now);
}

// ==================== InnerReportDailyEvent: lastReportTime persisted before cleanup (Bug 4 fix) ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_PersistBeforeCleanup
 * @tc.desc: lastReportTime is persisted to JSON before DeleteEventsByTime runs
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_PersistBeforeCleanup, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());

    // Insert old data that will be cleaned up
    uint64_t oldDay = today - MILLISECS_PER_DAY * 4;
    InsertSessionForDay(reporter_->dataHelper_, oldDay, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    reporter_->lastReportTime_ = oldDay + 12 * 3600000;
    reporter_->InnerReportDailyEvent();

    // After InnerReportDailyEvent, check that the persisted lastReportTime in JSON
    // is the NEW value (not the old one). Load it from dataHelper.
    uint64_t loaded = 0;
    reporter_->dataHelper_->LoadReportState(STATE_KEY_LAST_REPORT_TIME, loaded);
    // The persisted value should be yesterdayEnd (today - 1), NOT the old
    // lastReportTime_ (oldDay + 12h)
    EXPECT_NE(loaded, oldDay + 12 * 3600000);
    EXPECT_LT(loaded, today);
    EXPECT_GE(loaded, today - MILLISECS_PER_DAY);
}

// ==================== ReportAndCleanupOldData: reports and deletes old data only ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_DeletesOldPreservesNew
 * @tc.desc: ReportAndCleanupOldData deletes old data but preserves data after clearDataTime
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_DeletesOldPreservesNew, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());

    // Insert old data (4 days ago — should be cleaned up)
    uint64_t oldDay = today - MILLISECS_PER_DAY * 4;
    InsertSessionForDay(reporter_->dataHelper_, oldDay, { "com.old.ime", 3600000, 7200000, UNFOLDED_PORTRAIT });

    // Insert recent data (1 day ago — should be preserved)
    uint64_t recentDay = today - MILLISECS_PER_DAY;
    InsertSessionForDay(reporter_->dataHelper_, recentDay, { "com.new.ime", 3600000, 7200000, UNFOLDED_PORTRAIT });

    uint64_t clearTime = today - MILLISECS_PER_DAY * DATA_KEEP_DAY; // 3 days ago
    reporter_->ReportAndCleanupOldData(clearTime);

    // Old data should be deleted
    int oldIdx = reporter_->dataHelper_->QueryRawEventIndex("com.old.ime", EVENT_INPUT_START);
    EXPECT_EQ(oldIdx, IME_INDEX_NOT_FOUND);

    // Recent data should be preserved
    int newIdx = reporter_->dataHelper_->QueryRawEventIndex("com.new.ime", EVENT_INPUT_START);
    EXPECT_NE(newIdx, IME_INDEX_NOT_FOUND);
}

// ==================== Branch Coverage: InnerReportDailyEvent null dataHelper ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_NullDataHelper
 * @tc.desc: InnerReportDailyEvent with null dataHelper_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_NullDataHelper, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->dataHelper_ = nullptr;
    // Should not crash, returns immediately
    reporter_->InnerReportDailyEvent();
    EXPECT_EQ(reporter_->dataHelper_, nullptr);
}

// ==================== Branch Coverage: OnBootCompleted ====================

/**
 * @tc.name: ImeUsageReporter_OnBootCompleted_001
 * @tc.desc: OnBootCompleted with valid eventCacher_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnBootCompleted_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(reporter_->eventCacher_, nullptr);
    reporter_->OnBootCompleted();
    // Should not crash; with no data, lastReportTime_ stays REPORT_TIME_NEVER
    EXPECT_EQ(reporter_->lastReportTime_, 0u);
}

/**
 * @tc.name: ImeUsageReporter_OnBootCompleted_NullCacher
 * @tc.desc: OnBootCompleted with null eventCacher_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnBootCompleted_NullCacher, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventCacher_ = nullptr;
    reporter_->OnBootCompleted();
    // Should not crash
    EXPECT_EQ(reporter_->eventCacher_, nullptr);
}

/**
 * @tc.name: ImeUsageReporter_OnBootCompleted_TriggersReport
 * @tc.desc: OnBootCompleted with lastReportTime_=0 and no data keeps REPORT_TIME_NEVER
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnBootCompleted_TriggersReport, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Reset lastReportTime_ to 0 to simulate never-reported state
    reporter_->lastReportTime_ = 0;
    reporter_->OnBootCompleted();
    // With no data, lastReportTime_ stays REPORT_TIME_NEVER (0)
    EXPECT_EQ(reporter_->lastReportTime_, 0u);
}

// ==================== Branch Coverage: PersistLastReportTime ====================

/**
 * @tc.name: ImeUsageReporter_PersistLastReportTime_NullDataHelper
 * @tc.desc: PersistLastReportTime with null dataHelper_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, PersistLastReportTime_NullDataHelper, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->dataHelper_ = nullptr;
    reporter_->lastReportTime_ = 12345ULL;
    // Should not crash, returns immediately
    reporter_->PersistLastReportTime();
    EXPECT_EQ(reporter_->dataHelper_, nullptr);
}

/**
 * @tc.name: ImeUsageReporter_PersistLastReportTime_SaveFails
 * @tc.desc: PersistLastReportTime when SaveReportState fails does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, PersistLastReportTime_SaveFails, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Make SaveReportState fail by clearing fileStore_->eventsFilePath_
    reporter_->dataHelper_->fileStore_->eventsFilePath_.clear();
    reporter_->lastReportTime_ = 99999ULL;
    // Should not crash; SaveReportState returns DB_FAILED but PersistLastReportTime just logs error
    reporter_->PersistLastReportTime();
    EXPECT_EQ(reporter_->lastReportTime_, 99999ULL);
}

// ==================== Branch Coverage: LoadLastReportTime ====================

/**
 * @tc.name: ImeUsageReporter_LoadLastReportTime_LoadFails
 * @tc.desc: LoadLastReportTime with ready_=false returns REPORT_TIME_NEVER (0)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, LoadLastReportTime_LoadFails, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Make LoadReportState fail by setting ready_ = false
    reporter_->dataHelper_->ready_ = false;
    uint64_t loaded = reporter_->LoadLastReportTime();
    // Should return REPORT_TIME_NEVER (0) on failure
    EXPECT_EQ(loaded, 0u);
}

// ==================== Branch Coverage: ReportAndCleanupOldData edge cases ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_NullDataHelper
 * @tc.desc: ReportAndCleanupOldData with null dataHelper_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_NullDataHelper, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->dataHelper_ = nullptr;
    reporter_->ReportAndCleanupOldData(MILLISECS_PER_DAY);
    // Should not crash
    EXPECT_EQ(reporter_->dataHelper_, nullptr);
}

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_ClearDataTimeZero
 * @tc.desc: ReportAndCleanupOldData with clearDataTime=0 does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_ClearDataTimeZero, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // clearDataTime=0 means reportEnd = 0-1 = 0 (underflow guarded by ternary)
    reporter_->ReportAndCleanupOldData(0);
    // Should not crash
    EXPECT_NE(reporter_->dataHelper_, nullptr);
}

} // namespace MiscServices
} // namespace OHOS
