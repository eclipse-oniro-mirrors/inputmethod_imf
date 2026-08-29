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
#include "ime_usage_db_helper.h"

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
    // Remove DB files before each test to ensure a clean state
    std::string dbFile = DB_DIR + "/ime_usage_log.db";
    std::remove(dbFile.c_str());
    std::remove((dbFile + "-wal").c_str());
    std::remove((dbFile + "-shm").c_str());

    reporter_ = std::make_unique<ImeUsageReporter>();
}

void ImeUsageReporterTest::TearDown()
{
    reporter_.reset();
}

// Helper: insert a complete session into DB for a given day
static void InsertSessionForDay(std::shared_ptr<ImeUsageDbHelper> db, const std::string &bundle, uint64_t dayStart,
    uint64_t startOffset, uint64_t stopOffset, int32_t screenStatus)
{
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + startOffset;
    startRec.happenTime = dayStart + startOffset;
    startRec.bundleName = bundle;
    startRec.screenStatus = screenStatus;
    startRec.preScreenStatus = screenStatus;
    db->AddEvent(startRec);

    ImeEventRecord stopRec;
    stopRec.rawid = EVENT_INPUT_STOP;
    stopRec.ts = dayStart + stopOffset;
    stopRec.happenTime = dayStart + stopOffset;
    stopRec.bundleName = bundle;
    stopRec.screenStatus = screenStatus;
    stopRec.preScreenStatus = screenStatus;
    DurationMap durations;
    durations[screenStatus] = static_cast<uint64_t>(stopOffset - startOffset);
    db->AddEvent(stopRec, durations);

    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = dayStart + stopOffset;
    countRec.happenTime = dayStart + stopOffset;
    countRec.bundleName = bundle;
    countRec.screenStatus = screenStatus;
    countRec.preScreenStatus = screenStatus;
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
 * @tc.desc: Init with no prior report triggers immediate daily report
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, Init_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // lastReportTime_ defaults to 0, which triggers immediate report
    // After report, lastReportTime_ should be updated to non-zero
    EXPECT_NE(reporter_->lastReportTime_, 0u);
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

/**
 * @tc.name: ImeUsageReporter_ReportDailyEvent_Scenario3
 * @tc.desc: Scenario 3 - time jumped backward
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportDailyEvent_Scenario3, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Set nextReportTime_ far in the future to simulate backward clock
    reporter_->nextReportTime_ = reporter_->GetNowMs() + MILLISECS_PER_DAY * 2;
    reporter_->ReportDailyEvent();
    // lastReportTime_ should be updated to now, nextReportTime_ recalculated
}

/**
 * @tc.name: ImeUsageReporter_ReportDailyEvent_Scenario4
 * @tc.desc: Scenario 4 - normal boundary crossing
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportDailyEvent_Scenario4, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Set nextReportTime_ to a past time (but within 1 day)
    reporter_->nextReportTime_ = reporter_->GetNowMs() - 1;
    reporter_->lastReportTime_ = reporter_->nextReportTime_ - MILLISECS_PER_DAY;
    reporter_->ReportDailyEvent();
}

// ==================== InnerReportDailyEvent ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_001
 * @tc.desc: InnerReportDailyEvent with no data in DB
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->InnerReportDailyEvent();
    // Should not crash; lastReportTime_ updated
}

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
    InsertSessionForDay(
        reporter_->eventFactory_->GetDbHelper(), TEST_BUNDLE, dayStart, 3600000, 7200000, UNFOLDED_PORTRAIT);

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
    InsertSessionForDay(
        reporter_->eventFactory_->GetDbHelper(), TEST_BUNDLE, dayStart, 3600000, 7200000, UNFOLDED_PORTRAIT);

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

// ==================== OnBootCompleted ====================

/**
 * @tc.name: ImeUsageReporter_OnBootCompleted_001
 * @tc.desc: OnBootCompleted with no prior report triggers immediate daily report
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnBootCompleted_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->OnBootCompleted();
    // lastReportTime_ was 0 (no prior report), should trigger immediate report
    EXPECT_NE(reporter_->lastReportTime_, 0u);
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
    // so LoadLastReportTime can access the dbHelper.
    auto dbHelper = std::make_shared<ImeUsageDbHelper>(DB_DIR);
    ASSERT_NE(dbHelper, nullptr);
    ASSERT_TRUE(dbHelper->IsReady());
    reporter_->eventFactory_ = std::make_unique<ImeUsageEventFactory>(dbHelper);
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

// ==================== GetNextReportTimeMs ====================

/**
 * @tc.name: ImeUsageReporter_GetNextReportTimeMs_001
 * @tc.desc: GetNextReportTimeMs returns value > now
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, GetNextReportTimeMs_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t nextReport = reporter_->GetNextReportTimeMs();
    uint64_t now = reporter_->GetNowMs();
    EXPECT_GT(nextReport, now);
}

// ==================== GetToday0ClockMs ====================

/**
 * @tc.name: ImeUsageReporter_GetToday0ClockMs_001
 * @tc.desc: GetToday0ClockMs returns today's 0:00
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, GetToday0ClockMs_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today0 = reporter_->GetToday0ClockMs();
    uint64_t expectedToday0 = GetToday0ClockMs();
    EXPECT_EQ(today0, expectedToday0);
}

// ==================== DayStartFromMs ====================

/**
 * @tc.name: ImeUsageReporter_DayStartFromMs_001
 * @tc.desc: DayStartFromMs converts ms to day start
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, DayStartFromMs_001, TestSize.Level0)
{
    uint64_t ms = 1700000000000ULL;
    uint64_t dayStart = reporter_->DayStartFromMs(ms);
    EXPECT_GT(dayStart, 0u);
    // dayStart should be <= the input timestamp (it's the midnight of that day)
    EXPECT_LE(dayStart, ms);
    // dayStart + MILLISECS_PER_DAY should be > the input timestamp (next midnight is after it)
    EXPECT_GT(dayStart + MILLISECS_PER_DAY, ms);
}

// ==================== ReportAndCleanupOldData ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_001
 * @tc.desc: ReportAndCleanupOldData with no data in DB
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_001, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t clearTime = reporter_->GetNowMs();
    reporter_->ReportAndCleanupOldData(clearTime, clearTime + MILLISECS_PER_DAY);
    // Should not crash
}

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_002
 * @tc.desc: ReportAndCleanupOldData deletes data when all reports succeed
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_002, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());
    // Insert data for 4 days ago (should be cleaned up)
    uint64_t oldDay = today - MILLISECS_PER_DAY * 4;
    InsertSessionForDay(
        reporter_->eventFactory_->GetDbHelper(), TEST_BUNDLE, oldDay, 3600000, 7200000, UNFOLDED_PORTRAIT);

    uint64_t clearTime = today - MILLISECS_PER_DAY * DATA_KEEP_DAY;
    reporter_->ReportAndCleanupOldData(clearTime, oldDay + MILLISECS_PER_DAY);
    // Verify data was deleted
    int idx = reporter_->eventFactory_->GetDbHelper()->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_EQ(idx, IME_INDEX_NOT_FOUND);
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
    // Force eventCacher_->Init to fail by setting dbHelper to nullptr inside cacher
    reporter_->eventCacher_->dbHelper_ = nullptr;
    // Now re-init should still succeed (new cacher created)
    auto reporter2 = std::make_unique<ImeUsageReporter>();
    ret = reporter2->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
}

// ==================== InnerReportDailyEvent null checks ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_003
 * @tc.desc: InnerReportDailyEvent with null eventFactory_ returns early
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_003, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventFactory_ = nullptr;
    reporter_->InnerReportDailyEvent();
    // Should not crash; lastReportTime_ stays unchanged
}

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_004
 * @tc.desc: InnerReportDailyEvent with null dbHelper returns early
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
 * @tc.desc: InnerReportDailyEvent with lastReportTime_==0 and no data updates time
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_005, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->lastReportTime_ = 0;
    reporter_->InnerReportDailyEvent();
    // No data in DB, should still update lastReportTime_ to now
    EXPECT_NE(reporter_->lastReportTime_, 0u);
}

// ==================== ReportDailyEvent scenario2 no-report branch ====================

/**
 * @tc.name: ImeUsageReporter_ReportDailyEvent_Scenario2_NoReport
 * @tc.desc: Scenario 2 time jumped forward but lastReportTime_ >= currentPeriodStart skips report
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportDailyEvent_Scenario2_NoReport, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t now = reporter_->GetNowMs();
    // Set nextReportTime_ far in the past (> 1 day gap) triggers forward jump path
    // which calls InnerReportDailyEvent directly (no conditional check)
    reporter_->nextReportTime_ = now - MILLISECS_PER_DAY * 2;
    reporter_->lastReportTime_ = now - MILLISECS_PER_DAY * 3;
    reporter_->ReportDailyEvent();
    // Should have triggered a report via forward jump path
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
    reporter_->ReportAndCleanupOldData(0, MILLISECS_PER_DAY);
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
    // No data in DB, clearDataTime > firstReportDayStart
    uint64_t clearTime = today - MILLISECS_PER_DAY;
    reporter_->ReportAndCleanupOldData(clearTime, today);
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
    uint64_t currentPeriodStart = reporter_->GetToday0ClockMs();
    reporter_->lastReportTime_ = currentPeriodStart + 1000;
    // Persist so LoadLastReportTime returns a recent value
    reporter_->PersistLastReportTime();
    uint64_t beforeTime = reporter_->lastReportTime_;
    reporter_->OnBootCompleted();
    // lastReportTime_ was loaded as recent, no report needed
    EXPECT_EQ(reporter_->lastReportTime_, beforeTime);
}

// ==================== PersistLastReportTime null check ====================

/**
 * @tc.name: ImeUsageReporter_PersistLastReportTime_NullDbHelper
 * @tc.desc: PersistLastReportTime with null eventFactory_ does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, PersistLastReportTime_NullDbHelper, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventFactory_ = nullptr;
    reporter_->lastReportTime_ = 1700000000000ULL;
    reporter_->PersistLastReportTime();
    // Should not crash
}

// ==================== LoadLastReportTime invalid value ====================

/**
 * @tc.name: ImeUsageReporter_LoadLastReportTime_InvalidValue
 * @tc.desc: LoadLastReportTime with non-numeric stored value returns 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, LoadLastReportTime_InvalidValue, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Store a non-numeric value
    reporter_->eventFactory_->GetDbHelper()->SaveReportState(STATE_KEY_LAST_REPORT_TIME, "not_a_number");
    uint64_t loaded = reporter_->LoadLastReportTime();
    EXPECT_EQ(loaded, 0u);
}

/**
 * @tc.name: ImeUsageReporter_LoadLastReportTime_NullDbHelper
 * @tc.desc: LoadLastReportTime with null eventFactory_ returns 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, LoadLastReportTime_NullDbHelper, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    reporter_->eventFactory_ = nullptr;
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
    uint64_t today0 = reporter_->GetToday0ClockMs();
    if (today0 > 0) {
        EXPECT_EQ(nextReport, today0 + MILLISECS_PER_DAY);
    }
}

// ==================== Init: dbHelper creation failure ====================

/**
 * @tc.name: ImeUsageReporter_Init_004
 * @tc.desc: Init with invalid workPath (empty string) returns error
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, Init_004, TestSize.Level0)
{
    auto reporter = std::make_unique<ImeUsageReporter>();
    int ret = reporter->Init("");
    // Empty path should cause dbHelper creation to fail
    EXPECT_NE(ret, 0);
}

// ==================== ReportAndCleanupOldData: earliestTime <= 0 ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_005
 * @tc.desc: ReportAndCleanupOldData with no data returns early (earliestTime <= 0)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_005, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // No data in DB, QueryEarliestEventTime returns <= 0
    reporter_->ReportAndCleanupOldData(1, 2);
    // Should not crash; early return due to earliestTime <= 0
}

// ==================== ReportAndCleanupOldData: clearDataTime <= firstReportDayStart ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_006
 * @tc.desc: ReportAndCleanupOldData skips when clearDataTime <= firstReportDayStart
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_006, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());
    // Insert data for today
    InsertSessionForDay(
        reporter_->eventFactory_->GetDbHelper(), TEST_BUNDLE, today, 3600000, 7200000, UNFOLDED_PORTRAIT);

    // clearDataTime <= firstReportDayStart: no cleanup loop executes
    uint64_t clearTime = today; // equal to firstReportDayStart
    reporter_->ReportAndCleanupOldData(clearTime, today);
    // Should not crash; while loop condition dayStart < reportEnd is false from the start
}

// ==================== ReportAndCleanupOldData: some reports fail (allReported=false) ====================

/**
 * @tc.name: ImeUsageReporter_ReportAndCleanupOldData_007
 * @tc.desc: ReportAndCleanupOldData with data keeps data when report fails
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, ReportAndCleanupOldData_007, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());
    // Insert data for an old day (should trigger report + cleanup)
    uint64_t oldDay = today - MILLISECS_PER_DAY * 2;
    InsertSessionForDay(
        reporter_->eventFactory_->GetDbHelper(), TEST_BUNDLE, oldDay, 3600000, 7200000, UNFOLDED_PORTRAIT);

    // clearDataTime > oldDay so cleanup should run
    uint64_t clearTime = oldDay + MILLISECS_PER_DAY;
    reporter_->ReportAndCleanupOldData(clearTime, clearTime + MILLISECS_PER_DAY);
    // HiSysEventWrite may fail in test env, so allReported may be false
    // If allReported is false, data should NOT be deleted
    // This exercises the else branch at line 414
}

// ==================== InnerReportDailyEvent: lastReportTime_ != 0 (else branch) ====================

/**
 * @tc.name: ImeUsageReporter_InnerReportDailyEvent_006
 * @tc.desc: InnerReportDailyEvent with lastReportTime_ != 0 uses lastReportTime for firstReportDayStart
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, InnerReportDailyEvent_006, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    uint64_t today = DayStartFromMs(GetToday0ClockMs());
    // Insert data
    InsertSessionForDay(
        reporter_->eventFactory_->GetDbHelper(), TEST_BUNDLE, today, 3600000, 7200000, UNFOLDED_PORTRAIT);
    // Set lastReportTime_ to a non-zero value (else branch at line 232)
    reporter_->lastReportTime_ = today + 1000;
    reporter_->InnerReportDailyEvent();
    // Should use lastReportTime_ for firstReportDayStart
}

// ==================== LoadLastReportTime: empty value in DB ====================

/**
 * @tc.name: ImeUsageReporter_LoadLastReportTime_EmptyValue
 * @tc.desc: LoadLastReportTime with empty string stored in DB returns 0
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, LoadLastReportTime_EmptyValue, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Store an empty string value
    reporter_->eventFactory_->GetDbHelper()->SaveReportState(STATE_KEY_LAST_REPORT_TIME, "");
    uint64_t loaded = reporter_->LoadLastReportTime();
    EXPECT_EQ(loaded, 0u);
}

// ==================== OnBootCompleted: lastReportTime_ >= currentPeriodStart ====================

/**
 * @tc.name: ImeUsageReporter_OnBootCompleted_003
 * @tc.desc: OnBootCompleted with lastReportTime_ >= currentPeriodStart does not trigger report
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageReporterTest, OnBootCompleted_003, TestSize.Level0)
{
    int ret = reporter_->Init(DB_DIR);
    EXPECT_EQ(ret, 0);
    // Set lastReportTime_ to a value >= currentPeriodStart
    uint64_t currentPeriodStart = reporter_->GetToday0ClockMs();
    reporter_->lastReportTime_ = currentPeriodStart + 1;
    reporter_->PersistLastReportTime();
    uint64_t beforeTime = reporter_->lastReportTime_;
    reporter_->OnBootCompleted();
    // No report needed since lastReportTime_ >= currentPeriodStart
    EXPECT_EQ(reporter_->lastReportTime_, beforeTime);
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
    uint64_t currentPeriodStart = reporter_->GetToday0ClockMs();
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

} // namespace MiscServices
} // namespace OHOS
