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

// Description: ImeUsageEventFactory unit test
// Create: 2026-08-25

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include "ime_usage_common.h"
#include "ime_usage_db_helper.h"

#define private   public
#define protected public
#include "ime_usage_event_factory.h"
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

const std::string TEST_BUNDLE = "com.test.ime";
const std::string TEST_BUNDLE2 = "com.test.ime2";
const std::string DB_DIR = "/data/test/ime_usage_event_factory_test";
} // namespace

class ImeUsageEventFactoryTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<ImeUsageDbHelper> dbHelper_;
    std::unique_ptr<ImeUsageEventFactory> factory_;
};

void ImeUsageEventFactoryTest::SetUpTestCase(void) { }
void ImeUsageEventFactoryTest::TearDownTestCase(void) { }

void ImeUsageEventFactoryTest::SetUp()
{
    dbHelper_ = std::make_shared<ImeUsageDbHelper>(DB_DIR);
    factory_ = std::make_unique<ImeUsageEventFactory>(dbHelper_);
}

void ImeUsageEventFactoryTest::TearDown()
{
    factory_.reset();
    dbHelper_.reset();
}

// Helper: parameters for InsertSession
// startOffset/stopOffset are millisecond offsets from dayStart
struct SessionParams {
    std::string bundle;
    uint64_t startOffset = 0;
    uint64_t stopOffset = 0;
    int32_t screenStatus = 0;
};

// Helper: insert a complete show->hide session into DB
static void InsertSession(ImeUsageDbHelper &db, uint64_t dayStart, const SessionParams &params)
{
    uint64_t startHappenTime = dayStart + params.startOffset;
    uint64_t stopHappenTime = dayStart + params.stopOffset;

    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = startHappenTime;
    startRec.happenTime = startHappenTime;
    startRec.bundleName = params.bundle;
    startRec.screenStatus = params.screenStatus;
    startRec.preScreenStatus = params.screenStatus;
    db.AddEvent(startRec);

    ImeEventRecord stopRec;
    stopRec.rawid = EVENT_INPUT_STOP;
    stopRec.ts = stopHappenTime;
    stopRec.happenTime = stopHappenTime;
    stopRec.bundleName = params.bundle;
    stopRec.screenStatus = params.screenStatus;
    stopRec.preScreenStatus = params.screenStatus;
    DurationMap durations;
    durations[params.screenStatus] = static_cast<uint64_t>(stopHappenTime - startHappenTime);
    db.AddEvent(stopRec, durations);

    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = stopHappenTime;
    countRec.happenTime = stopHappenTime;
    countRec.bundleName = params.bundle;
    countRec.screenStatus = params.screenStatus;
    countRec.preScreenStatus = params.screenStatus;
    db.AddEvent(countRec, durations);
}

// ==================== Constructor ====================

/**
 * @tc.name: ImeUsageEventFactory_Constructor_001
 * @tc.desc: Constructor with valid dbHelper
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, Constructor_001, TestSize.Level0)
{
    ASSERT_NE(factory_, nullptr);
    // Verify dbHelper_ is stored from constructor argument
    EXPECT_NE(factory_->dbHelper_, nullptr);
    // Verify dbHelper_ is the same instance passed in constructor
    EXPECT_EQ(factory_->dbHelper_, dbHelper_);
    // Verify GetDbHelper returns the same instance
    EXPECT_EQ(factory_->GetDbHelper(), dbHelper_);
    // Verify dbHelper is usable
    EXPECT_TRUE(factory_->dbHelper_->IsReady());
}

/**
 * @tc.name: ImeUsageEventFactory_Constructor_002
 * @tc.desc: Constructor with nullptr dbHelper
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, Constructor_002, TestSize.Level0)
{
    auto f = std::make_unique<ImeUsageEventFactory>(nullptr);
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->dbHelper_, nullptr);
}

// ==================== GetDbHelper ====================

/**
 * @tc.name: ImeUsageEventFactory_GetDbHelper_001
 * @tc.desc: GetDbHelper returns the stored dbHelper
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, GetDbHelper_001, TestSize.Level0)
{
    // GetDbHelper should return the stored dbHelper instance
    auto helper = factory_->GetDbHelper();
    EXPECT_NE(helper, nullptr);
    EXPECT_EQ(helper, dbHelper_);
    // Verify the helper is usable (DB is ready)
    EXPECT_TRUE(helper->IsReady());
    // Verify returned helper matches factory_->dbHelper_ member
    EXPECT_EQ(helper, factory_->dbHelper_);
}

// ==================== Create ====================

/**
 * @tc.name: ImeUsageEventFactory_Create_001
 * @tc.desc: Create with nullptr dbHelper returns empty infos
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, Create_001, TestSize.Level0)
{
    auto f = std::make_unique<ImeUsageEventFactory>(nullptr);
    std::vector<ImeUsageInfo> infos;
    uint64_t dayStart = GetToday0ClockMs();
    f->Create(infos, dayStart, dayStart + MILLISECS_PER_DAY - 1);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: ImeUsageEventFactory_Create_002
 * @tc.desc: Create with empty DB returns empty infos
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, Create_002, TestSize.Level0)
{
    std::vector<ImeUsageInfo> infos;
    uint64_t dayStart = GetToday0ClockMs();
    factory_->Create(infos, dayStart, dayStart + MILLISECS_PER_DAY - 1);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: ImeUsageEventFactory_Create_003
 * @tc.desc: Create with data in DB returns aggregated infos
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, Create_003, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    InsertSession(*dbHelper_, dayStart, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    std::vector<ImeUsageInfo> infos;
    factory_->Create(infos, dayStart, dayStart + MILLISECS_PER_DAY - 1);
    ASSERT_EQ(infos.size(), 1u);
    EXPECT_EQ(infos[0].package, TEST_BUNDLE);
    EXPECT_GT(infos[0].usage, 0u);
}

// ==================== GetUsageInfo ====================

/**
 * @tc.name: ImeUsageEventFactory_GetUsageInfo_001
 * @tc.desc: GetUsageInfo with nullptr dbHelper returns empty
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, GetUsageInfo_001, TestSize.Level0)
{
    auto f = std::make_unique<ImeUsageEventFactory>(nullptr);
    std::vector<ImeUsageInfo> infos;
    f->GetUsageInfo(infos, 0, MILLISECS_PER_DAY);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: ImeUsageEventFactory_GetUsageInfo_002
 * @tc.desc: GetUsageInfo aggregates multiple IMEs correctly
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, GetUsageInfo_002, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    InsertSession(*dbHelper_, dayStart, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });
    InsertSession(*dbHelper_, dayStart, { TEST_BUNDLE2, 10800000, 14400000, EXPAND_PORTRAIT });

    std::vector<ImeUsageInfo> infos;
    factory_->GetUsageInfo(infos, dayStart, dayStart + MILLISECS_PER_DAY - 1);
    EXPECT_GE(infos.size(), 2u);
}

// ==================== MergeForegroundInfo ====================

/**
 * @tc.name: ImeUsageEventFactory_MergeForegroundInfo_001
 * @tc.desc: MergeForegroundInfo with no foreground IME (last event is STOP)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, MergeForegroundInfo_001, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;
    // Insert a complete session (ends with STOP), so last event is COUNT_DURATION or STOP
    InsertSession(*dbHelper_, dayStart, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    factory_->MergeForegroundInfo(statisticInfos, dayStart, dayEnd);
    // No foreground IME at endTime, so statisticInfos should be empty
    EXPECT_TRUE(statisticInfos.empty());
}

/**
 * @tc.name: ImeUsageEventFactory_MergeForegroundInfo_002
 * @tc.desc: MergeForegroundInfo with foreground IME adds foreground duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, MergeForegroundInfo_002, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;

    // Insert START event without matching STOP (IME still showing at day boundary)
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + 7200000;
    startRec.happenTime = dayStart + 7200000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    factory_->MergeForegroundInfo(statisticInfos, dayStart, dayEnd);
    // Should have added foreground duration for TEST_BUNDLE
    EXPECT_FALSE(statisticInfos.empty());
    auto it = statisticInfos.find(TEST_BUNDLE);
    ASSERT_NE(it, statisticInfos.end());
    EXPECT_GT(it->second.usage, 0u);
}

/**
 * @tc.name: ImeUsageEventFactory_MergeForegroundInfo_003
 * @tc.desc: MergeForegroundInfo merges with existing statisticInfos
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, MergeForegroundInfo_003, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;

    // Insert a COUNT_DURATION record (simulating already aggregated data)
    ImeEventRecord countRec;
    countRec.rawid = EVENT_COUNT_DURATION;
    countRec.ts = dayStart + 3600000;
    countRec.happenTime = dayStart + 3600000;
    countRec.bundleName = TEST_BUNDLE;
    countRec.screenStatus = UNFOLDED_PORTRAIT;
    countRec.preScreenStatus = UNFOLDED_PORTRAIT;
    DurationMap durations;
    durations[UNFOLDED_PORTRAIT] = 5000;
    dbHelper_->AddEvent(countRec, durations);

    // Insert START without STOP (foreground IME)
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + 7200000;
    startRec.happenTime = dayStart + 7200000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    // Pre-populate statisticInfos with aggregated data
    ImeUsageInfo existing;
    existing.package = TEST_BUNDLE;
    existing.unFoldedPortraitDuration = 5000;
    existing.showCount = 1;
    existing.usage = existing.GetAppUsage();
    statisticInfos[TEST_BUNDLE] = existing;

    factory_->MergeForegroundInfo(statisticInfos, dayStart, dayEnd);
    auto it = statisticInfos.find(TEST_BUNDLE);
    ASSERT_NE(it, statisticInfos.end());
    // Should have merged: existing 5000 + foreground duration > 5000
    EXPECT_GT(it->second.unFoldedPortraitDuration, 5000u);
}

// ==================== CollectAndSortResults ====================

/**
 * @tc.name: ImeUsageEventFactory_CollectAndSortResults_001
 * @tc.desc: CollectAndSortResults filters zero-usage entries
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, CollectAndSortResults_001, TestSize.Level0)
{
    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    ImeUsageInfo zeroInfo;
    zeroInfo.package = "com.zero.usage";
    zeroInfo.usage = 0;
    statisticInfos["com.zero.usage"] = zeroInfo;

    ImeUsageInfo nonzero;
    nonzero.package = TEST_BUNDLE;
    nonzero.unFoldedPortraitDuration = 1000;
    nonzero.usage = 1000;
    statisticInfos[TEST_BUNDLE] = nonzero;

    std::vector<ImeUsageInfo> infos;
    factory_->CollectAndSortResults(statisticInfos, infos);
    ASSERT_EQ(infos.size(), 1u);
    EXPECT_EQ(infos[0].package, TEST_BUNDLE);
}

/**
 * @tc.name: ImeUsageEventFactory_CollectAndSortResults_002
 * @tc.desc: CollectAndSortResults sorts by usage descending
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, CollectAndSortResults_002, TestSize.Level0)
{
    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    ImeUsageInfo info1;
    info1.package = TEST_BUNDLE;
    info1.unFoldedPortraitDuration = 1000;
    info1.usage = 1000;
    statisticInfos[TEST_BUNDLE] = info1;

    ImeUsageInfo info2;
    info2.package = TEST_BUNDLE2;
    info2.expandPortraitDuration = 5000;
    info2.usage = 5000;
    statisticInfos[TEST_BUNDLE2] = info2;

    std::vector<ImeUsageInfo> infos;
    factory_->CollectAndSortResults(statisticInfos, infos);
    ASSERT_EQ(infos.size(), 2u);
    // First element should have higher usage
    EXPECT_EQ(infos[0].package, TEST_BUNDLE2);
    EXPECT_EQ(infos[1].package, TEST_BUNDLE);
}

/**
 * @tc.name: ImeUsageEventFactory_CollectAndSortResults_003
 * @tc.desc: CollectAndSortResults caps at MAX_IME_USAGE_SIZE(100)
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, CollectAndSortResults_003, TestSize.Level0)
{
    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    // Insert 102 entries
    for (uint32_t i = 0; i < 102; i++) {
        ImeUsageInfo info;
        info.package = "com.ime" + std::to_string(i);
        info.unFoldedPortraitDuration = 1000 + i;
        info.usage = 1000 + i;
        statisticInfos[info.package] = info;
    }

    std::vector<ImeUsageInfo> infos;
    factory_->CollectAndSortResults(statisticInfos, infos);
    EXPECT_EQ(infos.size(), static_cast<size_t>(MAX_IME_USAGE_SIZE));
}

// ==================== CleanupOldData ====================

/**
 * @tc.name: ImeUsageEventFactory_CleanupOldData_001
 * @tc.desc: CleanupOldData with nullptr dbHelper does not crash
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, CleanupOldData_001, TestSize.Level0)
{
    auto f = std::make_unique<ImeUsageEventFactory>(nullptr);
    ASSERT_NE(f, nullptr);
    // CleanupOldData with nullptr dbHelper should return early without crash
    f->CleanupOldData(0);
    // Verify dbHelper_ is still nullptr (unchanged)
    EXPECT_EQ(f->dbHelper_, nullptr);
    // Call again with a different timestamp to confirm no side effects
    f->CleanupOldData(UINT64_MAX);
    EXPECT_EQ(f->dbHelper_, nullptr);
}

/**
 * @tc.name: ImeUsageEventFactory_CleanupOldData_002
 * @tc.desc: CleanupOldData deletes old events from DB
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, CleanupOldData_002, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    InsertSession(*dbHelper_, dayStart, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    // Delete all events (clearDataTime = far future)
    uint64_t clearTime = dayStart + MILLISECS_PER_DAY;
    factory_->CleanupOldData(clearTime);

    // Verify events are deleted
    int idx = dbHelper_->QueryRawEventIndex(TEST_BUNDLE, EVENT_INPUT_START);
    EXPECT_EQ(idx, -1);
}

// ==================== MergeForegroundInfo: EVENT_INPUT_STATUS_CHANGED ====================

/**
 * @tc.name: ImeUsageEventFactory_MergeForegroundInfo_004
 * @tc.desc: MergeForegroundInfo with last event being STATUS_CHANGED adds foreground duration
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, MergeForegroundInfo_004, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;

    // Insert START followed by STATUS_CHANGED (IME still showing at day boundary with status change)
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + 3600000;
    startRec.happenTime = dayStart + 3600000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    ImeEventRecord changedRec;
    changedRec.rawid = EVENT_INPUT_STATUS_CHANGED;
    changedRec.ts = dayStart + 5400000;
    changedRec.happenTime = dayStart + 5400000;
    changedRec.bundleName = TEST_BUNDLE;
    changedRec.screenStatus = EXPAND_PORTRAIT;
    changedRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(changedRec);

    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    factory_->MergeForegroundInfo(statisticInfos, dayStart, dayEnd);
    // Should have added foreground duration for TEST_BUNDLE
    EXPECT_FALSE(statisticInfos.empty());
    auto it = statisticInfos.find(TEST_BUNDLE);
    ASSERT_NE(it, statisticInfos.end());
    EXPECT_GT(it->second.usage, 0u);
    // Should have both UNFOLDED_PORTRAIT and EXPAND_PORTRAIT durations
    EXPECT_GT(it->second.unFoldedPortraitDuration, 0u);
    EXPECT_GT(it->second.expandPortraitDuration, 0u);
}

// ==================== CollectAndSortResults: empty input ====================

/**
 * @tc.name: ImeUsageEventFactory_CollectAndSortResults_004
 * @tc.desc: CollectAndSortResults with empty statisticInfos produces empty output
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, CollectAndSortResults_004, TestSize.Level0)
{
    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    std::vector<ImeUsageInfo> infos;
    factory_->CollectAndSortResults(statisticInfos, infos);
    EXPECT_TRUE(infos.empty());
}

// ==================== GetUsageInfo: full flow with foreground ====================

/**
 * @tc.name: ImeUsageEventFactory_GetUsageInfo_003
 * @tc.desc: GetUsageInfo with foreground IME merges correctly
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, GetUsageInfo_003, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    // Insert a complete session (START + STOP + COUNT_DURATION)
    InsertSession(*dbHelper_, dayStart, { TEST_BUNDLE, 3600000, 7200000, UNFOLDED_PORTRAIT });

    // Insert START without STOP (IME still showing at day boundary)
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + 80000000;
    startRec.happenTime = dayStart + 80000000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = EXPAND_PORTRAIT;
    startRec.preScreenStatus = EXPAND_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    std::vector<ImeUsageInfo> infos;
    factory_->GetUsageInfo(infos, dayStart, dayStart + MILLISECS_PER_DAY - 1);
    ASSERT_EQ(infos.size(), 1u);
    EXPECT_EQ(infos[0].package, TEST_BUNDLE);
    // Should have both aggregated (from COUNT_DURATION) and foreground duration
    EXPECT_GT(infos[0].usage, 0u);
}

// ==================== MergeForegroundInfo: foreground IME not in statisticInfos (else branch) ====================

/**
 * @tc.name: ImeUsageEventFactory_MergeForegroundInfo_005
 * @tc.desc: MergeForegroundInfo adds new entry when foreground IME not already in statisticInfos
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, MergeForegroundInfo_005, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;

    // Insert START event without STOP for TEST_BUNDLE (foreground IME)
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + 7200000;
    startRec.happenTime = dayStart + 7200000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    // Empty statisticInfos - foreground IME not already present, hits else branch
    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    factory_->MergeForegroundInfo(statisticInfos, dayStart, dayEnd);
    // Should have added TEST_BUNDLE as a new entry (else branch of it != statisticInfos.end())
    auto it = statisticInfos.find(TEST_BUNDLE);
    ASSERT_NE(it, statisticInfos.end());
    EXPECT_GT(it->second.usage, 0u);
}

// ==================== Create: with foreground IME that has no prior statistic ====================

/**
 * @tc.name: ImeUsageEventFactory_Create_004
 * @tc.desc: Create with only foreground IME (no COUNT_DURATION records) still reports
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, Create_004, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;

    // Only insert a START event (no STOP/COUNT_DURATION) - foreground IME
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + 3600000;
    startRec.happenTime = dayStart + 3600000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    std::vector<ImeUsageInfo> infos;
    factory_->Create(infos, dayStart, dayEnd);
    // MergeForegroundInfo should add the foreground IME duration
    ASSERT_EQ(infos.size(), 1u);
    EXPECT_EQ(infos[0].package, TEST_BUNDLE);
    EXPECT_GT(infos[0].usage, 0u);
}

// ==================== CollectAndSortResults: exactly MAX_IME_USAGE_SIZE entries ====================

/**
 * @tc.name: ImeUsageEventFactory_CollectAndSortResults_005
 * @tc.desc: CollectAndSortResults with exactly MAX_IME_USAGE_SIZE entries does not cap
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, CollectAndSortResults_005, TestSize.Level0)
{
    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    // Insert exactly MAX_IME_USAGE_SIZE(100) entries
    for (uint32_t i = 0; i < MAX_IME_USAGE_SIZE; i++) {
        ImeUsageInfo info;
        info.package = "com.ime" + std::to_string(i);
        info.unFoldedPortraitDuration = 1000 + i;
        info.usage = 1000 + i;
        statisticInfos[info.package] = info;
    }

    std::vector<ImeUsageInfo> infos;
    factory_->CollectAndSortResults(statisticInfos, infos);
    EXPECT_EQ(infos.size(), static_cast<size_t>(MAX_IME_USAGE_SIZE));
}

// ==================== MergeForegroundInfo: EVENT_INPUT_STATUS_CHANGED as last event ====================

/**
 * @tc.name: ImeUsageEventFactory_MergeForegroundInfo_006
 * @tc.desc: MergeForegroundInfo with STATUS_CHANGED as last event and no prior statistic adds new entry
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, MergeForegroundInfo_006, TestSize.Level0)
{
    uint64_t dayStart = DayStartFromMs(GetToday0ClockMs());
    uint64_t dayEnd = dayStart + MILLISECS_PER_DAY - 1;

    // Insert START then STATUS_CHANGED (no STOP) - IME still foreground
    ImeEventRecord startRec;
    startRec.rawid = EVENT_INPUT_START;
    startRec.ts = dayStart + 3600000;
    startRec.happenTime = dayStart + 3600000;
    startRec.bundleName = TEST_BUNDLE;
    startRec.screenStatus = UNFOLDED_PORTRAIT;
    startRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(startRec);

    ImeEventRecord changedRec;
    changedRec.rawid = EVENT_INPUT_STATUS_CHANGED;
    changedRec.ts = dayStart + 5400000;
    changedRec.happenTime = dayStart + 5400000;
    changedRec.bundleName = TEST_BUNDLE;
    changedRec.screenStatus = EXPAND_PORTRAIT;
    changedRec.preScreenStatus = UNFOLDED_PORTRAIT;
    dbHelper_->AddEvent(changedRec);

    // Empty statisticInfos - hits the else branch for adding new entry
    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    factory_->MergeForegroundInfo(statisticInfos, dayStart, dayEnd);
    auto it = statisticInfos.find(TEST_BUNDLE);
    ASSERT_NE(it, statisticInfos.end());
    EXPECT_GT(it->second.usage, 0u);
    // Should have both UNFOLDED_PORTRAIT and EXPAND_PORTRAIT durations from foreground calculation
    EXPECT_GT(it->second.unFoldedPortraitDuration + it->second.expandPortraitDuration, 0u);
}

// ==================== GetToday0ClockMs ====================

/**
 * @tc.name: ImeUsageEventFactory_GetToday0ClockMs_001
 * @tc.desc: GetToday0ClockMs returns non-zero value
 * @tc.type: FUNC
 */
HWTEST_F(ImeUsageEventFactoryTest, GetToday0ClockMs_001, TestSize.Level0)
{
    uint64_t t = factory_->GetToday0ClockMs();
    EXPECT_GT(t, 0u);
    // Verify result is reasonable: should be less than year 2100 in ms
    EXPECT_LT(t, 4102444800000ULL);
    // Verify it matches global GetToday0ClockMs
    uint64_t globalT = GetToday0ClockMs();
    EXPECT_EQ(t, globalT);
}

} // namespace MiscServices
} // namespace OHOS
