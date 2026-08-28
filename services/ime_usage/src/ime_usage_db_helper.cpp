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

#include "ime_usage_db_helper.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <sys/stat.h>
#include <thread>

#include "global.h"
#include "rdb_helper.h"
#include "values_bucket.h"

using namespace OHOS::MiscServices::ImeUsageTable;
using namespace OHOS::MiscServices::ImeScreenStatus;
using namespace OHOS::MiscServices::ImeUsageEventId;

namespace OHOS {
namespace MiscServices {
namespace {
constexpr int DB_SUCC = 0;
constexpr int DB_FAILED = -1;
constexpr int DB_VERSION = 3;
constexpr int32_t RDB_RETRY_TIMEOUT_MS = 200;
constexpr int32_t RDB_RETRY_COUNT = 5;

// Transient RDB error codes that warrant retry (same set as SMS/MMS)
constexpr int32_t RETRY_ERROR_CODES[] = { 27394108, 27394109, 27394110, 27394112, 27394100, 27394095 };

// Duration columns in DB, mapped to their screen status codes and DurationIndex
struct DurationColumnInfo {
    const char *fieldName;
    int32_t screenStatus;
    size_t index;
};

const std::vector<DurationColumnInfo> DURATION_COLUMNS = {
    {FIELD_UNFOLDED_PORTRAIT_DURATION,   UNFOLDED_PORTRAIT,  IDX_UNFOLDED_PORTRAIT },
    { FIELD_UNFOLDED_LANDSCAPE_DURATION, UNFOLDED_LANDSCAPE, IDX_UNFOLDED_LANDSCAPE},
    { FIELD_FOLD_PORTRAIT_DURATION,      FOLD_PORTRAIT,      IDX_FOLD_PORTRAIT     },
    { FIELD_FOLD_LANDSCAPE_DURATION,     FOLD_LANDSCAPE,     IDX_FOLD_LANDSCAPE    },
    { FIELD_EXPAND_PORTRAIT_DURATION,    EXPAND_PORTRAIT,    IDX_EXPAND_PORTRAIT   },
    { FIELD_EXPAND_LANDSCAPE_DURATION,   EXPAND_LANDSCAPE,   IDX_EXPAND_LANDSCAPE  },
    { FIELD_G_PORTRAIT_DURATION,         G_PORTRAIT,         IDX_G_PORTRAIT        },
    { FIELD_G_LANDSCAPE_DURATION,        G_LANDSCAPE,        IDX_G_LANDSCAPE       },
    { FIELD_N_PORTRAIT_DURATION,         N_PORTRAIT,         IDX_N_PORTRAIT        },
    { FIELD_N_LANDSCAPE_DURATION,        N_LANDSCAPE,        IDX_N_LANDSCAPE       },
    { FIELD_LM_PORTRAIT_DURATION,        LM_PORTRAIT,        IDX_LM_PORTRAIT       },
    { FIELD_LM_LANDSCAPE_DURATION,       LM_LANDSCAPE,       IDX_LM_LANDSCAPE      },
};

struct ForegroundRawEvt {
    int32_t rawId;
    std::string bundle;
    int32_t screenAfter;
    int32_t screenBefore;
    int64_t happenTime;
    int64_t ts;
};

void CollectForegroundEvents(std::shared_ptr<NativeRdb::ResultSet> resultSet, const std::string &targetBundle,
    std::vector<ForegroundRawEvt> &events)
{
    std::string lastBundle;
    while (resultSet->GoToNextRow() == DB_SUCC) {
        ForegroundRawEvt evt;
        resultSet->GetInt(0, evt.rawId);
        std::string bundle;
        resultSet->GetString(1, bundle);
        evt.bundle = bundle;
        resultSet->GetLong(2, evt.ts);
        resultSet->GetLong(3, evt.happenTime);
        resultSet->GetInt(4, evt.screenAfter);
        resultSet->GetInt(5, evt.screenBefore);

        if (lastBundle.empty()) {
            lastBundle = bundle;
        }
        if (bundle != lastBundle) {
            IMSA_HILOGD("CollectForegroundEvents: bundle changed, stop");
            break;
        }
        if (evt.rawId == ImeUsageEventId::EVENT_INPUT_START) {
            events.push_back(evt);
            break;
        }
        if (evt.rawId == ImeUsageEventId::EVENT_INPUT_STATUS_CHANGED) {
            events.push_back(evt);
        }
    }
    resultSet->Close();
}

void CalculateForegroundDuration(const std::vector<ForegroundRawEvt> &events, uint64_t startTime, uint64_t endTime,
    int32_t screenStatus, ImeUsageInfo &info)
{
    if (events.empty()) {
        uint32_t duration = static_cast<uint32_t>(endTime - startTime);
        size_t idx = ScreenStatusToIndex(screenStatus);
        if (idx < DURATION_COUNT) {
            info.durations[idx] += duration;
        }
        return;
    }
    auto &oldest = events.back();
    if (oldest.rawId == ImeUsageEventId::EVENT_INPUT_STATUS_CHANGED) {
        uint32_t duration = static_cast<uint32_t>(oldest.happenTime - startTime);
        size_t idx = ScreenStatusToIndex(oldest.screenBefore);
        if (idx < DURATION_COUNT) {
            info.durations[idx] += duration;
        }
    }
    for (int i = static_cast<int>(events.size()) - 1; i > 0; i--) {
        int64_t tsDelta = events[i - 1].ts - events[i].ts;
        int64_t htDelta = events[i - 1].happenTime - events[i].happenTime;
        constexpr int64_t DIVERGENCE_THRESHOLD_MS = 30000; // 30 seconds
        if (tsDelta > 0 && htDelta > 0 && std::abs(tsDelta - htDelta) > DIVERGENCE_THRESHOLD_MS) {
            IMSA_HILOGW("CalculateForegroundDuration: ts/happenTime divergence at idx=%{public}d, "
                        "tsDelta=%{public}lld, htDelta=%{public}lld",
                i, static_cast<long long>(tsDelta), static_cast<long long>(htDelta));
        }
        uint32_t duration =
            (events[i - 1].ts > events[i].ts) ? static_cast<uint32_t>(events[i - 1].ts - events[i].ts) : 0;
        size_t idx = ScreenStatusToIndex(events[i].screenAfter);
        if (idx < DURATION_COUNT) {
            info.durations[idx] += duration;
        }
    }
    auto &newest = events[0];
    uint32_t duration =
        (static_cast<uint64_t>(newest.happenTime) < endTime) ? static_cast<uint32_t>(endTime - newest.happenTime) : 0;
    size_t idx = ScreenStatusToIndex(newest.screenAfter);
    if (idx < DURATION_COUNT) {
        info.durations[idx] += duration;
    }
}

class ImeUsageDbOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override
    {
        return DB_SUCC;
    }
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        // This feature has not yet shipped, so no production V1/V2 databases exist.
        // The upgrade path is retained for forward compatibility: if a future
        // schema change bumps DB_VERSION again, add a new `if (oldVersion < N)` block.
        if (oldVersion < 3) {
            // Re-create events table (drops any stale schema) and add report state table
            rdbStore.ExecuteSql("DROP TABLE IF EXISTS ime_usage_events");
            rdbStore.ExecuteSql("CREATE TABLE IF NOT EXISTS ime_usage_report_state ("
                                "key TEXT PRIMARY KEY, value TEXT NOT NULL)");
        }
        return DB_SUCC;
    }
};
} // namespace

ImeUsageDbHelper::ImeUsageDbHelper(const std::string &workPath) : dbPath_(workPath)
{
    CreateDbStore(dbPath_);
}

bool ImeUsageDbHelper::IsReady() const
{
    return rdbStore_ != nullptr;
}

bool ImeUsageDbHelper::EnsureDirectoryExist(const std::string &path)
{
    if (path.empty()) {
        IMSA_HILOGE("EnsureDirectoryExist: path is empty");
        return false;
    }
    if (access(path.c_str(), F_OK) == 0) {
        return true;
    }
    // Recursively create parent directories
    size_t pos = 0;
    while ((pos = path.find('/', pos + 1)) != std::string::npos) {
        std::string subPath = path.substr(0, pos);
        if (access(subPath.c_str(), F_OK) != 0) {
            if (mkdir(subPath.c_str(), S_IRWXU | S_IRWXG) != 0 && errno != EEXIST) {
                IMSA_HILOGE("EnsureDirectoryExist: mkdir %{public}s failed, errno=%{public}d", subPath.c_str(), errno);
                return false;
            }
        }
    }
    // Create the final directory
    if (mkdir(path.c_str(), S_IRWXU | S_IRWXG) != 0 && errno != EEXIST) {
        IMSA_HILOGE("EnsureDirectoryExist: mkdir %{public}s failed, errno=%{public}d", path.c_str(), errno);
        return false;
    }
    IMSA_HILOGD("EnsureDirectoryExist: created %{public}s", path.c_str());
    return true;
}

bool ImeUsageDbHelper::CreateDbStore(const std::string &dbPath)
{
    IMSA_HILOGD("CreateDbStore: dbPath=%{public}s", dbPath.c_str());

    // Use direct path pattern (same as Time Service, Certificate Manager):
    // build the full db file path ourselves, ensure directory exists,
    // then pass it directly to RdbStoreConfig without SetBundleName/SetArea.
    std::string dbFile = dbPath;
    if (!dbFile.empty() && dbFile.back() == '/') {
        dbFile.pop_back();
    }
    dbFile += "/" + std::string(IME_USAGE_DB_NAME);
    IMSA_HILOGD("CreateDbStore: dbFile=%{public}s", dbFile.c_str());

    std::string dbDir = dbFile.substr(0, dbFile.rfind('/'));
    if (!EnsureDirectoryExist(dbDir)) {
        IMSA_HILOGE("CreateDbStore: failed to ensure directory %{public}s", dbDir.c_str());
        return false;
    }

    NativeRdb::RdbStoreConfig config(dbFile);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    config.SetAllowRebuild(true);
    config.SetReadConSize(0);

    ImeUsageDbOpenCallback callback;
    int errCode = DB_SUCC;
    rdbStore_ = GetRdbStoreWithRetry(config, DB_VERSION, callback, errCode);
    if (rdbStore_ == nullptr || errCode != DB_SUCC) {
        IMSA_HILOGE("CreateDbStore: GetRdbStore failed after retries, dbFile=%{public}s, err=%{public}d",
            dbFile.c_str(), errCode);
        return false;
    }

    IMSA_HILOGD("RdbStore created successfully");

    // Create tables first — on a fresh install the tables do not exist yet,
    // so any verification must happen AFTER this step.
    errCode = CreateImeUsageTable();
    if (errCode != DB_SUCC) {
        IMSA_HILOGE("Failed to create table, err=%{public}d", errCode);
        return false;
    }
    errCode = CreateReportStateTable();
    if (errCode != DB_SUCC) {
        IMSA_HILOGE("Failed to create report state table, err=%{public}d", errCode);
        return false;
    }

    return VerifyAndRecoverStore(dbFile, config, errCode);
}

bool ImeUsageDbHelper::VerifyAndRecoverStore(const std::string &dbFile, NativeRdb::RdbStoreConfig &config, int &errCode)
{
    auto checkRs = rdbStore_->QuerySql("SELECT COUNT(*) FROM " + std::string(IME_USAGE_DB_TABLE));
    int checkCount = -1;
    if (checkRs != nullptr && checkRs->GoToNextRow() == DB_SUCC) {
        checkRs->GetInt(0, checkCount);
    }
    if (checkRs != nullptr) {
        checkRs->Close();
    }
    IMSA_HILOGD("VerifyAndRecoverStore: COUNT(*)=%{public}d", checkCount);
    if (checkCount < 0) {
        IMSA_HILOGW("VerifyAndRecoverStore: store broken, deleting and recreating");
        rdbStore_ = nullptr;
        int delRet = NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
        IMSA_HILOGD("VerifyAndRecoverStore: DeleteRdbStore ret=%{public}d", delRet);
        ImeUsageDbOpenCallback callback;
        rdbStore_ = GetRdbStoreWithRetry(config, DB_VERSION, callback, errCode);
        if (rdbStore_ == nullptr || errCode != DB_SUCC) {
            IMSA_HILOGE("VerifyAndRecoverStore: retry GetRdbStore failed, err=%{public}d", errCode);
            return false;
        }
        int tableRet = CreateImeUsageTable();
        if (tableRet != DB_SUCC) {
            IMSA_HILOGE("VerifyAndRecoverStore: CreateImeUsageTable failed after recovery, ret=%{public}d", tableRet);
            return false;
        }
        tableRet = CreateReportStateTable();
        if (tableRet != DB_SUCC) {
            IMSA_HILOGE("VerifyAndRecoverStore: CreateReportStateTable failed "
                        "after recovery, ret=%{public}d",
                tableRet);
            return false;
        }
    }
    return true;
}

std::shared_ptr<NativeRdb::RdbStore> ImeUsageDbHelper::GetRdbStoreWithRetry(
    NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &callback, int &errCode)
{
    errCode = NativeRdb::E_ERROR;
    auto store = NativeRdb::RdbHelper::GetRdbStore(config, version, callback, errCode);
    if (errCode == NativeRdb::E_OK && store != nullptr) {
        return store;
    }
    // Retry only for transient I/O errors (same set as SMS/MMS)
    for (int retryCount = 1; retryCount <= RDB_RETRY_COUNT; retryCount++) {
        if (std::find(std::begin(RETRY_ERROR_CODES), std::end(RETRY_ERROR_CODES), errCode) ==
            std::end(RETRY_ERROR_CODES)) {
            break;
        }
        IMSA_HILOGW("GetRdbStoreWithRetry: errCode=%{public}d, retry #%{public}d", errCode, retryCount);
        std::this_thread::sleep_for(std::chrono::milliseconds(RDB_RETRY_TIMEOUT_MS));
        errCode = NativeRdb::E_ERROR;
        store = NativeRdb::RdbHelper::GetRdbStore(config, version, callback, errCode);
        if (errCode == NativeRdb::E_OK && store != nullptr) {
            return store;
        }
    }
    return store;
}

int ImeUsageDbHelper::CreateImeUsageTable()
{
    std::string sql = "CREATE TABLE IF NOT EXISTS " + std::string(IME_USAGE_DB_TABLE) + " (" + std::string(FIELD_ID) +
        " INTEGER PRIMARY KEY AUTOINCREMENT, " + std::string(FIELD_RAWID) + " INTEGER NOT NULL, " +
        std::string(FIELD_TS) + " INTEGER NOT NULL, " + std::string(FIELD_FOLD_STATUS) + " INTEGER, " +
        std::string(FIELD_PRE_FOLD_STATUS) + " INTEGER, " + std::string(FIELD_BUNDLE_NAME) + " TEXT NOT NULL, " +
        std::string(FIELD_HAPPEN_TIME) + " INTEGER, ";
    for (size_t i = 0; i < DURATION_COLUMNS.size(); i++) {
        sql += std::string(DURATION_COLUMNS[i].fieldName) + " INTEGER DEFAULT 0";
        if (i + 1 < DURATION_COLUMNS.size()) {
            sql += ", ";
        }
    }
    sql += ");";
    int ret = rdbStore_->ExecuteSql(sql);
    if (ret != DB_SUCC) {
        IMSA_HILOGE("ExecuteSql failed, ret=%{public}d", ret);
        return DB_FAILED;
    }
    // Create indexes for common query patterns
    rdbStore_->ExecuteSql(
        "CREATE INDEX IF NOT EXISTS idx_bundle_rawid ON " + std::string(IME_USAGE_DB_TABLE) + "(bundle_name, rawid)");
    rdbStore_->ExecuteSql(
        "CREATE INDEX IF NOT EXISTS idx_happen_time ON " + std::string(IME_USAGE_DB_TABLE) + "(happen_time)");
    return DB_SUCC;
}

int ImeUsageDbHelper::CreateReportStateTable()
{
    std::string sql = "CREATE TABLE IF NOT EXISTS " + std::string(IME_USAGE_STATE_TABLE) +
        " (key TEXT PRIMARY KEY, value TEXT NOT NULL)";
    int ret = rdbStore_->ExecuteSql(sql);
    if (ret != DB_SUCC) {
        IMSA_HILOGE("CreateReportStateTable failed, ret=%{public}d", ret);
        return DB_FAILED;
    }
    return DB_SUCC;
}

int ImeUsageDbHelper::AddEvent(const ImeEventRecord &record, const DurationMap &durations)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        IMSA_HILOGE("rdbStore_ is nullptr");
        return DB_FAILED;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(FIELD_RAWID, record.rawid);
    values.PutLong(FIELD_TS, record.ts);
    values.PutInt(FIELD_FOLD_STATUS, record.screenStatus);
    values.PutInt(FIELD_PRE_FOLD_STATUS, record.preScreenStatus);
    values.PutString(FIELD_BUNDLE_NAME, record.bundleName);
    values.PutLong(FIELD_HAPPEN_TIME, record.happenTime);

    for (const auto &col : DURATION_COLUMNS) {
        auto it = durations.find(col.screenStatus);
        if (it != durations.end()) {
            values.PutLong(col.fieldName, static_cast<int64_t>(it->second));
        } else {
            values.PutLong(col.fieldName, 0);
        }
    }

    int64_t rowId = -1;
    int ret = rdbStore_->Insert(rowId, IME_USAGE_DB_TABLE, values);
    if (ret != DB_SUCC) {
        IMSA_HILOGE("Insert failed, ret=%{public}d, rawId=%{public}d, bundle=%{public}s", ret, record.rawid,
            record.bundleName.c_str());
        return DB_FAILED;
    }

    IMSA_HILOGD("AddEvent: rowId=%{public}lld, rawId=%{public}d, bundle=%{public}s, "
                "screenStatus=%{public}d, happenTime=%{public}lld, durationCount=%{public}zu",
        static_cast<long long>(rowId), record.rawid, record.bundleName.c_str(), record.screenStatus,
        static_cast<long long>(record.happenTime), durations.size());

    return DB_SUCC;
}

int ImeUsageDbHelper::AddEventsTransactional(const std::vector<std::pair<ImeEventRecord, DurationMap>> &events)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        IMSA_HILOGE("AddEventsTransactional: rdbStore_ is nullptr");
        return DB_FAILED;
    }
    if (events.empty()) {
        return DB_SUCC;
    }

    int ret = rdbStore_->BeginTransaction();
    if (ret != DB_SUCC) {
        IMSA_HILOGE("AddEventsTransactional: BeginTransaction failed, ret=%{public}d", ret);
        return DB_FAILED;
    }

    for (const auto &[record, durations] : events) {
        NativeRdb::ValuesBucket values;
        values.PutInt(FIELD_RAWID, record.rawid);
        values.PutLong(FIELD_TS, record.ts);
        values.PutInt(FIELD_FOLD_STATUS, record.screenStatus);
        values.PutInt(FIELD_PRE_FOLD_STATUS, record.preScreenStatus);
        values.PutString(FIELD_BUNDLE_NAME, record.bundleName);
        values.PutLong(FIELD_HAPPEN_TIME, record.happenTime);

        for (const auto &col : DURATION_COLUMNS) {
            auto it = durations.find(col.screenStatus);
            if (it != durations.end()) {
                values.PutLong(col.fieldName, static_cast<int64_t>(it->second));
            } else {
                values.PutLong(col.fieldName, 0);
            }
        }

        int64_t rowId = -1;
        ret = rdbStore_->Insert(rowId, IME_USAGE_DB_TABLE, values);
        if (ret != DB_SUCC) {
            IMSA_HILOGE("AddEventsTransactional: Insert failed, ret=%{public}d, rawId=%{public}d, bundle=%{public}s",
                ret, record.rawid, record.bundleName.c_str());
            rdbStore_->RollBack();
            return DB_FAILED;
        }
    }

    ret = rdbStore_->Commit();
    if (ret != DB_SUCC) {
        IMSA_HILOGE("AddEventsTransactional: Commit failed, ret=%{public}d", ret);
        rdbStore_->RollBack();
        return DB_FAILED;
    }

    IMSA_HILOGD("AddEventsTransactional: committed %{public}zu events", events.size());
    return DB_SUCC;
}

int ImeUsageDbHelper::QueryRawEventIndex(const std::string &bundleName, int32_t rawId)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        return -1;
    }
    std::string sql = "SELECT id FROM " + std::string(IME_USAGE_DB_TABLE) +
        " WHERE bundle_name = ? AND rawid = ? ORDER BY id DESC LIMIT 1";
    auto resultSet = rdbStore_->QuerySql(sql, std::vector<std::string> { bundleName, std::to_string(rawId) });
    if (resultSet == nullptr) {
        IMSA_HILOGD(
            "QueryRawEventIndex: resultSet is null, bundle=%{public}s, rawId=%{public}d", bundleName.c_str(), rawId);
        return -1;
    }
    int32_t id = -1;
    if (resultSet->GoToNextRow() == DB_SUCC) {
        resultSet->GetInt(0, id);
    }
    resultSet->Close();
    IMSA_HILOGD(
        "QueryRawEventIndex: bundle=%{public}s, rawId=%{public}d, foundId=%{public}d", bundleName.c_str(), rawId, id);
    return id;
}

void ImeUsageDbHelper::QueryEventRecords(
    int32_t startIndex, int64_t dayStartTime, const std::string &bundleName, std::vector<ImeEventRecord> &records)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        return;
    }
    std::string sql = "SELECT id, rawid, ts, happen_time, bundle_name, fold_status, "
                      "pre_fold_status FROM " +
        std::string(IME_USAGE_DB_TABLE) + " WHERE bundle_name = ? AND id >= ? AND happen_time >= ? ORDER BY id ASC";
    auto resultSet = rdbStore_->QuerySql(
        sql, std::vector<std::string> { bundleName, std::to_string(startIndex), std::to_string(dayStartTime) });
    if (resultSet == nullptr) {
        IMSA_HILOGW("QueryEventRecords: resultSet is null, bundle=%{public}s", bundleName.c_str());
        return;
    }
    int checkpointCount = 0;
    while (resultSet->GoToNextRow() == DB_SUCC) {
        ImeEventRecord record;
        int32_t tmpId = 0;
        resultSet->GetInt(0, tmpId);
        resultSet->GetInt(1, record.rawid);
        resultSet->GetLong(2, record.ts);
        resultSet->GetLong(3, record.happenTime);
        std::string bundle;
        resultSet->GetString(4, bundle);
        record.bundleName = bundle;
        resultSet->GetInt(5, record.screenStatus);
        resultSet->GetInt(6, record.preScreenStatus);

        if (record.rawid == ImeUsageEventId::EVENT_COUNT_DURATION) {
            checkpointCount++;
            if (!records.empty()) {
                IMSA_HILOGW("QueryEventRecords: COUNT_DURATION encountered with %{public}zu "
                            "unprocessed records, discarding (bundle=%{public}s)",
                    records.size(), record.bundleName.c_str());
            }
            records.clear();
            continue;
        }
        records.push_back(record);
    }
    resultSet->Close();
    IMSA_HILOGD("QueryEventRecords: bundle=%{public}s, startIndex=%{public}d, "
                "dayStartTime=%{public}lld, resultCount=%{public}zu, checkpoints=%{public}d",
        bundleName.c_str(), startIndex, static_cast<long long>(dayStartTime), records.size(), checkpointCount);
}

void ImeUsageDbHelper::QueryStatisticEventsInPeriod(
    uint64_t startTime, uint64_t endTime, std::unordered_map<std::string, ImeUsageInfo> &infos)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        return;
    }
    IMSA_HILOGD("QueryStatisticEventsInPeriod: startTime=%{public}llu, endTime=%{public}llu",
        static_cast<unsigned long long>(startTime), static_cast<unsigned long long>(endTime));

    std::string sql = "SELECT bundle_name";
    for (const auto &col : DURATION_COLUMNS) {
        sql += ", SUM(" + std::string(col.fieldName) + ")";
    }
    sql += ", SUM(CASE WHEN rawid = ? THEN 1 ELSE 0 END) FROM " + std::string(IME_USAGE_DB_TABLE) +
        " WHERE happen_time >= ? AND happen_time <= ?"
        " GROUP BY bundle_name";
    auto resultSet = rdbStore_->QuerySql(sql,
        std::vector<std::string> { std::to_string(ImeUsageEventId::EVENT_INPUT_START),
            std::to_string(static_cast<int64_t>(startTime)), std::to_string(static_cast<int64_t>(endTime)) });
    if (resultSet == nullptr) {
        return;
    }
    while (resultSet->GoToNextRow() == DB_SUCC) {
        ImeUsageInfo info;
        std::string bundle;
        resultSet->GetString(0, bundle);
        info.package = bundle;

        int colIdx = 1;
        for (const auto &dc : DURATION_COLUMNS) {
            int64_t val = 0;
            resultSet->GetLong(colIdx, val);
            info.durations[dc.index] += static_cast<uint32_t>(std::max<int64_t>(0, val));
            colIdx++;
        }
        int64_t startNum = 0;
        resultSet->GetLong(colIdx, startNum);
        info.showCount = static_cast<uint32_t>(std::max<int64_t>(0, startNum));
        info.usage = info.GetAppUsage();

        infos[bundle] = info;
    }
    resultSet->Close();
    IMSA_HILOGD("QueryStatisticEventsInPeriod: found %{public}zu IME groups", infos.size());
}

void ImeUsageDbHelper::QueryFinalEventInfo(uint64_t endTime, ImeUsageRawEvent &event)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        return;
    }
    std::string sql = "SELECT id, rawid, bundle_name, ts, happen_time, fold_status, "
                      "pre_fold_status FROM " +
        std::string(IME_USAGE_DB_TABLE) + " WHERE happen_time <= ? ORDER BY id DESC LIMIT 1";
    auto resultSet =
        rdbStore_->QuerySql(sql, std::vector<std::string> { std::to_string(static_cast<int64_t>(endTime)) });
    if (resultSet == nullptr) {
        IMSA_HILOGD("QueryFinalEventInfo: resultSet is null");
        return;
    }
    if (resultSet->GoToNextRow() == DB_SUCC) {
        resultSet->GetLong(0, event.id);
        resultSet->GetInt(1, event.rawId);
        std::string bundle;
        resultSet->GetString(2, bundle);
        event.package = bundle;
        resultSet->GetLong(3, event.ts);
        resultSet->GetLong(4, event.happenTime);
        resultSet->GetInt(5, event.screenStatusAfter);
        resultSet->GetInt(6, event.screenStatusBefore);
        IMSA_HILOGD("QueryFinalEventInfo: id=%{public}lld, rawId=%{public}d, "
                    "pkg=%{public}s, screenAfter=%{public}d, screenBefore=%{public}d",
            static_cast<long long>(event.id), event.rawId, event.package.c_str(), event.screenStatusAfter,
            event.screenStatusBefore);
    } else {
        IMSA_HILOGD("QueryFinalEventInfo: no events found before endTime=%{public}llu",
            static_cast<unsigned long long>(endTime));
    }
    resultSet->Close();
}

void ImeUsageDbHelper::QueryForegroundImeInfo(
    uint64_t startTime, uint64_t endTime, int32_t screenStatus, ImeUsageInfo &info)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        return;
    }
    IMSA_HILOGD("QueryForegroundImeInfo: startTime=%{public}llu, endTime=%{public}llu, "
                "screenStatus=%{public}d, pkg=%{public}s",
        static_cast<unsigned long long>(startTime), static_cast<unsigned long long>(endTime), screenStatus,
        info.package.c_str());
    std::string sql = "SELECT rawid, bundle_name, ts, happen_time, fold_status, "
                      "pre_fold_status FROM " +
        std::string(IME_USAGE_DB_TABLE) +
        " WHERE bundle_name = ? AND happen_time >= ? AND happen_time <= ? ORDER BY id DESC";
    auto resultSet = rdbStore_->QuerySql(sql,
        std::vector<std::string> { info.package, std::to_string(static_cast<int64_t>(startTime)),
            std::to_string(static_cast<int64_t>(endTime)) });
    if (resultSet == nullptr) {
        IMSA_HILOGW("QueryForegroundImeInfo: resultSet is null");
        return;
    }

    std::vector<ForegroundRawEvt> events;
    CollectForegroundEvents(resultSet, info.package, events);
    IMSA_HILOGD("QueryForegroundImeInfo: collected %{public}zu events", events.size());
    CalculateForegroundDuration(events, startTime, endTime, screenStatus, info);
}

int ImeUsageDbHelper::DeleteEventsByTime(uint64_t clearDataTime)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        return DB_FAILED;
    }
    std::string sql = "DELETE FROM " + std::string(IME_USAGE_DB_TABLE) + " WHERE happen_time < ?";
    std::vector<NativeRdb::ValueObject> args = { NativeRdb::ValueObject(
        std::to_string(static_cast<int64_t>(clearDataTime))) };
    int ret = rdbStore_->ExecuteSql(sql, args);
    if (ret != DB_SUCC) {
        IMSA_HILOGE("Delete failed, ret=%{public}d", ret);
        return DB_FAILED;
    }
    IMSA_HILOGD("Deleted rows older than %{public}llu", static_cast<unsigned long long>(clearDataTime));
    return DB_SUCC;
}

int ImeUsageDbHelper::SaveReportState(const std::string &key, const std::string &value)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        return DB_FAILED;
    }
    // INSERT OR REPLACE: update if key exists, insert otherwise
    NativeRdb::ValuesBucket values;
    values.PutString("key", key);
    values.PutString("value", value);
    int64_t rowId = -1;
    int ret = rdbStore_->InsertWithConflictResolution(
        rowId, IME_USAGE_STATE_TABLE, values, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    if (ret != DB_SUCC) {
        IMSA_HILOGE("SaveReportState failed, key=%{public}s, ret=%{public}d", key.c_str(), ret);
        return DB_FAILED;
    }
    IMSA_HILOGD("SaveReportState: key=%{public}s, value=%{public}s", key.c_str(), value.c_str());
    return DB_SUCC;
}

int ImeUsageDbHelper::LoadReportState(const std::string &key, std::string &value)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        return DB_FAILED;
    }
    value.clear();
    std::string sql = "SELECT value FROM " + std::string(IME_USAGE_STATE_TABLE) + " WHERE key = ?";
    auto resultSet = rdbStore_->QuerySql(sql, std::vector<std::string> { key });
    if (resultSet == nullptr) {
        IMSA_HILOGD("LoadReportState: no result for key=%{public}s", key.c_str());
        return DB_FAILED;
    }
    if (resultSet->GoToNextRow() == DB_SUCC) {
        resultSet->GetString(0, value);
    }
    resultSet->Close();
    if (value.empty()) {
        IMSA_HILOGD("LoadReportState: key=%{public}s not found", key.c_str());
        return DB_FAILED;
    }
    IMSA_HILOGD("LoadReportState: key=%{public}s, value=%{public}s", key.c_str(), value.c_str());
    return DB_SUCC;
}

int64_t ImeUsageDbHelper::QueryEarliestEventTime()
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    if (rdbStore_ == nullptr) {
        return -1;
    }
    std::string sql = "SELECT MIN(happen_time) FROM " + std::string(IME_USAGE_DB_TABLE);
    auto resultSet = rdbStore_->QuerySql(sql);
    if (resultSet == nullptr) {
        return -1;
    }
    int64_t earliestTime = -1;
    if (resultSet->GoToNextRow() == DB_SUCC) {
        resultSet->GetLong(0, earliestTime);
    }
    resultSet->Close();
    IMSA_HILOGD("QueryEarliestEventTime: %{public}lld", static_cast<long long>(earliestTime));
    return earliestTime;
}

std::vector<uint64_t> ImeUsageDbHelper::QueryActiveDays(uint64_t startTime, uint64_t endTime)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    std::vector<uint64_t> days;
    if (rdbStore_ == nullptr) {
        return days;
    }
    // Group happen_time by day, return distinct day-start timestamps
    // SQLite: happen_time is in milliseconds, MILLISECS_PER_DAY = 86400000
    std::string sql = "SELECT DISTINCT (happen_time / " + std::to_string(MILLISECS_PER_DAY) + ") * " +
        std::to_string(MILLISECS_PER_DAY) + " FROM " + std::string(IME_USAGE_DB_TABLE) +
        " WHERE happen_time >= ? AND happen_time <= ? ORDER BY 1 ASC";
    auto resultSet = rdbStore_->QuerySql(sql,
        std::vector<std::string> {
            std::to_string(static_cast<int64_t>(startTime)), std::to_string(static_cast<int64_t>(endTime)) });
    if (resultSet == nullptr) {
        return days;
    }
    while (resultSet->GoToNextRow() == DB_SUCC) {
        int64_t dayStart = 0;
        if (resultSet->GetLong(0, dayStart) == DB_SUCC && dayStart >= 0) {
            days.push_back(static_cast<uint64_t>(dayStart));
        }
    }
    resultSet->Close();
    IMSA_HILOGD("QueryActiveDays: found %{public}zu days in [%{public}llu, %{public}llu]", days.size(),
        static_cast<unsigned long long>(startTime), static_cast<unsigned long long>(endTime));
    return days;
}

} // namespace MiscServices
} // namespace OHOS
