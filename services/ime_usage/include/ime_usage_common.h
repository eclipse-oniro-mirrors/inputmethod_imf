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

#ifndef SERVICES_IME_USAGE_INCLUDE_IME_USAGE_COMMON_H
#define SERVICES_IME_USAGE_INCLUDE_IME_USAGE_COMMON_H

#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <map>
#include <string>

namespace OHOS {
namespace MiscServices {

// Event IDs for IME usage tracking
namespace ImeUsageEventId {
inline constexpr int32_t EVENT_INPUT_START = 1001;
inline constexpr int32_t EVENT_INPUT_STOP = 1002;
inline constexpr int32_t EVENT_INPUT_STATUS_CHANGED = 1003;
inline constexpr int32_t EVENT_COUNT_DURATION = 1004;
} // namespace ImeUsageEventId

// Screen status base values (directly mapped from FoldDisplayMode)
namespace ImeFoldStatusBase {
inline constexpr int8_t UNFOLDED = 1; // 非折叠机
inline constexpr int8_t FOLD = 2;     // F态 (MAIN)
inline constexpr int8_t EXPAND = 3;   // M态 (FULL/COORDINATION)
inline constexpr int8_t G = 4;        // G态 (GLOBAL_FULL)
inline constexpr int8_t N = 5;        // N态 (N_MAIN)
inline constexpr int8_t LM = 6;       // LM态 (L_FULL)
inline constexpr int8_t LANDSCAPE = 1;
inline constexpr int8_t PORTRAIT = 2;
// Range bounds derived from the enum values above
inline constexpr int8_t FOLD_STATUS_MIN = UNFOLDED;
inline constexpr int8_t FOLD_STATUS_MAX = LM;
inline constexpr int8_t VH_MODE_MIN = LANDSCAPE;
inline constexpr int8_t VH_MODE_MAX = PORTRAIT;
inline constexpr int8_t VH_MODE_COUNT = VH_MODE_MAX - VH_MODE_MIN + 1;
} // namespace ImeFoldStatusBase

// Encoding base for screenStatus: screenStatus = foldStatus * ENCODE_BASE + vhMode
inline constexpr int32_t SCREEN_STATUS_ENCODE_BASE = 10;

// Screen status encoding: screenStatus = foldStatus * 10 + vhMode
//
// foldStatus (derived from FoldDisplayMode):
//   1 = UNFOLDED  (non-foldable device)
//   2 = FOLD      (F态, MAIN)
//   3 = EXPAND    (M态, FULL/COORDINATION)
//   4 = G         (G态, GLOBAL_FULL)
//   5 = N         (N态, N_MAIN)
//   6 = LM        (LM态, L_FULL)
//
// vhMode (screen orientation):
//   1 = LANDSCAPE
//   2 = PORTRAIT
//
// Combined examples:
//   12 = UNFOLDED+PORTRAIT    (non-foldable, portrait)
//   22 = FOLD+PORTRAIT        (folded, portrait)
//   32 = EXPAND+PORTRAIT      (expanded, portrait)
//   11 = UNFOLDED+LANDSCAPE   (non-foldable, landscape)
//   42 = G+PORTRAIT           (G-mode, portrait)
//   52 = N+PORTRAIT           (N-mode, portrait)
//   62 = LM+PORTRAIT          (LM-mode, portrait)
namespace ImeScreenStatus {
using namespace ImeFoldStatusBase;
inline constexpr int UNFOLDED_LANDSCAPE = UNFOLDED * SCREEN_STATUS_ENCODE_BASE + LANDSCAPE;
inline constexpr int UNFOLDED_PORTRAIT = UNFOLDED * SCREEN_STATUS_ENCODE_BASE + PORTRAIT;
inline constexpr int FOLD_LANDSCAPE = FOLD * SCREEN_STATUS_ENCODE_BASE + LANDSCAPE;
inline constexpr int FOLD_PORTRAIT = FOLD * SCREEN_STATUS_ENCODE_BASE + PORTRAIT;
inline constexpr int EXPAND_LANDSCAPE = EXPAND * SCREEN_STATUS_ENCODE_BASE + LANDSCAPE;
inline constexpr int EXPAND_PORTRAIT = EXPAND * SCREEN_STATUS_ENCODE_BASE + PORTRAIT;
inline constexpr int G_LANDSCAPE = G * SCREEN_STATUS_ENCODE_BASE + LANDSCAPE;
inline constexpr int G_PORTRAIT = G * SCREEN_STATUS_ENCODE_BASE + PORTRAIT;
inline constexpr int N_LANDSCAPE = N * SCREEN_STATUS_ENCODE_BASE + LANDSCAPE;
inline constexpr int N_PORTRAIT = N * SCREEN_STATUS_ENCODE_BASE + PORTRAIT;
inline constexpr int LM_LANDSCAPE = LM * SCREEN_STATUS_ENCODE_BASE + LANDSCAPE;
inline constexpr int LM_PORTRAIT = LM * SCREEN_STATUS_ENCODE_BASE + PORTRAIT;
} // namespace ImeScreenStatus

// Index into the durations array in ImeUsageInfo.
// Order matches DURATION_COLUMNS in ime_usage_db_helper.cpp.
enum DurationIndex : size_t {
    IDX_UNFOLDED_LANDSCAPE = 0, // foldStatus=1, vhMode=1
    IDX_UNFOLDED_PORTRAIT = 1,  // foldStatus=1, vhMode=2
    IDX_FOLD_LANDSCAPE = 2,     // foldStatus=2, vhMode=1
    IDX_FOLD_PORTRAIT = 3,      // foldStatus=2, vhMode=2
    IDX_EXPAND_LANDSCAPE = 4,   // foldStatus=3, vhMode=1
    IDX_EXPAND_PORTRAIT = 5,    // foldStatus=3, vhMode=2
    IDX_G_LANDSCAPE = 6,        // foldStatus=4, vhMode=1
    IDX_G_PORTRAIT = 7,         // foldStatus=4, vhMode=2
    IDX_N_LANDSCAPE = 8,        // foldStatus=5, vhMode=1
    IDX_N_PORTRAIT = 9,         // foldStatus=5, vhMode=2
    IDX_LM_LANDSCAPE = 10,      // foldStatus=6, vhMode=1
    IDX_LM_PORTRAIT = 11,       // foldStatus=6, vhMode=2
    DURATION_COUNT = 12
};

// Convert a screenStatus code (foldStatus*10 + vhMode) to DurationIndex.
// Returns DURATION_COUNT for invalid screenStatus values.
inline size_t ScreenStatusToIndex(int32_t screenStatus)
{
    using namespace ImeFoldStatusBase;
    int32_t foldStatus = screenStatus / SCREEN_STATUS_ENCODE_BASE;
    int32_t vhMode = screenStatus % SCREEN_STATUS_ENCODE_BASE;
    if (foldStatus < FOLD_STATUS_MIN || foldStatus > FOLD_STATUS_MAX || vhMode < VH_MODE_MIN || vhMode > VH_MODE_MAX) {
        return DURATION_COUNT;
    }
    return static_cast<size_t>((foldStatus - FOLD_STATUS_MIN) * VH_MODE_COUNT + (vhMode - VH_MODE_MIN));
}

// Screen status value indicating IME is unavailable for the current display mode
// (e.g., SUB or V_MAIN fold modes where the IME panel cannot be shown).
inline constexpr int32_t IME_SCREEN_STATUS_UNAVAILABLE = -1;

// DB table field names
namespace ImeUsageTable {
inline constexpr char FIELD_ID[] = "id";
inline constexpr char FIELD_RAWID[] = "rawid";
inline constexpr char FIELD_TS[] = "ts";
inline constexpr char FIELD_FOLD_STATUS[] = "fold_status";
inline constexpr char FIELD_PRE_FOLD_STATUS[] = "pre_fold_status";
inline constexpr char FIELD_BUNDLE_NAME[] = "bundle_name";
inline constexpr char FIELD_HAPPEN_TIME[] = "happen_time";
inline constexpr char FIELD_FOLD_PORTRAIT_DURATION[] = "fold_portrait_duration";
inline constexpr char FIELD_FOLD_LANDSCAPE_DURATION[] = "fold_landscape_duration";
inline constexpr char FIELD_EXPAND_PORTRAIT_DURATION[] = "expand_portrait_duration";
inline constexpr char FIELD_EXPAND_LANDSCAPE_DURATION[] = "expand_landscape_duration";
inline constexpr char FIELD_G_PORTRAIT_DURATION[] = "g_portrait_duration";
inline constexpr char FIELD_G_LANDSCAPE_DURATION[] = "g_landscape_duration";
inline constexpr char FIELD_UNFOLDED_PORTRAIT_DURATION[] = "unfolded_portrait_duration";
inline constexpr char FIELD_UNFOLDED_LANDSCAPE_DURATION[] = "unfolded_landscape_duration";
inline constexpr char FIELD_N_PORTRAIT_DURATION[] = "n_portrait_duration";
inline constexpr char FIELD_N_LANDSCAPE_DURATION[] = "n_landscape_duration";
inline constexpr char FIELD_LM_PORTRAIT_DURATION[] = "lm_portrait_duration";
inline constexpr char FIELD_LM_LANDSCAPE_DURATION[] = "lm_landscape_duration";
inline constexpr char FIELD_SHOW_COUNT[] = "show_count";
} // namespace ImeUsageTable

// HiSysEvent field keys for reporting
namespace ImeUsageEventSpace {
inline constexpr char EVENT_NAME[] = "IME_USAGE_DURATION";
inline constexpr char KEY_OF_PACKAGE[] = "PACKAGE";
inline constexpr char KEY_OF_FOLD_PORTRAIT[] = "FOLD_V";
inline constexpr char KEY_OF_FOLD_LANDSCAPE[] = "FOLD_H";
inline constexpr char KEY_OF_EXPAND_PORTRAIT[] = "EXPD_V";
inline constexpr char KEY_OF_EXPAND_LANDSCAPE[] = "EXPD_H";
inline constexpr char KEY_OF_G_PORTRAIT[] = "G_V";
inline constexpr char KEY_OF_G_LANDSCAPE[] = "G_H";
inline constexpr char KEY_OF_UNFOLDED_PORTRAIT[] = "UNFOLD_V";
inline constexpr char KEY_OF_UNFOLDED_LANDSCAPE[] = "UNFOLD_H";
inline constexpr char KEY_OF_N_PORTRAIT[] = "N_V";
inline constexpr char KEY_OF_N_LANDSCAPE[] = "N_H";
inline constexpr char KEY_OF_LM_PORTRAIT[] = "LM_V";
inline constexpr char KEY_OF_LM_LANDSCAPE[] = "LM_H";
inline constexpr char KEY_OF_USAGE[] = "USAGE";
inline constexpr char KEY_OF_DATE[] = "DATE";
inline constexpr char KEY_OF_SHOW_COUNT[] = "TOTAL_SHOW_NUM";
} // namespace ImeUsageEventSpace

inline constexpr uint32_t MAX_IME_USAGE_SIZE = 100;
inline constexpr uint32_t DATA_KEEP_DAY = 3;
inline constexpr uint64_t MILLISECS_PER_DAY = 24ULL * 60 * 60 * 1000;
inline constexpr uint64_t MILLISECS_PER_SEC = 1000;
inline constexpr uint64_t NANOSECS_PER_MILLISEC = 1000000;
inline constexpr const char *IME_USAGE_DB_NAME = "ime_usage_log.db";
inline constexpr const char *IME_USAGE_DB_TABLE = "ime_usage_events";
inline constexpr const char *IME_USAGE_STATE_TABLE = "ime_usage_report_state";
inline constexpr const char *STATE_KEY_LAST_REPORT_TIME = "last_report_time";

// Common return codes for IME usage operations
inline constexpr int IME_USAGE_SUCCESS = 0;
inline constexpr int IME_USAGE_FAILED = -1;
// Sentinel value indicating no matching DB row was found
inline constexpr int IME_INDEX_NOT_FOUND = -1;

// Sentinel values for "not set" / "never happened" states
// rawid=0 means the ImeEventRecord was default-constructed and never filled
inline constexpr int32_t RAWID_NONE = 0;
// screenStatus=0 means foldStatus/vhMode were never initialized
inline constexpr int32_t SCREEN_STATUS_UNINITIALIZED = 0;
// lastReportTime=0 means no report has ever been recorded
inline constexpr uint64_t REPORT_TIME_NEVER = 0;

// Single event record written to DB
struct ImeEventRecord {
    int32_t rawid = RAWID_NONE;
    int64_t ts = 0;         // boot-relative timestamp for duration calculation
    int64_t happenTime = 0; // wall-clock timestamp for date-range queries
    std::string bundleName;
    int32_t preScreenStatus = SCREEN_STATUS_UNINITIALIZED;
    int32_t screenStatus = SCREEN_STATUS_UNINITIALIZED;
};

// Raw event read from DB for foreground recovery
struct ImeUsageRawEvent {
    int64_t id = 0;
    int32_t rawId = RAWID_NONE;
    std::string package;
    int64_t ts = 0;
    int64_t happenTime = 0;
    int32_t screenStatusBefore = SCREEN_STATUS_UNINITIALIZED;
    int32_t screenStatusAfter = SCREEN_STATUS_UNINITIALIZED;
};

// Aggregated usage info per IME package
struct ImeUsageInfo {
    std::string package;
    std::array<uint32_t, DURATION_COUNT> durations {};
    uint32_t showCount = 0;
    uint64_t usage = 0;

    ImeUsageInfo &operator+=(const ImeUsageInfo &other)
    {
        for (size_t i = 0; i < DURATION_COUNT; i++) {
            durations[i] += other.durations[i];
        }
        showCount += other.showCount;
        usage = GetAppUsage();
        return *this;
    }

    uint64_t GetAppUsage() const
    {
        uint64_t total = 0;
        for (size_t i = 0; i < DURATION_COUNT; i++) {
            total += durations[i];
        }
        return total;
    }
};

// Map from screen status code to duration (used in DB read/write)
using DurationMap = std::map<int32_t, uint64_t>;

inline uint64_t ZeroClockMsFromTimeT(std::time_t t)
{
    struct tm localTm = {};
    if (localtime_r(&t, &localTm) == nullptr) {
        return 0;
    }
    localTm.tm_hour = 0;
    localTm.tm_min = 0;
    localTm.tm_sec = 0;
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::from_time_t(std::mktime(&localTm)).time_since_epoch())
                                     .count());
}

inline uint64_t GetToday0ClockMs()
{
    return ZeroClockMsFromTimeT(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

inline uint64_t DayStartFromMs(uint64_t ms)
{
    return ZeroClockMsFromTimeT(static_cast<std::time_t>(ms / MILLISECS_PER_SEC));
}

// Encode foldStatus and vhMode into a single screenStatus code.
// Constraint: foldStatus must be in [1, 9] for correct decoding.
// foldStatus=0 is reserved for "uninitialized" and should not be encoded.
inline int32_t EncodeScreenStatus(int32_t foldStatus, int32_t vhMode)
{
    return foldStatus * SCREEN_STATUS_ENCODE_BASE + vhMode;
}

// Decode a screenStatus code back into foldStatus and vhMode.
// Inverse of EncodeScreenStatus. Only valid when foldStatus was in [1, 9].
inline void DecodeScreenStatus(int32_t screenStatus, int32_t &foldStatus, int32_t &vhMode)
{
    foldStatus = screenStatus / SCREEN_STATUS_ENCODE_BASE;
    vhMode = screenStatus % SCREEN_STATUS_ENCODE_BASE;
}

inline std::string FormatDateStr(uint64_t dayStartMs)
{
    std::time_t t = static_cast<std::time_t>(dayStartMs / MILLISECS_PER_SEC);
    struct tm localTm = {};
    if (localtime_r(&t, &localTm) != nullptr) {
        char buf[16] = { 0 };
        std::strftime(buf, sizeof(buf), "%Y%m%d", &localTm);
        return std::string(buf);
    }
    return "19700101";
}

} // namespace MiscServices
} // namespace OHOS

#endif // SERVICES_IME_USAGE_INCLUDE_IME_USAGE_COMMON_H
