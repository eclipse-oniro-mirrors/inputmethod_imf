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
 
#include <chrono>
#include <ctime>
#include <cstdint>
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
inline constexpr int8_t UNFOLDED = 1;  // 非折叠机
inline constexpr int8_t FOLD = 2;      // F态 (MAIN)
inline constexpr int8_t EXPAND = 3;    // M态 (FULL/COORDINATION)
inline constexpr int8_t G = 4;         // G态 (GLOBAL_FULL)
inline constexpr int8_t N = 5;         // N态 (N_MAIN)
inline constexpr int8_t LM = 6;        // LM态 (L_FULL)
inline constexpr int8_t LANDSCAPE = 1;
inline constexpr int8_t PORTRAIT = 2;
} // namespace ImeFoldStatusBase
 
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
inline constexpr int UNFOLDED_LANDSCAPE = UNFOLDED * 10 + LANDSCAPE;
inline constexpr int UNFOLDED_PORTRAIT = UNFOLDED * 10 + PORTRAIT;
inline constexpr int FOLD_LANDSCAPE = FOLD * 10 + LANDSCAPE;
inline constexpr int FOLD_PORTRAIT = FOLD * 10 + PORTRAIT;
inline constexpr int EXPAND_LANDSCAPE = EXPAND * 10 + LANDSCAPE;
inline constexpr int EXPAND_PORTRAIT = EXPAND * 10 + PORTRAIT;
inline constexpr int G_LANDSCAPE = G * 10 + LANDSCAPE;
inline constexpr int G_PORTRAIT = G * 10 + PORTRAIT;
inline constexpr int N_LANDSCAPE = N * 10 + LANDSCAPE;
inline constexpr int N_PORTRAIT = N * 10 + PORTRAIT;
inline constexpr int LM_LANDSCAPE = LM * 10 + LANDSCAPE;
inline constexpr int LM_PORTRAIT = LM * 10 + PORTRAIT;
} // namespace ImeScreenStatus
 
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
inline constexpr const char *IME_USAGE_DB_NAME = "ime_usage_log.db";
inline constexpr const char *IME_USAGE_DB_TABLE = "ime_usage_events";
inline constexpr const char *IME_USAGE_STATE_TABLE = "ime_usage_report_state";
inline constexpr const char *STATE_KEY_LAST_REPORT_TIME = "last_report_time";
 
// Single event record written to DB
struct ImeEventRecord {
    int32_t rawid = 0;
    int64_t ts = 0;           // boot-relative timestamp for duration calculation
    int64_t happenTime = 0;   // wall-clock timestamp for date-range queries
    std::string bundleName;
    int32_t preScreenStatus = 0;
    int32_t screenStatus = 0;
};
 
// Raw event read from DB for foreground recovery
struct ImeUsageRawEvent {
    int64_t id = 0;
    int32_t rawId = 0;
    std::string package;
    int64_t ts = 0;
    int64_t happenTime = 0;
    int32_t screenStatusBefore = 0;
    int32_t screenStatusAfter = 0;
};
 
// Aggregated usage info per IME package
struct ImeUsageInfo {
    std::string package;
    uint32_t foldPortraitDuration = 0;
    uint32_t foldLandscapeDuration = 0;
    uint32_t expandPortraitDuration = 0;
    uint32_t expandLandscapeDuration = 0;
    uint32_t gPortraitDuration = 0;
    uint32_t gLandscapeDuration = 0;
    uint32_t unFoldedPortraitDuration = 0;
    uint32_t unFoldedLandscapeDuration = 0;
    uint32_t nPortraitDuration = 0;
    uint32_t nLandscapeDuration = 0;
    uint32_t lmPortraitDuration = 0;
    uint32_t lmLandscapeDuration = 0;
    uint32_t showCount = 0;
    uint64_t usage = 0;
 
    ImeUsageInfo &operator+=(const ImeUsageInfo &other)
    {
        foldPortraitDuration += other.foldPortraitDuration;
        foldLandscapeDuration += other.foldLandscapeDuration;
        expandPortraitDuration += other.expandPortraitDuration;
        expandLandscapeDuration += other.expandLandscapeDuration;
        gPortraitDuration += other.gPortraitDuration;
        gLandscapeDuration += other.gLandscapeDuration;
        unFoldedPortraitDuration += other.unFoldedPortraitDuration;
        unFoldedLandscapeDuration += other.unFoldedLandscapeDuration;
        nPortraitDuration += other.nPortraitDuration;
        nLandscapeDuration += other.nLandscapeDuration;
        lmPortraitDuration += other.lmPortraitDuration;
        lmLandscapeDuration += other.lmLandscapeDuration;
        showCount += other.showCount;
        usage = GetAppUsage();
        return *this;
    }
 
    uint64_t GetAppUsage() const
    {
        return static_cast<uint64_t>(foldPortraitDuration) + foldLandscapeDuration +
               expandPortraitDuration + expandLandscapeDuration +
               gPortraitDuration + gLandscapeDuration +
               unFoldedPortraitDuration + unFoldedLandscapeDuration +
               nPortraitDuration + nLandscapeDuration +
               lmPortraitDuration + lmLandscapeDuration;
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
        std::chrono::system_clock::from_time_t(std::mktime(&localTm)).time_since_epoch()).count());
}
 
inline uint64_t GetToday0ClockMs()
{
    return ZeroClockMsFromTimeT(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}
 
inline uint64_t DayStartFromMs(uint64_t ms)
{
    return ZeroClockMsFromTimeT(static_cast<std::time_t>(ms / 1000));
}
 
inline std::string FormatDateStr(uint64_t dayStartMs)
{
    std::time_t t = static_cast<std::time_t>(dayStartMs / 1000);
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