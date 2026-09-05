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

#ifndef SERVICES_IME_USAGE_INCLUDE_IME_USAGE_EVENT_CACHER_H
#define SERVICES_IME_USAGE_INCLUDE_IME_USAGE_EVENT_CACHER_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ime_usage_common.h"
#include "ime_usage_db_helper.h"

namespace OHOS {
namespace MiscServices {

class ImeUsageEventCacher {
public:
    ImeUsageEventCacher() = default;
    ~ImeUsageEventCacher() = default;

    int Init(std::shared_ptr<ImeUsageDbHelper> dbHelper, int32_t foldStatus, int32_t vhMode);

    // Called when a real IME is bound to a client (BindClientWithIme + IsRealIme)
    void OnImeBind(const std::string &bundleName);

    // Called when a real IME session ends (unbind/hide from framework).
    // Idempotent: if isKeyboardShowing_ is false (no active session), the call
    // is a no-op. Multiple paths may call this for the same unbind event
    // (e.g., HideKeyboardSelf + DestroyPanel), but only the first call with
    // isKeyboardShowing_==true will produce a STOP event.
    void OnImeUnbind(const std::string &bundleName);

    // Called when screen status changes (fold/rotate)
    void OnScreenStatusChanged(int32_t preScreenStatus, int32_t newScreenStatus);

    // Called on service init to recover in-progress state
    void RecoverActiveSession();

    // Get current screen status encoding
    int32_t GetScreenStatus() const;

private:
    // Result of PrepareShowEvent: contains both the hide record (if an IME
    // was previously showing) and the show record for the new IME.
    struct ShowPrepareResult {
        ImeEventRecord hideRecord;
        ImeEventRecord showRecord;
    };

    ShowPrepareResult PrepareShowEvent(const std::string &bundleName);
    ImeEventRecord PrepareHideRecord(const std::string &bundleName);
    ImeEventRecord ProcessScreenChangedEvent(int32_t preScreenStatus, int32_t newScreenStatus);
    void CountDuration(ImeEventRecord &record);
    DurationMap CalculateDurationForRecord(const ImeEventRecord &record);
    void CalculateDuration(uint64_t dayStartTime, std::vector<ImeEventRecord> &records, DurationMap &durations);
    bool CanCalcDuration(int32_t preRawId, int32_t rawId) const;
    void Accumulate(int32_t screenStatus, uint64_t duration, DurationMap &durations) const;
    void ProcessCountDurationEvent(ImeEventRecord &record, const DurationMap &durations);
    int GetStartIndex(const std::string &bundleName);
    uint64_t GetBootTimeMs() const;
    uint64_t GetWallClockMs() const;

    std::shared_ptr<ImeUsageDbHelper> dbHelper_;
    std::string currentImeBundle_;
    bool isKeyboardShowing_ = false;
    int32_t foldStatus_ = 0;
    int32_t vhMode_ = 0;
    int32_t lastScreenStatus_ = 0; // last screenStatus written to DB, used for dedup
    std::mutex mutex_;
};

} // namespace MiscServices
} // namespace OHOS

#endif // SERVICES_IME_USAGE_INCLUDE_IME_USAGE_EVENT_CACHER_H
