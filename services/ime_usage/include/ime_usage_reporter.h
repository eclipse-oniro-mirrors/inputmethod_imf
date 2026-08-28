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
 
#ifndef SERVICES_IME_USAGE_INCLUDE_IME_USAGE_REPORTER_H
#define SERVICES_IME_USAGE_INCLUDE_IME_USAGE_REPORTER_H
 
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
 
#include "event_handler.h"
#include "ime_usage_event_cacher.h"
#include "ime_usage_event_factory.h"
 
namespace OHOS {
namespace MiscServices {
class ImeUsageReporter {
public:
    ImeUsageReporter() = default;
    ~ImeUsageReporter();
 
    // Initialize the reporter, create DB, start timer
    int Init(const std::string &workPath);
 
    // Set the event handler for timer scheduling (called from service)
    void SetEventHandler(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
 
    // Event notification methods - called from IMF service
    void OnImeBind(const std::string &bundleName);
    void OnImeUnbind(const std::string &bundleName);
    void OnScreenStatusChanged(int32_t preScreenStatus, int32_t newScreenStatus);
 
    // Called on boot completed to recover state
    void OnBootCompleted();
 
private:
    void StartTimer();
    void OnTimeout();
    void ReportDailyEvent();
    void InnerReportDailyEvent();
    void ReportAndCleanupOldData(uint64_t clearDataTime, uint64_t alreadyReportedDay0);
    bool ReportSingleDay(uint64_t dayStartTime, uint64_t dayEndTime, const std::string &dateStr);
    uint32_t ReportCatchupDays(uint64_t firstReportDayStart, uint64_t today0Time);
    bool WriteImeUsageEvent(const ImeUsageInfo &info, const std::string &dateStr);
    uint64_t GetToday0ClockMs() const;
    uint64_t GetNowMs() const;
    void PersistLastReportTime();
    uint64_t LoadLastReportTime();
    uint64_t DayStartFromMs(uint64_t ms) const;
    uint64_t GetCurrentPeriodStartMs() const;
    uint64_t GetNextReportTimeMs() const;
 
    std::unique_ptr<ImeUsageEventCacher> eventCacher_;
    std::unique_ptr<ImeUsageEventFactory> eventFactory_;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_;
    std::atomic<bool> shouldReportLastData_{ false };
    std::atomic<bool> isRunning_{ false };
    uint64_t lastReportTime_{ 0 };
    uint64_t nextReportTime_{ 0 };
    std::string workPath_;
    std::mutex reportMutex_;
};
} // namespace MiscServices
} // namespace OHOS
 
#endif // SERVICES_IME_USAGE_INCLUDE_IME_USAGE_REPORTER_H