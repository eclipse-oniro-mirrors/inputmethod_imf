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

#include "ime_usage_event_factory.h"

#include <algorithm>

#include "global.h"

using namespace OHOS::MiscServices::ImeUsageEventId;

namespace OHOS {
namespace MiscServices {

ImeUsageEventFactory::ImeUsageEventFactory(std::shared_ptr<ImeUsageDataHelper> dataHelper)
{
    dataHelper_ = dataHelper;
    IMSA_HILOGI("ImeUsageEventFactory created");
}

void ImeUsageEventFactory::Create(std::vector<ImeUsageInfo> &infos, uint64_t dayStartTime, uint64_t dayEndTime)
{
    IMSA_HILOGD("Create: dayStartTime=%{public}llu, dayEndTime=%{public}llu",
        static_cast<unsigned long long>(dayStartTime), static_cast<unsigned long long>(dayEndTime));

    GetUsageInfo(infos, dayStartTime, dayEndTime);

    IMSA_HILOGD("Daily aggregation: infoCount=%{public}zu", infos.size());
}

void ImeUsageEventFactory::GetUsageInfo(std::vector<ImeUsageInfo> &infos, uint64_t startTime, uint64_t endTime)
{
    // Channel 1: Query aggregated COUNT_DURATION records
    if (dataHelper_ == nullptr) {
        IMSA_HILOGE("dataHelper_ is nullptr");
        return;
    }
    std::unordered_map<std::string, ImeUsageInfo> statisticInfos;
    dataHelper_->QueryStatisticEventsInPeriod(startTime, endTime, statisticInfos);
    IMSA_HILOGD("GetUsageInfo: channel1(statistic) found %{public}zu IMEs", statisticInfos.size());

    // Channel 2+3: Merge foreground IME duration
    MergeForegroundInfo(statisticInfos, startTime, endTime);

    CollectAndSortResults(statisticInfos, infos);
    IMSA_HILOGD("GetUsageInfo: after filter, %{public}zu IMEs with usage > 0", infos.size());
}

void ImeUsageEventFactory::MergeForegroundInfo(
    std::unordered_map<std::string, ImeUsageInfo> &statisticInfos, uint64_t startTime, uint64_t endTime)
{
    if (dataHelper_ == nullptr) {
        IMSA_HILOGE("MergeForegroundInfo: dataHelper_ is nullptr");
        return;
    }
    ImeUsageRawEvent lastEvent;
    dataHelper_->QueryFinalEventInfo(endTime, lastEvent);

    if (lastEvent.rawId != EVENT_INPUT_START && lastEvent.rawId != EVENT_INPUT_STATUS_CHANGED) {
        IMSA_HILOGI("MergeForegroundInfo: no foreground IME, lastRawId=%{public}d", lastEvent.rawId);
        return;
    }
    IMSA_HILOGD(
        "MergeForegroundInfo: lastEvent rawId=%{public}d, pkg=%{public}s", lastEvent.rawId, lastEvent.package.c_str());

    // showCount defaults to 0 via ImeUsageInfo's default member initializer;
    // Channel1 already counts INPUT_START events, so no explicit assignment needed.
    ImeUsageInfo foregroundInfo;
    foregroundInfo.package = lastEvent.package;

    dataHelper_->QueryForegroundImeInfo(startTime, endTime, lastEvent.screenStatusAfter, foregroundInfo);
    foregroundInfo.usage = foregroundInfo.GetAppUsage();

    auto it = statisticInfos.find(foregroundInfo.package);
    if (it != statisticInfos.end()) {
        it->second += foregroundInfo;
    } else {
        statisticInfos[foregroundInfo.package] = foregroundInfo;
    }
}

void ImeUsageEventFactory::CollectAndSortResults(
    std::unordered_map<std::string, ImeUsageInfo> &statisticInfos, std::vector<ImeUsageInfo> &infos)
{
    infos.clear();
    for (auto &[key, info] : statisticInfos) {
        if (info.usage > 0) {
            infos.push_back(info);
        }
    }
    std::sort(infos.begin(), infos.end(), [](const ImeUsageInfo &a, const ImeUsageInfo &b) {
        return a.usage > b.usage;
    });

    if (infos.size() > MAX_IME_USAGE_SIZE) {
        IMSA_HILOGD("CollectAndSortResults: capping from %{public}zu to %{public}u", infos.size(), MAX_IME_USAGE_SIZE);
        infos.resize(MAX_IME_USAGE_SIZE);
    }
}

} // namespace MiscServices
} // namespace OHOS
