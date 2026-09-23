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

#include "ime_usage_file_store.h"

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "file_operator.h"
#include "global.h"
#include "serializable.h"

namespace OHOS {
namespace MiscServices {
namespace {
// Directory permission: owner rwx + group rwx
constexpr mode_t DIR_PERM = S_IRWXU | S_IRWXG;
// JSON field keys for the events file
constexpr char KEY_NEXT_ID[] = "nextId";
constexpr char KEY_LAST_REPORT_TIME[] = "lastReportTime";
constexpr char KEY_EVENTS[] = "events";
// JSON field keys for a single event row
constexpr char KEY_ID[] = "id";
constexpr char KEY_RAWID[] = "rawid";
constexpr char KEY_TS[] = "ts";
constexpr char KEY_HAPPEN_TIME[] = "happenTime";
constexpr char KEY_BUNDLE_NAME[] = "bundleName";
constexpr char KEY_PRE_SCREEN_STATUS[] = "preScreenStatus";
constexpr char KEY_SCREEN_STATUS[] = "screenStatus";
constexpr char KEY_DURATIONS[] = "durations";
constexpr char KEY_SHOW_COUNT[] = "showCount";

// Serializable wrapper for a single ImeUsageEventRow.
// Owns a row internally and is default-constructible, so the array templates
// Serializable::GetValue(vector<T>) / SetValue(vector<T>) can be reused for
// reading/writing arrays of events without any direct cJSON calls here.
struct EventRowJson : public Serializable {
    ImeUsageEventRow row;

    EventRowJson() = default;
    explicit EventRowJson(const ImeUsageEventRow &r) : row(r) { }

    bool Unmarshal(cJSON *node) override
    {
        bool ok = true;
        ok = GetValue(node, KEY_ID, row.id) && ok;
        ok = GetValue(node, KEY_RAWID, row.rawid) && ok;
        ok = GetValue(node, KEY_TS, row.ts) && ok;
        ok = GetValue(node, KEY_HAPPEN_TIME, row.happenTime) && ok;
        ok = GetValue(node, KEY_BUNDLE_NAME, row.bundleName) && ok;
        ok = GetValue(node, KEY_PRE_SCREEN_STATUS, row.preScreenStatus) && ok;
        ok = GetValue(node, KEY_SCREEN_STATUS, row.screenStatus) && ok;
        // showCount is optional in JSON (omitted when 0 for non-COUNT_DURATION rows)
        GetValue(node, KEY_SHOW_COUNT, row.showCount);
        // durations is optional in JSON (omitted when all-zero for non-COUNT_DURATION rows)
        std::vector<uint64_t> durVec;
        if (GetValue(node, KEY_DURATIONS, durVec)) {
            if (durVec.size() != DURATION_COUNT) {
                IMSA_HILOGE("durations size %{public}zu != %{public}zu", durVec.size(), DURATION_COUNT);
                return false;
            }
            for (size_t i = 0; i < DURATION_COUNT; i++) {
                row.durations[i] = durVec[i];
            }
        } else if (GetSubNode(node, KEY_DURATIONS) != nullptr) {
            // Node present but failed to parse (not array / non-number element)
            IMSA_HILOGE("durations present but invalid");
            return false;
        }
        // Missing durations node means all-zero (default-constructed)
        return ok;
    }

    bool Marshal(cJSON *node) const override
    {
        bool ok = true;
        ok = SetValue(node, KEY_ID, row.id) && ok;
        ok = SetValue(node, KEY_RAWID, row.rawid) && ok;
        ok = SetValue(node, KEY_TS, row.ts) && ok;
        ok = SetValue(node, KEY_HAPPEN_TIME, row.happenTime) && ok;
        ok = SetValue(node, KEY_BUNDLE_NAME, row.bundleName) && ok;
        ok = SetValue(node, KEY_PRE_SCREEN_STATUS, row.preScreenStatus) && ok;
        ok = SetValue(node, KEY_SCREEN_STATUS, row.screenStatus) && ok;
        // Omit showCount when 0 (non-COUNT_DURATION rows) to save space
        if (row.showCount != 0) {
            ok = SetValue(node, KEY_SHOW_COUNT, row.showCount) && ok;
        }
        // Omit durations when all-zero (non-COUNT_DURATION rows) to save space.
        // Each all-zero array would waste ~80 bytes per row in JSON.
        if (!IsDurationMapEmpty(row.durations)) {
            std::vector<uint64_t> durVec(row.durations.begin(), row.durations.end());
            ok = SetValue(node, KEY_DURATIONS, durVec) && ok;
        }
        return ok;
    }
};

// Serializable wrapper for the events file: { "nextId": N, "lastReportTime": T, "events": [...] }
struct EventsFileJson : public Serializable {
    std::vector<ImeUsageEventRow> *events = nullptr;
    int64_t *nextId = nullptr;
    uint64_t *lastReportTime = nullptr;
    const std::vector<ImeUsageEventRow> *cevents = nullptr;
    int64_t cnextId = 0;
    uint64_t clastReportTime = 0;

    // For loading
    EventsFileJson(std::vector<ImeUsageEventRow> &e, int64_t &n, uint64_t &t)
        : events(&e), nextId(&n), lastReportTime(&t), cevents(&e), cnextId(n), clastReportTime(t)
    {
    }
    // For writing
    EventsFileJson(const std::vector<ImeUsageEventRow> &e, int64_t n, uint64_t t)
        : events(nullptr), nextId(nullptr), lastReportTime(nullptr), cevents(&e), cnextId(n), clastReportTime(t)
    {
    }

    bool Unmarshal(cJSON *node) override
    {
        if (events == nullptr || nextId == nullptr || lastReportTime == nullptr) {
            return false;
        }
        if (!GetValue(node, KEY_NEXT_ID, *nextId)) {
            IMSA_HILOGE("nextId missing");
            return false;
        }
        // lastReportTime is optional (absent on first run or legacy files).
        // Serializable only supports int64_t, not uint64_t, so use a proxy.
        int64_t tmp = 0;
        GetValue(node, KEY_LAST_REPORT_TIME, tmp);
        *lastReportTime = static_cast<uint64_t>(tmp);
        std::vector<EventRowJson> rows;
        if (!GetValue(node, KEY_EVENTS, rows)) {
            IMSA_HILOGE("events not array");
            return false;
        }
        events->clear();
        events->reserve(rows.size());
        for (auto &r : rows) {
            events->push_back(std::move(r.row));
        }
        return true;
    }

    bool Marshal(cJSON *node) const override
    {
        if (cevents == nullptr) {
            return false;
        }
        if (!SetValue(node, KEY_NEXT_ID, cnextId)) {
            return false;
        }
        if (!SetValue(node, KEY_LAST_REPORT_TIME, static_cast<int64_t>(clastReportTime))) {
            return false;
        }
        std::vector<EventRowJson> rows;
        rows.reserve(cevents->size());
        for (const auto &row : *cevents) {
            rows.emplace_back(row);
        }
        return SetValue(node, KEY_EVENTS, rows);
    }
};
} // namespace

ImeUsageFileStore::ImeUsageFileStore(const std::string &workPath)
{
    if (workPath.empty()) {
        IMSA_HILOGE("workPath is empty");
        return;
    }
    if (!EnsureDirectoryExist(workPath)) {
        IMSA_HILOGE("EnsureDirectoryExist failed: %{public}s", workPath.c_str());
        return;
    }
    std::string base = workPath;
    if (base.back() != '/') {
        base += '/';
    }
    eventsFilePath_ = base + IME_USAGE_EVENTS_FILE_NAME;
    IMSA_HILOGI("ImeUsageFileStore ready: events=%{public}s", eventsFilePath_.c_str());
}

bool ImeUsageFileStore::EnsureDirectoryExist(const std::string &path)
{
    if (path.empty()) {
        IMSA_HILOGE("path is empty");
        return false;
    }
    if (access(path.c_str(), F_OK) == 0) {
        return true;
    }
    size_t pos = 0;
    while ((pos = path.find('/', pos + 1)) != std::string::npos) {
        std::string subPath = path.substr(0, pos);
        if (access(subPath.c_str(), F_OK) != 0) {
            if (mkdir(subPath.c_str(), DIR_PERM) != 0 && errno != EEXIST) {
                IMSA_HILOGE("mkdir %{public}s failed, errno=%{public}d", subPath.c_str(), errno);
                return false;
            }
        }
    }
    if (mkdir(path.c_str(), DIR_PERM) != 0 && errno != EEXIST) {
        IMSA_HILOGE("mkdir %{public}s failed, errno=%{public}d", path.c_str(), errno);
        return false;
    }
    IMSA_HILOGI("created %{public}s", path.c_str());
    return true;
}

bool ImeUsageFileStore::LoadEvents(std::vector<ImeUsageEventRow> &events, int64_t &nextId, uint64_t &lastReportTime)
{
    if (!IsReady()) {
        IMSA_HILOGE("not ready");
        return false;
    }
    events.clear();
    nextId = 1;
    lastReportTime = 0;
    if (!FileOperator::IsExist(eventsFilePath_)) {
        IMSA_HILOGI("events file not exist, start fresh");
        return true;
    }
    std::string content;
    if (!FileOperator::Read(eventsFilePath_, content)) {
        IMSA_HILOGE("read events file failed");
        return false;
    }
    if (content.empty()) {
        IMSA_HILOGI("events file empty, start fresh");
        return true;
    }
    EventsFileJson fileJson(events, nextId, lastReportTime);
    if (!fileJson.Unmarshall(content)) {
        IMSA_HILOGW("parse events file failed, backing up corrupt file and starting fresh");
        // Rename the corrupt file instead of deleting it, so that lastReportTime
        // and event data can potentially be recovered manually if needed.
        std::string backupPath = eventsFilePath_ + ".corrupt";
        std::remove(backupPath.c_str());
        if (std::rename(eventsFilePath_.c_str(), backupPath.c_str()) != 0) {
            // If rename fails (e.g., cross-device), fall back to removal.
            std::remove(eventsFilePath_.c_str());
        }
        events.clear();
        nextId = 1;
        lastReportTime = 0;
        return true;
    }
    IMSA_HILOGI("loaded %{public}zu events, nextId=%{public}" PRId64 ", lastReportTime=%{public}llu", events.size(),
        nextId, static_cast<unsigned long long>(lastReportTime));
    return true;
}

bool ImeUsageFileStore::WriteEvents(
    const std::vector<ImeUsageEventRow> &events, int64_t nextId, uint64_t lastReportTime)
{
    if (!IsReady()) {
        IMSA_HILOGE("not ready");
        return false;
    }
    EventsFileJson fileJson(events, nextId, lastReportTime);
    std::string content;
    if (!fileJson.Marshall(content)) {
        IMSA_HILOGE("marshal events failed");
        return false;
    }
    if (!FileOperator::Write(eventsFilePath_, content, O_CREAT | O_WRONLY | O_SYNC | O_TRUNC)) {
        IMSA_HILOGE("write events file failed");
        return false;
    }
    return true;
}

} // namespace MiscServices
} // namespace OHOS
