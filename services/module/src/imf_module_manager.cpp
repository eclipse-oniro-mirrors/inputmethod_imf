/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "imf_module_manager.h"

#include "global.h"
namespace OHOS {
namespace MiscServices {
ImfModuleMgr &ImfModuleMgr::GetInstance()
{
    static ImfModuleMgr instance;
    return instance;
}

int32_t ImfModuleMgr::Scan(const std::string &modulePath)
{
    if (HasScan(modulePath)) {
        IMSA_HILOGE("module:%{public}s has scan.", modulePath.c_str());
        return ErrorCode::NO_ERROR;
    }
    auto moduleMgr = ModuleMgrScan(modulePath.c_str());
    if (ModuleMgrGetCnt(moduleMgr) == 0) {
        IMSA_HILOGE("module:%{public}s scan failed.", modulePath.c_str());
        ModuleMgrDestroy(moduleMgr);
        return ErrorCode::ERROR_EX_ILLEGAL_STATE;
    }
    {
        std::lock_guard<std::mutex> lock(modulesLock_);
        modules_.insert({ modulePath, moduleMgr });
    }
    return ErrorCode::NO_ERROR;
}

void ImfModuleMgr::Destroy(const std::string &modulePath)
{
    MODULE_MGR *moduleMgr = nullptr;
    {
        std::lock_guard<std::mutex> lock(modulesLock_);
        auto iter = modules_.find(modulePath);
        if (iter == modules_.end()) {
            return;
        }
        moduleMgr = iter->second;
        modules_.erase(iter);
    }
    ModuleMgrDestroy(moduleMgr);
}

bool ImfModuleMgr::HasScan(const std::string &modulePath)
{
    std::lock_guard<std::mutex> lock(modulesLock_);
    return modules_.find(modulePath) != modules_.end();
}
} // namespace MiscServices
} // namespace OHOS