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

#include "modulemgr.h"
namespace OHOS {
namespace MiscServices {
int g_modulesCount = 0;
MODULE_MGR *ModuleMgrScan(const char *modulePath)
{
    MODULE_MGR *mgr = nullptr;
    return mgr;
}

void ModuleMgrDestroy(MODULE_MGR *moduleMgr)
{
}

void SetModulesCnt(int count)
{
    g_modulesCount = count;
}
int ModuleMgrGetCnt(MODULE_MGR *moduleMgr)
{
    return g_modulesCount;
}
} // namespace MiscServices
} // namespace OHOS