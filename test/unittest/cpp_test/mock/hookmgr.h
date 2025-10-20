/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef IMF_HOOK_MGR_MOCK_H
#define IMF_HOOK_MGR_MOCK_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace MiscServices {

typedef struct HookMgr {
} HOOK_MGR;
typedef struct HookExecArgs {
} HOOK_EXEC_OPTIONS;

int HookMgrExecute(HOOK_MGR *hookMgr, int stage, void *executionContext, const HOOK_EXEC_OPTIONS *extraArgs);
void SetHookMgrExecuteRet(int ret);
} // namespace MiscServices
} // namespace OHOS
#endif // IMF_HOOK_MGR_MOCK_H
