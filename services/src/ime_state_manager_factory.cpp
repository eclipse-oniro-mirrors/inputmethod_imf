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
#include "ime_state_manager_factory.h"

#include "freeze_manager.h"
#include "ime_lifecycle_manager.h"
#include "global.h"

namespace OHOS {
namespace MiscServices {
void ImeStateManagerFactory::SetDynamicStartIme(bool ifDynamicStartIme)
{
    ifDynamicStartIme_ = ifDynamicStartIme;
}

bool ImeStateManagerFactory::GetDynamicStartIme()
{
    return ifDynamicStartIme_;
}

ImeStateManagerFactory &ImeStateManagerFactory::GetInstance()
{
    static ImeStateManagerFactory instance;
    return instance;
}

std::shared_ptr<ImeStateManager> ImeStateManagerFactory::CreateImeStateManager(pid_t pid,
    std::function<void()> stopImeFunc)
{
    if (ifDynamicStartIme_) {
        return std::make_shared<ImeLifecycleManager>(pid, stopImeFunc);
    }
    return std::make_shared<FreezeManager>(pid);
}
} // namespace MiscServices
} // namespace OHOS