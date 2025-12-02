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
#ifndef ANI_CALLBACK_OBJECT_H
#define ANI_CALLBACK_OBJECT_H

#include <mutex>
#include <thread>

#include "block_data.h"
#include "event_handler.h"
#include "ohos.inputMethod.proj.hpp"
#include "ohos.inputMethod.impl.hpp"
#include "taihe/runtime.hpp"
#include "ani.h"

namespace OHOS {
namespace MiscServices {
// Ensure this object abstract in constract thread.
class AniMsgHandlerCallbackObject {
public:
    AniMsgHandlerCallbackObject(ani_vm* vm, ani_object onTerminated, ani_object onMessage);
    ~AniMsgHandlerCallbackObject();
    ani_ref onTerminatedCallback_ = nullptr;
    ani_ref onMessageCallback_ = nullptr;

private:
    static ani_vm* GetAniVm(ani_env* env);
    static ani_env* GetAniEnv(ani_vm* vm);
    static ani_env* AttachAniEnv(ani_vm* vm);
    static ani_vm* vm_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // ANI_CALLBACK_OBJECT_H
