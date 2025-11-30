/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ani_callback_object.h"
#include "global.h"

namespace OHOS {
namespace MiscServices {
ani_vm* AniMsgHandlerCallbackObject::vm_ {nullptr};
ani_vm* AniMsgHandlerCallbackObject::GetAniVm(ani_env* env)
{
    ani_vm* vm = nullptr;
    if (env->GetVM(&vm) != ANI_OK) {
        IMSA_HILOGE("GetVM failed");
        return nullptr;
    }
    return vm;
}

ani_env* AniMsgHandlerCallbackObject::GetAniEnv(ani_vm* vm)
{
    ani_env* env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        IMSA_HILOGE("GetEnv failed");
        return nullptr;
    }
    return env;
}

ani_env* AniMsgHandlerCallbackObject::AttachAniEnv(ani_vm* vm)
{
    ani_env *workerEnv = nullptr;
    ani_options aniArgs {0, nullptr};
    if (vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &workerEnv) != ANI_OK) {
        IMSA_HILOGE("Attach Env failed");
        return nullptr;
    }
    return workerEnv;
}

AniMsgHandlerCallbackObject::AniMsgHandlerCallbackObject(ani_vm* vm, ani_object onTerminated, ani_object onMessage)
{
    if (vm == nullptr) {
        IMSA_HILOGE("vm is nullptr");
        return;
    }
    ani_env* env = GetAniEnv(vm);
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr");
        return;
    }
    if (ANI_OK != env->GlobalReference_Create(onTerminated, &onTerminatedCallback_)) {
        IMSA_HILOGE("GlobalReference_Create onTerminated failed.");
        return;
    }
    if (ANI_OK != env->GlobalReference_Create(onMessage, &onMessageCallback_)) {
        IMSA_HILOGE("GlobalReference_Create onMessage failed.");
        return;
    }
}

AniMsgHandlerCallbackObject::~AniMsgHandlerCallbackObject()
{
    if (vm_ == nullptr) {
        IMSA_HILOGE("vm_ is nullptr");
        return;
    }
    ani_env *env = AttachAniEnv(vm_);
    if (env == nullptr) {
        IMSA_HILOGE("get env is nullptr");
        return;
    }
    if (onTerminatedCallback_ != nullptr) {
        env->GlobalReference_Delete(onTerminatedCallback_);
    }
    if (onMessageCallback_ != nullptr) {
        env->GlobalReference_Delete(onMessageCallback_);
    }
    return;
}
} // namespace MiscServices
} // namespace OHOS
