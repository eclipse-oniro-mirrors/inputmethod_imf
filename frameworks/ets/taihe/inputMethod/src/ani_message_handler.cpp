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

#include "ani_message_handler.h"
#include "ani_common.h"

namespace OHOS {
namespace MiscServices {
constexpr size_t ARGC_ONE = 1;
ani_env* AniMessageHandler::AttachAniEnv(ani_vm* vm)
{
    if (vm == nullptr) {
        IMSA_HILOGE("vm is nullptr");
        return nullptr;
    }
    ani_env *workerEnv = nullptr;
    ani_options aniArgs {0, nullptr};
    if (vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &workerEnv) != ANI_OK) {
        IMSA_HILOGE("Attach Env failed");
        return nullptr;
    }
    return workerEnv;
}

int32_t AniMessageHandler::OnTerminated()
{
    std::lock_guard<decltype(callbackObjectMutex_)> lock(callbackObjectMutex_);
    if (aniMessageHandler_ == nullptr) {
        IMSA_HILOGE("aniMessageHandler_ is nullptr, can not call OnTerminated!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    if (vm_ == nullptr) {
        IMSA_HILOGE("vm is nullptr, can not call OnTerminated!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    ani_env* env = AttachAniEnv(vm_);
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr, can not call OnTerminated!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    ani_ref nullRef;
    if (env->GetNull(&nullRef) != ANI_OK) {
        IMSA_HILOGE("get null failed.");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    ani_wref wref;
    if (env->WeakReference_Create(nullRef, &wref) != ANI_OK) {
        IMSA_HILOGE("create ref failed.");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    ani_ref ref;
    ani_boolean wasReleased;
    if (env->WeakReference_GetReference(wref, &wasReleased, &ref) != ANI_OK) {
        IMSA_HILOGE("get ref failed.");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    auto obj = reinterpret_cast<ani_fn_object>(ref);
    ani_ref result;
    if (env->FunctionalObject_Call(obj, 0, nullptr, &result) != ANI_OK) {
        IMSA_HILOGE("OnTerminated functionalObject_Call failed");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    return ErrorCode::NO_ERROR;
}

int32_t AniMessageHandler::OnMessage(const ArrayBuffer &arrayBuffer)
{
    std::lock_guard<decltype(callbackObjectMutex_)> lock(callbackObjectMutex_);
    if (aniMessageHandler_ == nullptr) {
        IMSA_HILOGE("MessageHandler was not regist!.");
        return ErrorCode::ERROR_MSG_HANDLER_NOT_REGIST;
    }
    if (!ArrayBuffer::IsSizeValid(arrayBuffer)) {
        IMSA_HILOGE("msgId limit 256B and msgParam limit 128KB.");
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    if (vm_ == nullptr) {
        IMSA_HILOGE("vm is nullptr, can not call OnMessage!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    ani_env* env = AttachAniEnv(vm_);
    if (env == nullptr) {
        IMSA_HILOGE("env is nullptr, can not call OnMessage!");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    ani_ref nullRef;
    if (env->GetNull(&nullRef) != ANI_OK) {
        return ErrorCode::ERROR_NULL_POINTER;
    }
    ani_wref wref;
    if (env->WeakReference_Create(nullRef, &wref) != ANI_OK) {
        IMSA_HILOGE("create ref failed.");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    ani_ref ref;
    ani_boolean wasReleased;
    if (env->WeakReference_GetReference(wref, &wasReleased, &ref) != ANI_OK) {
        IMSA_HILOGE("get ref failed.");
        return ErrorCode::ERROR_NULL_POINTER;
    }

    auto obj = reinterpret_cast<ani_fn_object>(ref);
    ani_ref result;
    std::vector<ani_ref> tmp;
    ani_string msgIdArgs;
    env->String_NewUTF8(arrayBuffer.msgId.c_str(), arrayBuffer.msgId.size(), &msgIdArgs);
    auto msgParamArgs = EnumConvert::Uint8ArrayToObject(env, arrayBuffer.msgParam);

    tmp.push_back(reinterpret_cast<ani_ref>(msgIdArgs));
    if (arrayBuffer.jsArgc > ARGC_ONE) {
        tmp.push_back(reinterpret_cast<ani_ref>(msgParamArgs));
    }
    if (env->FunctionalObject_Call(obj, tmp.size(), tmp.data(), &result) != ANI_OK) {
        IMSA_HILOGE("OnMessage functionalObject_Call failed");
        return ErrorCode::ERROR_NULL_POINTER;
    }
    return ErrorCode::NO_ERROR;
}
} // namespace MiscServices
} // namespace OHOS