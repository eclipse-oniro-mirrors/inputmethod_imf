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
#ifndef ANI_MESSAGE_HANDLER_H
#define ANI_MESSAGE_HANDLER_H

#include <mutex>
#include "msg_handler_callback_interface.h"
#include "ani_callback_object.h"
#include "ohos.inputMethod.proj.hpp"
#include "ohos.inputMethod.impl.hpp"
#include "taihe/runtime.hpp"
#include "ani.h"

namespace OHOS {
namespace MiscServices {
class AniMessageHandler : public MsgHandlerCallbackInterface {
public:
    explicit AniMessageHandler(ani_vm* vm, ani_object onTerminated, ani_object onMessage)
        : aniMessageHandler_(std::make_shared<AniMsgHandlerCallbackObject>(vm, onTerminated, onMessage)), vm_(vm) {};
    virtual ~AniMessageHandler() {};
    int32_t OnTerminated() override;
    int32_t OnMessage(const ArrayBuffer &arrayBuffer) override;
private:
    ani_env* AttachAniEnv(ani_vm* vm);
    std::mutex callbackObjectMutex_;
    std::shared_ptr<AniMsgHandlerCallbackObject> aniMessageHandler_ = nullptr;
    ani_vm* vm_ = nullptr;
};
} // namespace MiscServices
} // namespace OHOS
#endif // ANI_MESSAGE_HANDLER_H