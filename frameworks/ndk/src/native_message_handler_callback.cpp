/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "native_message_handler_callback.h"
#include "string_ex.h"

namespace OHOS {
namespace MiscServices {
int32_t NativeMessageHandlerCallback::OnTerminated()
{
    auto handler = messageHandler_.lock();
    if (handler != nullptr) {
        handler = NativeObjectRegistry<InputMethod_MessageHandlerProxy>::GetInstance().Get(handler.get());
    }
    if (handler == nullptr) {
        IMSA_HILOGE("Message handler is unregistered or destroyed.");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }

    auto callback = handler->onTerminatedFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("onTerminatedFunc is nullptr");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }

    auto ret = callback(handler.get());
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("onTerminatedFunc execute failed! ret: %{public}d", ret);
        return ErrorCode::ERROR_MESSAGE_HANDLER;
    }
    return ErrorCode::NO_ERROR;
}

int32_t NativeMessageHandlerCallback::OnMessage(const ArrayBuffer &arrayBuffer)
{
    auto handler = messageHandler_.lock();
    if (handler != nullptr) {
        handler = NativeObjectRegistry<InputMethod_MessageHandlerProxy>::GetInstance().Get(handler.get());
    }
    if (handler == nullptr) {
        IMSA_HILOGE("Message handler is unregistered or destroyed.");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }

    auto callback = handler->onMessageFunc.load();
    if (callback == nullptr) {
        IMSA_HILOGE("onMessageFunc is nullptr");
        return ErrorCode::ERROR_CLIENT_NULL_POINTER;
    }
    std::u16string msgIdStr16 = Str8ToStr16(arrayBuffer.msgId);
    auto ret = callback(handler.get(), msgIdStr16.c_str(), msgIdStr16.length(), arrayBuffer.msgParam.data(),
        arrayBuffer.msgParam.size());
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("onMessageFunc execute failed! ret: %{public}d", ret);
        return ErrorCode::ERROR_MESSAGE_HANDLER;
    }
    return ErrorCode::NO_ERROR;
}
} // namespace MiscServices
} // namespace OHOS