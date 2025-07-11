/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "input_data_channel_proxy_wrap.h"

#include <cinttypes>
#include <string>

#include "global.h"
#include "input_method_tools.h"
#include "string_ex.h"
#include "variant_util.h"

namespace OHOS {
namespace MiscServices {
constexpr std::size_t MESSAGE_UNANSWERED_MAX_NUMBER = 1000;
InputDataChannelProxyWrap::InputDataChannelProxyWrap(
    const std::shared_ptr<InputDataChannelProxy> &channel, const sptr<IRemoteObject> &agentObject)
{
    auto now = std::chrono::steady_clock::now();
    auto duration = now.time_since_epoch();
    msgId_ = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(duration).count());
    msgId_ = msgId_ ? msgId_ : ++msgId_;
    channel_ = channel;
    agentObject_ = agentObject;
}

InputDataChannelProxyWrap::~InputDataChannelProxyWrap()
{
}

int32_t InputDataChannelProxyWrap::InsertText(const std::string &text, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, text](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->InsertText(text, msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::DeleteForward(int32_t length, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, length](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->DeleteForward(length, msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::DeleteBackward(int32_t length, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, length](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->DeleteBackward(length, msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::GetTextBeforeCursor(
    int32_t number, std::string &text, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, number](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->GetTextBeforeCursor(number, msgId, agentObject);
    };
    SyncOutput output = nullptr;
    if (callback == nullptr) {
        output = [&text](const ResponseData &data) -> void { VariantUtil::GetValue(data, text); };
    }
    return Request(callback, work, callback == nullptr, output);
}

int32_t InputDataChannelProxyWrap::GetTextAfterCursor(
    int32_t number, std::string &text, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, number, text](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->GetTextAfterCursor(number, msgId, agentObject);
    };
    SyncOutput output = nullptr;
    if (callback == nullptr) {
        output = [&text](const ResponseData &data) -> void { VariantUtil::GetValue(data, text); };
    }
    return Request(callback, work, callback == nullptr, output);
}

int32_t InputDataChannelProxyWrap::SendFunctionKey(int32_t funcKey, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, funcKey](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->SendFunctionKey(funcKey, msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::MoveCursor(int32_t keyCode, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, keyCode](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->MoveCursor(keyCode, msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::SelectByRange(int32_t start, int32_t end, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, start, end](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->SelectByRange(start, end, msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::SelectByMovement(
    int32_t direction, int32_t cursorMoveSkip, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, direction, cursorMoveSkip](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->SelectByMovement(direction, cursorMoveSkip, msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::HandleExtendAction(int32_t action, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, action](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->HandleExtendAction(action, msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::GetTextIndexAtCursor(int32_t &index, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->GetTextIndexAtCursor(msgId, agentObject);
    };
    SyncOutput output = nullptr;
    if (callback == nullptr) {
        output = [&index](const ResponseData &data) -> void { VariantUtil::GetValue(data, index); };
    }
    return Request(callback, work, callback == nullptr, output);
}

int32_t InputDataChannelProxyWrap::SetPreviewText(
    const std::string &text, const RangeInner &range, const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_, text, range](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->SetPreviewText(text, range, msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::FinishTextPreview(const AsyncIpcCallBack &callback)
{
    auto work = [agentObject = agentObject_](
                    uint64_t msgId, const std::shared_ptr<InputDataChannelProxy> &channel) -> int32_t {
        return channel->FinishTextPreview(msgId, agentObject);
    };
    return Request(callback, work, callback == nullptr);
}

int32_t InputDataChannelProxyWrap::Request(
    const AsyncIpcCallBack &callback, const ChannelWork &work, bool isSync, const SyncOutput &output)
{
    auto channel = GetDataChannel();
    if (channel == nullptr) {
        IMSA_HILOGE("data channel is nullptr!");
        return ErrorCode::ERROR_IMA_CHANNEL_NULLPTR;
    }
    auto handler = AddRspHandler(callback, isSync);
    if (handler == nullptr) {
        IMSA_HILOGE("add rsp handler failed.");
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    auto ret = work(handler->msgId_, channel);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("work error: %{public}d.", ret);
        DeleteRspHandler(handler->msgId_);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    if (handler->syncBlockData_ != nullptr) {
        return WaitResponse(handler, output);
    }
    return ErrorCode::NO_ERROR;
}

std::shared_ptr<InputDataChannelProxy> InputDataChannelProxyWrap::GetDataChannel()
{
    std::lock_guard<std::mutex> lock(channelMutex_);
    return channel_;
}

uint64_t InputDataChannelProxyWrap::GenerateMsgId()
{
    return ++msgId_ ? msgId_ : ++msgId_;
}

std::shared_ptr<ResponseHandler> InputDataChannelProxyWrap::AddRspHandler(const AsyncIpcCallBack &callback, bool isSync)
{
    std::lock_guard<std::mutex> lock(rspMutex_);
    if (rspHandlers_.size() >= MESSAGE_UNANSWERED_MAX_NUMBER) {
        IMSA_HILOGW("too many unanswered, data channel abnormal");
        return nullptr;
    }
    auto msgId = GenerateMsgId();
    auto handler = std::make_shared<ResponseHandler>(msgId, isSync, callback);
    rspHandlers_.insert({ msgId, handler });
    return handler;
}

int32_t InputDataChannelProxyWrap::ClearRspHandlers()
{
    std::lock_guard<std::mutex> lock(rspMutex_);
    ResponseInfo rspInfo = { ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL, std::monostate{} };
    for (const auto &handler : rspHandlers_) {
        if (handler.second == nullptr) {
            continue;
        }
        if (handler.second->syncBlockData_ != nullptr) {
            handler.second->syncBlockData_->SetValue(rspInfo);
            continue;
        }
        if (handler.second->asyncCallback_ != nullptr) {
            handler.second->asyncCallback_(rspInfo.dealRet_, rspInfo.data_);
        }
    }
    rspHandlers_.clear();
    return ErrorCode::NO_ERROR;
}

int32_t InputDataChannelProxyWrap::HandleResponse(uint64_t msgId, const ResponseInfo &rspInfo)
{
    std::lock_guard<std::mutex> lock(rspMutex_);
    auto it = rspHandlers_.find(msgId);
    if (it == rspHandlers_.end()) {
        return ErrorCode::NO_ERROR;
    }
    if (it->second == nullptr) {
        rspHandlers_.erase(it);
        return ErrorCode::NO_ERROR;
    }
    if (it->second->syncBlockData_ != nullptr) {
        it->second->syncBlockData_->SetValue(rspInfo);
    }
    if (it->second->asyncCallback_ != nullptr) {
        it->second->asyncCallback_(rspInfo.dealRet_, rspInfo.data_);
    }
    rspHandlers_.erase(it);
    return ErrorCode::NO_ERROR;
}

int32_t InputDataChannelProxyWrap::WaitResponse(
    const std::shared_ptr<ResponseHandler> &handler, const SyncOutput &output)
{
    if (handler == nullptr || handler->syncBlockData_ == nullptr) {
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    ResponseInfo rspInfo = handler->syncBlockData_->GetValueWithoutTimeout();
    IMSA_HILOGD("rsp info id: %{public}" PRIu64 " ret: %{public}d", handler->msgId_, rspInfo.dealRet_);
    if (rspInfo.dealRet_ != ErrorCode::NO_ERROR) {
        return rspInfo.dealRet_;
    }
    if (output != nullptr) {
        output(rspInfo.data_);
    }
    return ErrorCode::NO_ERROR;
}

int32_t InputDataChannelProxyWrap::DeleteRspHandler(uint64_t msgId)
{
    std::lock_guard<std::mutex> lock(rspMutex_);
    auto it = rspHandlers_.find(msgId);
    if (it != rspHandlers_.end()) {
        rspHandlers_.erase(it);
    }
    return ErrorCode::NO_ERROR;
}
} // namespace MiscServices
} // namespace OHOS