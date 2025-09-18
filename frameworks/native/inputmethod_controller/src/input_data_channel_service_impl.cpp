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

#include "input_data_channel_service_impl.h"

#include "global.h"
#include "input_method_controller.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "itypes_util.h"
#include "message.h"
#include "input_method_tools.h"
#include "input_method_agent_proxy.h"
namespace OHOS {
namespace MiscServices {
InputDataChannelServiceImpl::InputDataChannelServiceImpl() {}

InputDataChannelServiceImpl::~InputDataChannelServiceImpl() {}
// LCOV_EXCL_START
ErrCode InputDataChannelServiceImpl::InsertText(
    const std::string &text, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    IMSA_HILOGD("start.");
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    int32_t ret = instance->InsertText(Str8ToStr16(text));
    ResponseDataChannel(agent, msgId, ret);
    IMSA_HILOGD("end.");
    return ret;
}

ErrCode InputDataChannelServiceImpl::DeleteForward(int32_t length, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    int32_t ret = instance->DeleteForward(length);
    ResponseDataChannel(agent, msgId, ret);
    return ret;
}

ErrCode InputDataChannelServiceImpl::DeleteBackward(int32_t length, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    int32_t ret = instance->DeleteBackward(length);
    ResponseDataChannel(agent, msgId, ret);
    return ret;
}

ErrCode InputDataChannelServiceImpl::GetTextBeforeCursor(
    int32_t number, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    std::u16string text;
    ResponseData data = Str16ToStr8(text);
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL, data);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    int32_t ret = instance->GetLeft(number, text);
    data = Str16ToStr8(text);
    ResponseDataChannel(agent, msgId, ret, data);
    return ret;
}

ErrCode InputDataChannelServiceImpl::GetTextAfterCursor(
    int32_t number, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    std::u16string text;
    ResponseData data = Str16ToStr8(text);
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL, data);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    auto ret = instance->GetRight(number, text);
    data = Str16ToStr8(text);
    ResponseDataChannel(agent, msgId, ret, data);
    return ret;
}

ErrCode InputDataChannelServiceImpl::GetTextIndexAtCursor(uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    int32_t index = 0;
    ResponseData data = index;
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL, data);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    auto ret = instance->GetTextIndexAtCursor(index);
    data = index;
    ResponseDataChannel(agent, msgId, ret, data);
    return ret;
}
// LCOV_EXCL_STOP
ErrCode InputDataChannelServiceImpl::GetEnterKeyType(int32_t &keyType)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        return ErrorCode::ERROR_EX_NULL_POINTER;
    }
    return instance->GetEnterKeyType(keyType);
}

ErrCode InputDataChannelServiceImpl::GetInputPattern(int32_t &inputPattern)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        return ErrorCode::ERROR_EX_NULL_POINTER;
    }
    return instance->GetInputPattern(inputPattern);
}

ErrCode InputDataChannelServiceImpl::GetTextConfig(TextTotalConfigInner &textConfigInner)
{
    TextTotalConfig textConfig = InputMethodTools::GetInstance().InnerToTextTotalConfig(textConfigInner);

    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        return ErrorCode::ERROR_EX_NULL_POINTER;
    }
    auto ret = instance->GetTextConfig(textConfig);
    textConfigInner = InputMethodTools::GetInstance().TextTotalConfigToInner(textConfig);
    return ret;
}

ErrCode InputDataChannelServiceImpl::SendKeyboardStatus(int32_t status)
{
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        instance->SendKeyboardStatus(static_cast<KeyboardStatus>(status));
    } else {
        IMSA_HILOGE("failed to get InputMethodController instance!");
    }
    return ERR_OK;
}
// LCOV_EXCL_START
ErrCode InputDataChannelServiceImpl::SendFunctionKey(int32_t funcKey, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    auto ret = instance->SendFunctionKey(funcKey);
    ResponseDataChannel(agent, msgId, ret);
    return ret;
}

ErrCode InputDataChannelServiceImpl::MoveCursor(int32_t keyCode, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    auto ret = instance->MoveCursor(static_cast<Direction>(keyCode));
    ResponseDataChannel(agent, msgId, ret);
    return ret;
}

ErrCode InputDataChannelServiceImpl::SelectByRange(
    int32_t start, int32_t end, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }

    instance->SelectByRange(start, end);
    ResponseDataChannel(agent, msgId, ErrorCode::NO_ERROR);
    return ERR_OK;
}

ErrCode InputDataChannelServiceImpl::SelectByMovement(
    int32_t direction, int32_t cursorMoveSkip, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGW("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    instance->SelectByMovement(direction, cursorMoveSkip);
    ResponseDataChannel(agent, msgId, ErrorCode::NO_ERROR);
    return ERR_OK;
}

ErrCode InputDataChannelServiceImpl::HandleExtendAction(
    int32_t action, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    auto ret = instance->HandleExtendAction(action);
    ResponseDataChannel(agent, msgId, ret);
    return ret;
}
// LCOV_EXCL_STOP
ErrCode InputDataChannelServiceImpl::NotifyPanelStatusInfo(const PanelStatusInfoInner &info)
{
    PanelStatusInfo panelStatusInfo = InputMethodTools::GetInstance().InnerToPanelStatusInfo(info);
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        instance->NotifyPanelStatusInfo(panelStatusInfo);
    } else {
        IMSA_HILOGW("failed to get InputMethodController instance!");
    }
    return ERR_OK;
}

ErrCode InputDataChannelServiceImpl::NotifyKeyboardHeight(uint32_t height)
{
    auto instance = InputMethodController::GetInstance();
    if (instance != nullptr) {
        instance->NotifyKeyboardHeight(height);
    } else {
        IMSA_HILOGW("failed to get InputMethodController instance!");
    }
    return ERR_OK;
}

ErrCode InputDataChannelServiceImpl::SendPrivateCommand(const Value &value)
{
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    privateCommand = value.valueMap;
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        return ErrorCode::ERROR_EX_NULL_POINTER;
    }
    return instance->ReceivePrivateCommand(privateCommand);
}
// LCOV_EXCL_START
ErrCode InputDataChannelServiceImpl::SetPreviewText(
    const std::string &text, const RangeInner &rangeInner, uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    Range range = InputMethodTools::GetInstance().InnerToRange(rangeInner);
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    auto ret = instance->SetPreviewText(text, range);
    ResponseDataChannel(agent, msgId, ret);
    return ret;
}

ErrCode InputDataChannelServiceImpl::FinishTextPreview(uint64_t msgId, const sptr<IRemoteObject> &agent)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        ResponseDataChannel(agent, msgId, ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL);
        return ErrorCode::ERROR_IMA_DATA_CHANNEL_ABNORMAL;
    }
    auto ret = instance->FinishTextPreview();
    ResponseDataChannel(agent, msgId, ret);
    return ret;
}
// LCOV_EXCL_STOP
ErrCode InputDataChannelServiceImpl::SendMessage(const ArrayBuffer &arraybuffer)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        return ErrorCode::ERROR_EX_NULL_POINTER;
    }
    return instance->RecvMessage(arraybuffer);
}

ErrCode InputDataChannelServiceImpl::HandleKeyEventResult(uint64_t cbId, bool consumeResult)
{
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        return ErrorCode::ERROR_EX_NULL_POINTER;
    }
    instance->HandleKeyEventResult(cbId, consumeResult);
    return ERR_OK;
}

int32_t InputDataChannelServiceImpl::ResponseDataChannel(
    const sptr<IRemoteObject> &agentObject, uint64_t msgId, int32_t code, const ResponseData &data)
{
    if (agentObject == nullptr) {
        IMSA_HILOGE("agentObject is nullptr!");
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }
    auto agent = std::make_shared<InputMethodAgentProxy>(agentObject);
    ResponseDataInner inner;
    inner.rspData = data;
    return agent->ResponseDataChannel(msgId, code, inner);
}
} // namespace MiscServices
} // namespace OHOS