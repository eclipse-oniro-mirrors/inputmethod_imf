/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "peruser_session.h"
#include "unistd.h"
#include "platform.h"
#include "parcel.h"
#include "message_parcel.h"
#include "utils.h"
#include "want.h"
#include "input_method_ability_connection_stub.h"
#include <vector>
#include "ability_connect_callback_proxy.h"
#include "ability_manager_interface.h"
#include "sa_mgr_client.h"
#include "element_name.h"
#include "system_ability_definition.h"
#include "input_client_proxy.h"
#include "input_data_channel_proxy.h"
#include "input_control_channel_proxy.h"
#include "ipc_skeleton.h"
#include "input_method_core_proxy.h"
#include "input_method_agent_proxy.h"
#include "para_handle.h"

namespace OHOS {
namespace MiscServices {
    using namespace MessageID;
    /*! Constructor
    \param userId the id of the given user
    \param msgId the msg id can be MessageID::MSG_ID_CLIENT_DIED (to monitor input client)
    \n or MessageID::MSG_ID_IMS_DIED (to monitor input method service)
    */
    RemoteObjectDeathRecipient::RemoteObjectDeathRecipient(int userId, int msgId)
    {
        userId_ = userId;
        msgId_ = msgId;
    }

    RemoteObjectDeathRecipient::~RemoteObjectDeathRecipient()
    {
    }

    /*! Notify that a remote object died.
    \n It's called when the linked remote object died.
    \param who the IRemoteObject handler of the remote object died.
    */
    void RemoteObjectDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &who)
    {
        auto parcel = new (std::nothrow) MessageParcel();
        if (parcel == nullptr) {
            IMSA_HILOGE("parcel is nullptr");
            return;
        }
        parcel->WriteInt32(userId_);
        parcel->WritePointer(reinterpret_cast<uintptr_t>(who.GetRefPtr()));
        auto msg = new (std::nothrow) Message(msgId_, parcel);
        if (msg == nullptr) {
            IMSA_HILOGE("msg is nullptr");
            return;
        }
        MessageHandler::Instance()->SendMessage(msg);
    }

    /*! Constructor
    \param userId the user id of this user whose session are managed by this instance of PerUserSession.
    */
    PerUserSession::PerUserSession(int userId)
    {
        userState = UserState::USER_STATE_STARTED;
        userId_ = userId;
        currentIme[0] = nullptr;
        currentIme[1] = nullptr;

        needReshowClient = nullptr;

        imsDeathRecipient = new RemoteObjectDeathRecipient(userId, MSG_ID_IMS_DIED);
    }

    /*! Destructor
    */
    PerUserSession::~PerUserSession()
    {
        if (userState == UserState::USER_STATE_UNLOCKED) {
            OnUserLocked();
        }
        imsDeathRecipient = nullptr;
        if (workThreadHandler.joinable()) {
            workThreadHandler.join();
        }
    }


    /*! Create work thread for this user
    \param handle message handle to receive the message
    */
    void PerUserSession::CreateWorkThread(MessageHandler& handler)
    {
        msgHandler = &handler;
        workThreadHandler = std::thread([this] {WorkThread();});
    }

    /*! Wait till work thread exits
    */
    void PerUserSession::JoinWorkThread()
    {
        if (workThreadHandler.joinable()) {
            workThreadHandler.join();
        }
    }

    /*! Work thread for this user
    */
    void PerUserSession::WorkThread()
    {
        if (!msgHandler) {
            return;
        }
        while (1) {
            Message *msg = msgHandler->GetMessage();
            std::unique_lock<std::mutex> lock(mtx);
            switch (msg->msgId_) {
                case MSG_ID_USER_LOCK:
                case MSG_ID_EXIT_SERVICE: {
                    OnUserLocked();
                    delete msg;
                    msg = nullptr;
                    return;
                }
                case MSG_ID_PREPARE_INPUT: {
                    OnPrepareInput(msg);
                    break;
                }
                case MSG_ID_RELEASE_INPUT: {
                    OnReleaseInput(msg);
                    break;
                }
                case MSG_ID_START_INPUT: {
                    OnStartInput(msg);
                    break;
                }
                case MSG_ID_STOP_INPUT: {
                    OnStopInput(msg);
                    break;
                }
                case MSG_ID_SET_CORE_AND_AGENT: {
                    SetCoreAndAgent(msg);
                    break;
                }
                case MSG_ID_CLIENT_DIED: {
                    auto *who = reinterpret_cast<IRemoteObject *>(msg->msgContent_->ReadPointer());
                    if (who == nullptr) {
                        IMSA_HILOGE("who is nullptr");
                        break;
                    }
                    OnClientDied(who);
                    break;
                }
                case MSG_ID_IMS_DIED: {
                    auto *who = reinterpret_cast<IRemoteObject *>(msg->msgContent_->ReadPointer());
                    if (who == nullptr) {
                        IMSA_HILOGE("who is nullptr");
                        break;
                    }
                    OnImsDied(who);
                    break;
                }
                case MSG_ID_HIDE_KEYBOARD_SELF: {
                    int flag = msg->msgContent_->ReadInt32();
                    OnHideKeyboardSelf(flag);
                    break;
                }
                case MSG_ID_ADVANCE_TO_NEXT: {
                    OnAdvanceToNext();
                    break;
                }
                case MSG_ID_SET_DISPLAY_MODE: {
                    int mode = msg->msgContent_->ReadInt32();
                    OnSetDisplayMode(mode);
                    break;
                }
                case MSG_ID_RESTART_IMS: {
                    int index = msg->msgContent_->ReadInt32();
                    std::u16string imeId = msg->msgContent_->ReadString16();
                    OnRestartIms(index, imeId);
                    break;
                }
                case MSG_HIDE_CURRENT_INPUT: {
                    OnHideKeyboardSelf(0);
                    break;
                }
                case MSG_SHOW_CURRENT_INPUT: {
                    OnShowKeyboardSelf();
                    break;
                }
                default: {
                    break;
                }
            }
            delete msg;
            msg = nullptr;
        }
    }

    /*! Set display Id
    \param displayId the Id of display screen on which the input method keyboard show.
    */
    void PerUserSession::SetDisplayId(int displayId)
    {
        this->displayId = displayId;
    }

    /*! Set the current input method engine
    \param ime the current (default) IME pointer referred to the instance in PerUserSetting.
    */
    void PerUserSession::SetCurrentIme(InputMethodProperty *ime)
    {
        currentIme[DEFAULT_IME] = ime;
        userState = UserState::USER_STATE_UNLOCKED;
    }

    /*! Set the system security input method engine
    \param ime system security IME pointer referred to the instance in PerUserSetting.
    */
    void PerUserSession::SetSecurityIme(InputMethodProperty *ime)
    {
        currentIme[SECURITY_IME] = ime;
    }

    /*! Set the input method setting data
    \param setting InputMethodSetting pointer referred to the instance in PerUserSetting.
    */
    void PerUserSession::SetInputMethodSetting(InputMethodSetting *setting)
    {
        inputMethodSetting = setting;
    }

    /*! Reset input method engine
    \param defaultIme default ime pointer referred to the instance in PerUserSetting
    \param  security security ime pointer referred to the instance in PerUserSetting
    \n Two input method engines can be running at the same time for one user.
    \n One is the default ime, another is security ime
    */
    void PerUserSession::ResetIme(InputMethodProperty *defaultIme, InputMethodProperty *securityIme)
    {
        IMSA_HILOGI("PerUserSession::ResetIme");
        std::unique_lock<std::mutex> lock(mtx);
        InputMethodProperty *ime[] = {defaultIme, securityIme};
        for (int i = 0; i < MIN_IME; i++) {
            if (currentIme[i] == ime[i] && ime[i]) {
                continue;
            }
            if (imsCore[i]) {
                StopInputMethod(i);
            }
            ResetImeError(i);
            currentIme[i] = ime[i];
            if (!currentIme[i]) {
                if (needReshowClient && GetImeIndex(needReshowClient) == i) {
                    needReshowClient = nullptr;
                }
                continue;
            }

            std::map<IRemoteObject *, ClientInfo *>::const_iterator it;
            bool flag = false;
            for (it = mapClients.cbegin(); it != mapClients.cend(); ++it) {
                if ((i == DEFAULT_IME && !it->second->attribute.GetSecurityFlag()) ||
                        (i == SECURITY_IME && it->second->attribute.GetSecurityFlag())) {
                    flag = true;
                    break;
                }
            }
            if (flag) {
                int ret = StartInputMethod(i);
                if (ret != ErrorCode::NO_ERROR) {
                    needReshowClient = nullptr;
                    break;
                }
                if (needReshowClient && GetImeIndex(needReshowClient) == i) {
                    ShowKeyboard(needReshowClient, true);
                    needReshowClient = nullptr;
                }
            }
        }
    }

    /*! Called when a package is removed
    \param packageName the name of package removed
    */
    void PerUserSession::OnPackageRemoved(const std::u16string& packageName)
    {
        IMSA_HILOGI("PerUserSession::OnPackageRemoved");
        InputMethodSetting tmpSetting;
        bool flag = false;
        std::unique_lock<std::mutex> lock(mtx);
        for (int i = 0; i < MAX_IME; i++) {
            if (currentIme[i] && currentIme[i]->mPackageName == packageName) {
                if (currentClient && GetImeIndex(currentClient) == i) {
                    needReshowClient = currentClient;
                    HideKeyboard(currentClient);
                }
                StopInputMethod(i);
                currentIme[i] = nullptr;
                if (i == DEFAULT_IME) {
                    tmpSetting.SetCurrentKeyboardType(-1);
                    inputMethodSetting->SetCurrentKeyboardType(-1);
                } else if (i == SECURITY_IME) {
                    tmpSetting.SetCurrentSysKeyboardType(-1);
                    inputMethodSetting->SetCurrentSysKeyboardType(-1);
                }
                currentKbdIndex[i] = 0;
                flag = true;
            }
        }
        if (flag) {
            Platform::Instance()->SetInputMethodSetting(userId_, tmpSetting);
        }
    }

    /*! Add an input client
    \param pid the process pid of the input client
    \param uid the uid of the the input client
    \param displayId the display id of the input client
    \param inputClient the remote object handler of the input client
    \param channel the remote InputDataChannel object handler for the input client.
    \n It will be transferred to input method service
    \param attribute the input attribute of the input client.
    \return \li ErrorCode::NO_ERROR no error
    \return \li ErrorCode::ERROR_CLIENT_DUPLICATED client is duplicated
    */
    int PerUserSession::AddClient(int pid, int uid, int displayId, const sptr<IInputClient> &inputClient,
        const sptr<IInputDataChannel> &channel, const InputAttribute &attribute)
    {
        IMSA_HILOGI("PerUserSession::AddClient");
        ClientInfo *clientInfo = GetClientInfo(inputClient);
        if (clientInfo != nullptr) {
            IMSA_HILOGE("PerUserSession::AddClient clientInfo is exist, not need add.");
            return ErrorCode::NO_ERROR;
        }

        sptr<IRemoteObject> obj = inputClient->AsObject();
        if (obj == nullptr) {
            IMSA_HILOGE("PerUserSession::AddClient inputClient AsObject is nullptr");
            return ErrorCode::ERROR_REMOTE_CLIENT_DIED;
        }
        sptr<RemoteObjectDeathRecipient> clientDeathRecipient = new (std::nothrow)
            RemoteObjectDeathRecipient(Utils::ToUserId(uid), MSG_ID_CLIENT_DIED);
        if (clientDeathRecipient == nullptr) {
            IMSA_HILOGE("clientDeathRecipient is nullptr");
        }
        int ret = obj->AddDeathRecipient(clientDeathRecipient);
        IMSA_HILOGI("Add death recipient %{public}s", ret ? "success" : "failed");

        clientInfo = new (std::nothrow)
            ClientInfo({ pid, uid, userId_, displayId, inputClient, channel, clientDeathRecipient, attribute });
        if (clientInfo == nullptr) {
            IMSA_HILOGE("clientInfo is nullptr");
            return ErrorCode::ERROR_NULL_POINTER;
        }
        mapClients.insert({ obj, clientInfo });
        return ErrorCode::NO_ERROR;
    }

    /*! Remove an input client
    \param inputClient remote object handler of the input client
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_CLIENT_NOT_FOUND client is not found
    */
    int PerUserSession::RemoveClient(const sptr<IRemoteObject> &inputClient)
    {
        IMSA_HILOGE("PerUserSession::RemoveClient");
        auto it = mapClients.find(inputClient);
        if (it == mapClients.end()) {
            IMSA_HILOGE("PerUserSession::RemoveClient client not found");
            return ErrorCode::ERROR_CLIENT_NOT_FOUND;
        }
        ClientInfo *clientInfo = it->second;
        inputClient->RemoveDeathRecipient(clientInfo->deathRecipient);
        delete clientInfo;
        clientInfo = nullptr;
        mapClients.erase(it);
        return ErrorCode::NO_ERROR;
    }

    /*! Start input method service
    \param index it can be 0 or 1. 0 - default ime, 1 - security ime
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_IME_BIND_FAILED failed to bind ime
    \return ErrorCode::ERROR_IME_NOT_AVAILABLE no ime is available
    \return ErrorCode::ERROR_SECURITY_IME_NOT_AVAILABLE no security ime is available
    \return ErrorCode::ERROR_TOKEN_CREATE_FAILED failed to create window token
    \return other errors returned by binder driver
    */
    int PerUserSession::StartInputMethod(int index)
    {
        IMSA_HILOGI("PerUserSession::StartInputMethod index = %{public}d [%{public}d]\n", index, userId_);

        if (!imsCore[index]) {
            IMSA_HILOGI("PerUserSession::StartInputMethod imscore is null");
            return ErrorCode::ERROR_IME_BIND_FAILED;
        }

        sptr<IRemoteObject> b = imsCore[index]->AsObject();
        inputMethodToken[index] = IPCSkeleton::GetInstance().GetContextObject();
        localControlChannel[index] = new InputControlChannelStub(userId_);
        inputControlChannel[index] = localControlChannel[index];
        int ret_init = imsCore[index]->initializeInput(inputMethodToken[index], displayId, inputControlChannel[index]);
        if (ret_init != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("PerUserSession::StartInputMethod initializeInput fail %{public}s", ErrorCode::ToString(ret_init));
            localControlChannel[index] = nullptr;
            inputControlChannel[index] = nullptr;
            return ret_init;
        }
        return ErrorCode::NO_ERROR;
    }

    /*! Stop input method service
    \param index it can be 0 or 1. 0 - default ime, 1 - security ime
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_IME_NOT_STARTED ime not started
    \return ErrorCode::ERROR_IME_UNBIND_FAILED failed to unbind ime
    \return ErrorCode::ERROR_TOKEN_DESTROY_FAILED failed to destroy window token
    \return other errors returned by binder driver
    */
    int PerUserSession::StopInputMethod(int index)
    {
        IMSA_HILOGI("Start... index = %{public}d [%{public}d]\n", index, userId_);
        if (index >= MAX_IME || index < 0) {
            IMSA_HILOGE("Aborted! %{public}s", ErrorCode::ToString(ErrorCode::ERROR_BAD_PARAMETERS));
            return ErrorCode::ERROR_BAD_PARAMETERS;
        }
        if (!imsCore[index] || !currentIme[index]) {
            IMSA_HILOGE("Aborted! %{public}s", ErrorCode::ToString(ErrorCode::ERROR_IME_NOT_STARTED));
            return ErrorCode::ERROR_IME_NOT_STARTED;
        }
        if (currentIme[index] == currentIme[1 - index] && imsCore[1 - index]) {
            imsCore[index] = nullptr;
            inputControlChannel[index] = nullptr;
            localControlChannel[index] = nullptr;
            IMSA_HILOGI("End...[%{public}d]\n", userId_);
            return ErrorCode::NO_ERROR;
        }

        IMSA_HILOGD("unbindInputMethodService...\n");

        IMSA_HILOGD("destroyWindowTaskId...\n");
        int errorCode = ErrorCode::NO_ERROR;
        int ret = Platform::Instance()->DestroyWindowToken(userId_, currentIme[index]->mPackageName);
        inputMethodToken[index] = nullptr;
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("destroyWindowTaskId return : %{public}s [%{public}d]\n", ErrorCode::ToString(ret), userId_);
            errorCode = ErrorCode::ERROR_TOKEN_DESTROY_FAILED;
        }
        sptr<IRemoteObject> b = imsCore[index]->AsObject();
        ret = b->RemoveDeathRecipient(imsDeathRecipient);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("RemoveDeathRecipient return : %{public}s [%{public}d]\n", ErrorCode::ToString(ret), userId_);
        }
        imsCore[index] = nullptr;
        inputControlChannel[index] = nullptr;
        localControlChannel[index] = nullptr;
        IMSA_HILOGI("End...[%{public}d]\n", userId_);
        return errorCode;
    }

    /*! Show keyboard
    \param inputClient the remote object handler of the input client.
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_IME_NOT_STARTED ime not started
    \return ErrorCode::ERROR_KBD_IS_OCCUPIED keyboard is showing by other client
    \return ErrorCode::ERROR_CLIENT_NOT_FOUND the input client is not found
    \return ErrorCode::ERROR_IME_START_FAILED failed to start input method service
    \return ErrorCode::ERROR_KBD_SHOW_FAILED failed to show keyboard
    \return other errors returned by binder driver
    */
    int PerUserSession::ShowKeyboard(const sptr<IInputClient>& inputClient, bool isShowKeyboard)
    {
        IMSA_HILOGI("PerUserSession::ShowKeyboard");
        ClientInfo *clientInfo = GetClientInfo(inputClient);
        int index = GetImeIndex(inputClient);
        if (index == -1 || !clientInfo) {
            IMSA_HILOGE("PerUserSession::ShowKeyboard Aborted! index = -1 or clientInfo is nullptr");
            return ErrorCode::ERROR_CLIENT_NOT_FOUND;
        }

        if (!imsCore[0]) {
            IMSA_HILOGE("PerUserSession::ShowKeyboard Aborted! imsCore[%{public}d] is nullptr", index);
            return ErrorCode::ERROR_NULL_POINTER;
        }

        imsCore[0]->showKeyboard(clientInfo->channel, isShowKeyboard);

        currentClient = inputClient;
        return ErrorCode::NO_ERROR;
    }

    /*! hide keyboard
    \param inputClient the remote object handler of the input client.
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_IME_NOT_STARTED ime not started
    \return ErrorCode::ERROR_KBD_IS_NOT_SHOWING keyboard has not been showing
    \return ErrorCode::ERROR_CLIENT_NOT_FOUND the input client is not found
    \return ErrorCode::ERROR_KBD_HIDE_FAILED failed to hide keyboard
    \return other errors returned by binder driver
    */
    int PerUserSession::HideKeyboard(const sptr<IInputClient>& inputClient)
    {
        IMSA_HILOGI("PerUserSession::HideKeyboard");
        int index = GetImeIndex(inputClient);
        if (index == -1) {
            IMSA_HILOGE("PerUserSession::HideKeyboard Aborted! ErrorCode::ERROR_CLIENT_NOT_FOUND");
            return ErrorCode::ERROR_CLIENT_NOT_FOUND;
        }
        ClientInfo *clientInfo = GetClientInfo(inputClient);
        if (!clientInfo) {
            IMSA_HILOGE("PerUserSession::HideKeyboard GetClientInfo pointer nullptr");
        }
        if (!imsCore[0]) {
            IMSA_HILOGE("PerUserSession::HideKeyboard imsCore[index] is nullptr");
            return ErrorCode::ERROR_IME_NOT_STARTED;
        }

        bool ret = imsCore[0]->hideKeyboard(1);
        if (!ret) {
            IMSA_HILOGE("PerUserSession::HideKeyboard [imsCore->hideKeyboard] failed");
            return ErrorCode::ERROR_KBD_HIDE_FAILED;
        }

        return ErrorCode::NO_ERROR;
    }

    /*! Get the display mode of the current keyboard showing
    \return return display mode.
    \n 0 - part screen mode, 1 - full screen mode
    */
    int PerUserSession::GetDisplayMode()
    {
        return currentDisplayMode;
    }

    /*! Get the keyboard window height
    \param[out] retHeight the height of keyboard window showing or showed returned to caller
    \return ErrorCode
    */
    int PerUserSession::GetKeyboardWindowHeight(int &retHeight)
    {
        if (imsCore[lastImeIndex]) {
            int ret = imsCore[lastImeIndex]->getKeyboardWindowHeight(retHeight);
            if (ret != ErrorCode::NO_ERROR) {
                IMSA_HILOGE("getKeyboardWindowHeight return : %{public}s", ErrorCode::ToString(ret));
            }
            return ret;
        }
        IMSA_HILOGW("No IME is started [%{public}d]\n", userId_);
        return ErrorCode::ERROR_IME_NOT_STARTED;
    }

    /*! Get the current keyboard type
    \return return the pointer of the object of current keyboard type.
    \n null if no keyboard type supported by the current ime.
    \note The returned pointer should NOT be freed by the caller.
    */
    KeyboardType *PerUserSession::GetCurrentKeyboardType()
    {
        if (!inputMethodSetting || !currentIme[DEFAULT_IME]) {
            IMSA_HILOGI("Ime has not started ! [%{public}d]\n", userId_);
            return nullptr;
        }
        if (currentIme[DEFAULT_IME] == currentIme[SECURITY_IME]) {
            return nullptr;
        }
        int hashCode = inputMethodSetting->GetCurrentKeyboardType();  // To be checked.
        if (hashCode == -1) {
            std::vector<int> hashCodeList = inputMethodSetting->GetEnabledKeyboardTypes(currentIme[DEFAULT_IME]->mImeId);
            if (!hashCodeList.size()) {
                IMSA_HILOGE("Cannot find any keyboard types for the current ime [%{public}d]\n", userId_);
                return nullptr;
            }
            hashCode = hashCodeList[0];
        }

        for (int i = 0; i < (int)currentIme[DEFAULT_IME]->mTypes.size(); i++) {
            if (currentIme[DEFAULT_IME]->mTypes[i]->getHashCode() == hashCode) {
                return currentIme[DEFAULT_IME]->mTypes[i];
            }
        }
        return nullptr;
    }

    /*! Handle the situation a remote input client died\n
    It's called when a remote input client died
    \param who the remote object handler of the input client died.
    */
    void PerUserSession::OnClientDied(IRemoteObject *who)
    {
        IMSA_HILOGI("PerUserSession::OnClientDied Start...[%{public}d]\n", userId_);
        auto it = mapClients.find(who);
        if (it == mapClients.end()) {
            IMSA_HILOGE("PerUserSession::RemoveClient client not found");
            return;
        }
        if (it->first == currentClient->AsObject()) {
            int ret = HideKeyboard(currentClient);
            if (ret != ErrorCode::NO_ERROR) {
                IMSA_HILOGE("hide keyboard failed: %{public}s", ErrorCode::ToString(ret));
            }
        }
        int ret = RemoveClient(it->first);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("remove client failed: %{public}s", ErrorCode::ToString(ret));
        }
    }

    /*! Handle the situation a input method service died\n
    It's called when an input method service died
    \param who the remote object handler of input method service who died.
    */
    void PerUserSession::OnImsDied(IRemoteObject *who)
    {
        (void)who;
        IMSA_HILOGI("Start...[%{public}d]\n", userId_);
        int index = 0;
        for (int i = 0; i < MAX_IME; i++) {
            if (imsCore[i] == nullptr) {
                continue;
            }
            auto b = imsCore[i]->AsObject();
            if (b.GetRefPtr() == who) {
                index = i;
                break;
            }
        }
        ClearImeData(index);
        if (!IsRestartIme(index)) {
            IMSA_HILOGI("Restart ime over max num");
            return;
        }
        IMSA_HILOGI("IME died. Restart input method...[%{public}d]\n", userId_);
        const auto &ime = ParaHandle::GetDefaultIme(userId_);
        auto *parcel = new (std::nothrow) MessageParcel();
        if (parcel == nullptr) {
            IMSA_HILOGE("parcel is nullptr");
            return;
        }
        parcel->WriteString(ime);
        auto *msg = new (std::nothrow) Message(MSG_ID_START_INPUT_SERVICE, parcel);
        if (msg == nullptr) {
            IMSA_HILOGE("msg is nullptr");
            delete parcel;
            return;
        }
        usleep(MAX_RESET_WAIT_TIME);
        MessageHandler::Instance()->SendMessage(msg);
        IMSA_HILOGI("End...[%{public}d]\n", userId_);
    }

    /*! It's called when input method setting data in the system is changed
    \param key the name of setting item changed.
    \param value the value of setting item changed.
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_SETTING_SAME_VALUE the current value is same as the one in the system.
    */
    int PerUserSession::OnSettingChanged(const std::u16string& key, const std::u16string& value)
    {
        IMSA_HILOGI("Start...[%{public}d]\n", userId_);
        std::unique_lock<std::mutex> lock(mtx);
        if (!inputMethodSetting) {
            return ErrorCode::ERROR_NULL_POINTER;
        }
        std::u16string currentValue = inputMethodSetting->GetValue(key);

        IMSA_HILOGD("PerUserSession::OnSettingChanged key = %{public}s", Utils::to_utf8(key).c_str());
        IMSA_HILOGD("PerUserSession::OnSettingChanged value = %{public}s", Utils::to_utf8(value).c_str());
        IMSA_HILOGD("PerUserSession::OnSettingChanged currentValue = %{public}s", Utils::to_utf8(currentValue).c_str());

        if (currentValue == value) {
            IMSA_HILOGI("End...[%{public}d]\n", userId_);
            return ErrorCode::ERROR_SETTING_SAME_VALUE;
        }

        if (key == InputMethodSetting::CURRENT_KEYBOARD_TYPE_TAG) {
            return OnCurrentKeyboardTypeChanged(DEFAULT_IME, value);
        } else if (key == InputMethodSetting::CURRENT_SYS_KEYBOARD_TYPE_TAG) {
            return OnCurrentKeyboardTypeChanged(SECURITY_IME, value);
        } else if (key == InputMethodSetting::CURRENT_INPUT_METHOD_TAG) {
            if (!currentIme[DEFAULT_IME] ||
                value == currentIme[DEFAULT_IME]->mImeId) {
                return ErrorCode::NO_ERROR;
            }
            if (currentClient && GetImeIndex(currentClient) == DEFAULT_IME) {
                needReshowClient = currentClient;
                HideKeyboard(currentClient);
            }
            StopInputMethod(DEFAULT_IME);
            currentIme[DEFAULT_IME] = nullptr;
            currentKbdIndex[DEFAULT_IME] = 0;
            inputMethodSetting->SetCurrentKeyboardType(-1);
        } else if (key == InputMethodSetting::ENABLED_INPUT_METHODS_TAG) {
            if (currentIme[DEFAULT_IME] && currentIme[DEFAULT_IME] != currentIme[SECURITY_IME]
                && value.find(currentIme[DEFAULT_IME]->mImeId) == std::string::npos) {
                if (currentClient && GetImeIndex(currentClient) == DEFAULT_IME) {
                    needReshowClient = currentClient;
                    HideKeyboard(currentClient);
                }
                StopInputMethod(DEFAULT_IME);
                currentIme[DEFAULT_IME] = nullptr;
                currentKbdIndex[DEFAULT_IME] = 0;
                inputMethodSetting->SetCurrentKeyboardType(-1);
            }
        }
        IMSA_HILOGI("End...[%{public}d]\n", userId_);
        return ErrorCode::NO_ERROR;
    }

    /*! Change current keyboard type.
    \param index it can be 0 or 1. 0 - default ime, 1 - security ime.
    \param value the hash code of keyboard type
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_SETTING_SAME_VALUE the current value is same as the one in the system.
    */
    int PerUserSession::OnCurrentKeyboardTypeChanged(int index, const std::u16string& value)
    {
        std::string str = Utils::to_utf8(value);
        int hashCode = std::atoi(str.c_str());
        if (hashCode == -1) {
            return ErrorCode::ERROR_SETTING_SAME_VALUE;;
        }
        // switch within the current ime.
        if (index == SECURITY_IME || currentIme[DEFAULT_IME] == currentIme[SECURITY_IME]) {
            int num = currentKbdIndex[index];
            if (currentIme[index]->mTypes[num]->getHashCode() == hashCode) {
                return ErrorCode::ERROR_SETTING_SAME_VALUE;
            }
            for (int i = 0; i < (int)currentIme[index]->mTypes.size(); i++) {
                if (currentIme[index]->mTypes[i]->getHashCode() == hashCode) {
                    currentKbdIndex[index] = i;
                    break;
                }
            }
        } else {
            std::u16string imeId = currentIme[index]->mImeId;
            std::vector<int> currentKbdTypes = inputMethodSetting->GetEnabledKeyboardTypes(imeId);
            int num = currentKbdIndex[index];
            if (currentKbdTypes[num] == hashCode) {
                return ErrorCode::ERROR_SETTING_SAME_VALUE;
            }
            for (int i = 0; i < (int)currentKbdTypes.size(); i++) {
                if (currentKbdTypes[i] == hashCode) {
                    currentKbdIndex[index] = i;
                    break;
                }
            }
        }
        KeyboardType *type = GetKeyboardType(index, currentKbdIndex[index]);
        if (type) {
            if (currentClient) {
                int ret = imsCore[index]->setKeyboardType(*type);
                if (ret != ErrorCode::NO_ERROR) {
                    IMSA_HILOGE("setKeyboardType return : %{public}s [%{public}d]\n", ErrorCode::ToString(ret), userId_);
                }
            }
            if (imsCore[index] == imsCore[1 - index]) {
                inputMethodSetting->SetCurrentKeyboardType(type->getHashCode());
                inputMethodSetting->SetCurrentSysKeyboardType(type->getHashCode());
                currentKbdIndex[1 - index] = currentKbdIndex[index];
            } else if (index == DEFAULT_IME) {
                inputMethodSetting->SetCurrentKeyboardType(type->getHashCode());
            } else {
                inputMethodSetting->SetCurrentSysKeyboardType(type->getHashCode());
            }
        }
        return ErrorCode::NO_ERROR;
    }

    /*! Hide current keyboard
    \param flag the flag to hide keyboard.
    */
    void PerUserSession::OnHideKeyboardSelf(int flags)
    {
        IMSA_HILOGW("PerUserSession::OnHideKeyboardSelf");
        (void) flags;
        HideKeyboard(currentClient);
    }

    void PerUserSession::OnShowKeyboardSelf()
    {
        IMSA_HILOGI("PerUserSession::OnShowKeyboardSelf");
        ShowKeyboard(currentClient, true);
    }

    /*! Switch to next keyboard type
    */
    void PerUserSession::OnAdvanceToNext()
    {
        int index = GetImeIndex(currentClient);
        if (index == -1) {
            IMSA_HILOGW("%{public}s [%{public}d]\n", ErrorCode::ToString(ErrorCode::ERROR_CLIENT_NOT_FOUND), userId_);
            return;
        }
        int size = 0;
        if (index == SECURITY_IME || currentIme[DEFAULT_IME] == currentIme[SECURITY_IME]) {
            size = currentIme[index]->mTypes.size();
        } else {
            std::u16string imeId = currentIme[index]->mImeId;
            std::vector<int> currentKbdTypes = inputMethodSetting->GetEnabledKeyboardTypes(imeId);
            size = currentKbdTypes.size();
        }
        if (size < MIN_IME) {
            IMSA_HILOGW("No next keyboard is available. [%{public}d]\n", userId_);
            return;
        }

        int num = currentKbdIndex[index]+1;
        if (size) {
            num %= size;
        }
        KeyboardType *type = GetKeyboardType(index, num);
        if (!type) {
            IMSA_HILOGW("No next keyboard is available. [%{public}d]\n", userId_);
            return;
        }
        InputMethodSetting tmpSetting;
        if (imsCore[index] == imsCore[1 - index]) {
            tmpSetting.SetCurrentKeyboardType(type->getHashCode());
            tmpSetting.SetCurrentSysKeyboardType(type->getHashCode());
        }
        else if (index == DEFAULT_IME) {
            tmpSetting.SetCurrentKeyboardType(type->getHashCode());
        } else {
            tmpSetting.SetCurrentSysKeyboardType(type->getHashCode());
        }
        Platform::Instance()->SetInputMethodSetting(userId_, tmpSetting);
    }

    /*! Set display mode
    \param mode the display mode of soft keyboard UI.
    \n 0 - part screen mode, 1 - full screen mode
    */
    void PerUserSession::OnSetDisplayMode(int mode)
    {
        currentDisplayMode = mode;
        ClientInfo *clientInfo = GetClientInfo(currentClient);
        if (!clientInfo) {
            IMSA_HILOGE("%{public}s [%{public}d]\n", ErrorCode::ToString(ErrorCode::ERROR_CLIENT_NOT_FOUND), userId_);
            return;
        }
        int ret = clientInfo->client->setDisplayMode(mode);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("setDisplayMode return : %{public}s [%{public}d]\n", ErrorCode::ToString(ret), userId_);
        }
    }

    /*! Restart input method service
    \param index it can be DEFAULT_IME or SECURITY_IME
    \param imeId the id of the input method service going to restart
    */
    void PerUserSession::OnRestartIms(int index, const std::u16string& imeId)
    {
        if (index < 0 || index >= MAX_IME) {
            return;
        }
        IMSA_HILOGI("Start...[%{public}d]\n", userId_);
        if (currentIme[index] && currentIme[index]->mImeId == imeId) {
            int ret = StartInputMethod(index);
            if (needReshowClient && GetImeIndex(needReshowClient) == index) {
                if (ret == ErrorCode::NO_ERROR) {
                    ShowKeyboard(needReshowClient, true);
                }
                needReshowClient = nullptr;
            }
        }
        IMSA_HILOGI("End...[%{public}d]\n", userId_);
    }

    /*! It's called when this user is locked
    */
    void PerUserSession::OnUserLocked()
    {
        IMSA_HILOGI("PerUserSession::OnUserLocked");
        if (userState == UserState::USER_STATE_STARTED) {
            IMSA_HILOGI("End...[%{public}d]\n", userId_);
            return;
        }
        userState = UserState::USER_STATE_STARTED;
        // hide current keyboard
        if (currentClient != nullptr) {
            HideKeyboard(currentClient);
        }
        for (int i = 0; i < MIN_IME; i++) {
            StopInputMethod(i);
            currentIme[i] = nullptr;
        }
        // disconnect all clients.
        std::map<IRemoteObject *, ClientInfo *>::iterator it;
        for (it = mapClients.begin(); it != mapClients.end();) {
            sptr<IRemoteObject> b = it->first;
            ClientInfo *clientInfo = it->second;
            b->RemoveDeathRecipient(clientInfo->deathRecipient);
            if (clientInfo != nullptr) {
                int ret = clientInfo->client->onInputReleased(0);
                if (ret != ErrorCode::NO_ERROR) {
                    IMSA_HILOGE("2-onInputReleased return : %{public}s", ErrorCode::ToString(ret));
                }
                delete clientInfo;
                clientInfo = nullptr;
            }
            IMSA_HILOGD("erase client..\n");
            it = mapClients.erase(it);
        }
        mapClients.clear();

        // reset values
        inputMethodSetting = nullptr;
        currentClient = nullptr;
        needReshowClient = nullptr;
    }

    /*! Get keyboard type
    \param imeIndex it can be 0 or 1.  0 - default ime, 1 - security ime
    \param typeIndex the index of keyboard type.
    \return a KeyboardType pointer when it's found.
    \return null when it's not found.
    \note The returned pointer should not be freed by caller.
    */
    KeyboardType *PerUserSession::GetKeyboardType(int imeIndex, int typeIndex)
    {
        if (typeIndex < 0) {
            return nullptr;
        }
        if (imeIndex == SECURITY_IME || currentIme[DEFAULT_IME] == currentIme[SECURITY_IME]) {
            if (typeIndex >= (int)currentIme[imeIndex]->mTypes.size()) {
                return nullptr;
            }
            return currentIme[imeIndex]->mTypes[typeIndex];
        } else {
            std::u16string imeId = currentIme[imeIndex]->mImeId;
            std::vector<int> currentKbdTypes = inputMethodSetting->GetEnabledKeyboardTypes(imeId);
            int size = currentKbdTypes.size();
            if (typeIndex >= size) {
                return nullptr;
            }
            int hashCode = currentKbdTypes[typeIndex];
            for (int i = 0; i < (int)currentIme[imeIndex]->mTypes.size(); i++) {
                if (currentIme[imeIndex]->mTypes[i]->getHashCode() == hashCode) {
                    return currentIme[imeIndex]->mTypes[i];
                }
            }
        }
        return nullptr;
    }

    /*! Reset current keyboard type
    \param imeIndex it can be 0 or 1. 0 - default ime, 1 - security ime
    */
    void PerUserSession::ResetCurrentKeyboardType(int imeIndex)
    {
        if (imeIndex < 0 || imeIndex > 1) {
            return;
        }
        currentKbdIndex[imeIndex] = 0;
        int hashCode = 0;
        if (imeIndex == DEFAULT_IME) {
            hashCode = inputMethodSetting->GetCurrentKeyboardType();
        } else {
            hashCode = inputMethodSetting->GetCurrentSysKeyboardType();
        }
        KeyboardType *type = nullptr;
        if (hashCode == -1) {
            type  = GetKeyboardType(imeIndex, currentKbdIndex[imeIndex]);
        } else {
            bool flag = false;
            if (imeIndex == SECURITY_IME || currentIme[DEFAULT_IME] == currentIme[SECURITY_IME]) {
                for (int i = 0; i < (int)currentIme[imeIndex]->mTypes.size(); i++) {
                    if (currentIme[imeIndex]->mTypes[i]->getHashCode() == hashCode) {
                        currentKbdIndex[imeIndex] = i;
                        flag = true;
                        break;
                    }
                }
            } else {
                std::vector<int> hashCodeList = inputMethodSetting->GetEnabledKeyboardTypes(currentIme[imeIndex]->mImeId);
                for (int i = 0; i < (int)hashCodeList.size(); i++) {
                    if (hashCode == hashCodeList[i]) {
                        currentKbdIndex[imeIndex] = i;
                        flag = true;
                        break;
                    }
                }
            }
            if (!flag) {
                IMSA_HILOGW("The current keyboard type is not found in the current IME. Reset it!");
                type = GetKeyboardType(imeIndex, currentKbdIndex[imeIndex]);
            } else if (imsCore[imeIndex] == imsCore[1 - imeIndex]) {
                currentKbdIndex[1 - imeIndex] = currentKbdIndex[imeIndex];
            }
        }
        if (type) {
            InputMethodSetting tmpSetting;
            if (imsCore[imeIndex] == imsCore[1 - imeIndex]) {
                inputMethodSetting->SetCurrentKeyboardType(type->getHashCode());
                inputMethodSetting->SetCurrentSysKeyboardType(type->getHashCode());
                currentKbdIndex[1 - imeIndex] = currentKbdIndex[imeIndex];
                tmpSetting.SetCurrentKeyboardType(type->getHashCode());
                tmpSetting.SetCurrentSysKeyboardType(type->getHashCode());
            } else if (imeIndex == DEFAULT_IME) {
                tmpSetting.SetCurrentKeyboardType(type->getHashCode());
                inputMethodSetting->SetCurrentKeyboardType(type->getHashCode());
            } else {
                tmpSetting.SetCurrentSysKeyboardType(type->getHashCode());
                inputMethodSetting->SetCurrentSysKeyboardType(type->getHashCode());
            }
            Platform::Instance()->SetInputMethodSetting(userId_, tmpSetting);
        }
    }

    /*! Get ime index for the input client
    \param inputClient the remote object handler of an input client.
    \return 0 - default ime
    \return 1 - security ime
    \return -1 - input client is not found
    */
    int PerUserSession::GetImeIndex(const sptr<IInputClient>& inputClient)
    {
        if (!inputClient) {
            IMSA_HILOGW("PerUserSession::GetImeIndex inputClient is nullptr");
            return -1;
        }

        ClientInfo *clientInfo = GetClientInfo(inputClient);
        if (!clientInfo) {
            IMSA_HILOGW("PerUserSession::GetImeIndex clientInfo is nullptr");
            return -1;
        }

        if (clientInfo->attribute.GetSecurityFlag()) {
            return SECURITY_IME;
        }
        return DEFAULT_IME;
    }

    /*! Copy session data from one IME to another IME
    \param imeIndex it can be 0 or 1.
    \n 0 - default ime, 1 - security ime
    */
    void PerUserSession::CopyInputMethodService(int imeIndex)
    {
        imsCore[imeIndex] = imsCore[1 - imeIndex];
        localControlChannel[imeIndex] = localControlChannel[1 - imeIndex];
        inputControlChannel[imeIndex] = inputControlChannel[1 - imeIndex];
        inputMethodToken[imeIndex] = inputMethodToken[1 - imeIndex];
        currentKbdIndex[imeIndex] = currentKbdIndex[1 - imeIndex];
        int hashCode[2];
        hashCode[0] = inputMethodSetting->GetCurrentKeyboardType();
        hashCode[1] = inputMethodSetting->GetCurrentSysKeyboardType();
        if (hashCode[imeIndex] != hashCode[1 - imeIndex]) {
            hashCode[imeIndex] = hashCode[1 - imeIndex];
            inputMethodSetting->SetCurrentKeyboardType(hashCode[0]);
            inputMethodSetting->SetCurrentSysKeyboardType(hashCode[1]);

            InputMethodSetting tmpSetting;
            tmpSetting.ClearData();
            tmpSetting.SetCurrentKeyboardType(hashCode[0]);
            tmpSetting.SetCurrentSysKeyboardType(hashCode[1]);
            Platform::Instance()->SetInputMethodSetting(userId_, tmpSetting);
        }
    }

    /*! Get ClientInfo
    \param inputClient the IInputClient remote handler of given input client
    \return a pointer of ClientInfo if client is found
    \n      null if client is not found
    \note the clientInfo pointer should not be freed by caller
    */
    ClientInfo *PerUserSession::GetClientInfo(const sptr<IInputClient> &inputClient)
    {
        if (inputClient == nullptr) {
            IMSA_HILOGE("PerUserSession::GetClientInfo inputClient is nullptr");
            return nullptr;
        }
        sptr<IRemoteObject> b = Platform::RemoteBrokerToObject(inputClient);
        std::map<IRemoteObject *, ClientInfo *>::iterator it = mapClients.find(b);
        if (it == mapClients.end()) {
            return nullptr;
        }
        return (ClientInfo *)it->second;
    }

    bool PerUserSession::StartInputService()
    {
        IMSA_HILOGE("PerUserSession::StartInputService");
        sptr<AAFwk::IAbilityManager> ams = GetAbilityManagerService();
        if (!ams) {
            return false;
        }
        AAFwk::Want want;
        want.SetAction("action.system.inputmethod");
        want.SetElementName("com.example.kikakeyboard", "com.example.kikakeyboard.ServiceExtAbility");
        int32_t result = ams->StartAbility(want);
        if (result) {
            IMSA_HILOGE("PerUserSession::StartInputService fail. result = %{public}d", result);
            return false;
        }
        return true;
    }

    sptr<AAFwk::IAbilityManager> PerUserSession::GetAbilityManagerService()
    {
        IMSA_HILOGE("GetAbilityManagerService start");
        sptr<IRemoteObject> abilityMsObj =
        OHOS::DelayedSingleton<AAFwk::SaMgrClient>::GetInstance()->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
        if (!abilityMsObj) {
            IMSA_HILOGE("failed to get ability manager service");
            return nullptr;
        }
        return iface_cast<AAFwk::IAbilityManager>(abilityMsObj);
    }

    /*! Prepare input. Called by an input client.
    \n Run in work thread of this user
    \param msg the parameters from remote client are saved in msg->msgContent_
    \return ErrorCode
    */
    void PerUserSession::OnPrepareInput(Message *msg)
    {
        IMSA_HILOGI("PerUserSession::OnPrepareInput Start...[%{public}d]\n", userId_);
        MessageParcel *data = msg->msgContent_;
        int pid = data->ReadInt32();
        int uid = data->ReadInt32();
        int displayId = data->ReadInt32();

        sptr<IRemoteObject> clientObject = data->ReadRemoteObject();
        if (!clientObject) {
            IMSA_HILOGI("PerUserSession::OnPrepareInput clientObject is null");
            return;
        }
        sptr<InputClientProxy> client = new InputClientProxy(clientObject);
        sptr<IRemoteObject> channelObject = data->ReadRemoteObject();
        if (!channelObject) {
            IMSA_HILOGI("PerUserSession::OnPrepareInput channelObject is null");
            return;
        }
        sptr<InputDataChannelProxy> channel = new InputDataChannelProxy(channelObject);
        InputAttribute *attribute = data->ReadParcelable<InputAttribute>();
        if (!attribute) {
            IMSA_HILOGI("PerUserSession::OnPrepareInput attribute is nullptr");
            return;
        }

        int ret = AddClient(pid, uid, displayId, client, channel, *attribute);
        delete attribute;
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("PerUserSession::OnPrepareInput Aborted! %{public}s", ErrorCode::ToString(ret));
            CreateComponentFailed(userId_, ret);
            return;
        }
        SendAgentToSingleClient(client);
    }

    void PerUserSession::SendAgentToSingleClient(const sptr<IInputClient>& inputClient)
    {
        IMSA_HILOGI("PerUserSession::SendAgentToSingleClient");
        if (!imsAgent) {
            IMSA_HILOGI("PerUserSession::SendAgentToSingleClient imsAgent is nullptr");
            CreateComponentFailed(userId_, ErrorCode::ERROR_NULL_POINTER);
            return;
        }
        ClientInfo *clientInfo = GetClientInfo(inputClient);
        if (!clientInfo) {
            IMSA_HILOGE("PerUserSession::SendAgentToSingleClient clientInfo is nullptr");
            CreateComponentFailed(userId_, ErrorCode::ERROR_NULL_POINTER);
            return;
        }
        clientInfo->client->onInputReady(imsAgent);
    }

    /*! Release input. Called by an input client.
    \n Run in work thread of this user
    \param msg the parameters from remote client are saved in msg->msgContent_
    \return ErrorCode
    */
    void PerUserSession::OnReleaseInput(Message *msg)
    {
        IMSA_HILOGI("PerUserSession::OnReleaseInput Start...[%{public}d]\n", userId_);
        MessageParcel *data = msg->msgContent_;

        sptr<IRemoteObject> clientObject = data->ReadRemoteObject();
        sptr<InputClientProxy> client = new InputClientProxy(clientObject);
        sptr<IInputClient> interface = client;
        if (imsCore[0] != nullptr) {
            imsCore[0]->SetClientState(false);
        }
        HideKeyboard(client);
        int ret = RemoveClient(clientObject);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("PerUserSession::OnReleaseInput Aborted! Failed to RemoveClient [%{public}d]\n", userId_);
        }
        IMSA_HILOGI("PerUserSession::OnReleaseInput End...[%{public}d]\n", userId_);
    }

    /*! Start input. Called by an input client.
    \n Run in work thread of this user
    \param msg the parameters from remote client are saved in msg->msgContent_
    \return ErrorCode
    */
    void PerUserSession::OnStartInput(Message *msg)
    {
        IMSA_HILOGI("PerUserSession::OnStartInput");
        MessageParcel *data = msg->msgContent_;
        sptr<IRemoteObject> clientObject = data->ReadRemoteObject();
        sptr<InputClientProxy> client = new InputClientProxy(clientObject);
        if (imsCore[0]) {
            imsCore[0]->SetClientState(true);
        }
        bool isShowKeyboard = data->ReadBool();
        ShowKeyboard(client, isShowKeyboard);
    }

    void PerUserSession::SetCoreAndAgent(Message *msg)
    {
        IMSA_HILOGI("PerUserSession::SetCoreAndAgent Start...[%{public}d]\n", userId_);
        auto data = msg->msgContent_;

        auto coreObject = data->ReadRemoteObject();
        if (coreObject == nullptr) {
            IMSA_HILOGE("coreObject is nullptr");
            return;
        }
        auto core = new (std::nothrow) InputMethodCoreProxy(coreObject);
        if (core == nullptr) {
            IMSA_HILOGE("core is nullptr");
            return;
        }
        if (imsCore[0] != nullptr) {
            IMSA_HILOGI("PerUserSession::SetCoreAndAgent Input Method Service has already been started ! ");
        }

        imsCore[0] = core;

        bool ret = coreObject->AddDeathRecipient(imsDeathRecipient);
        IMSA_HILOGI("Add death recipient %{public}s", ret ? "success" : "failed");

        auto agentObject = data->ReadRemoteObject();
        auto proxy = new (std::nothrow) InputMethodAgentProxy(agentObject);
        if (proxy == nullptr) {
            IMSA_HILOGE("proxy is nullptr");
            return;
        }
        imsAgent = proxy;

        InitInputControlChannel();

        SendAgentToAllClients();
    }

    void PerUserSession::SendAgentToAllClients()
    {
        IMSA_HILOGI("PerUserSession::SendAgentToAllClients");
        if (imsAgent == nullptr) {
            IMSA_HILOGI("PerUserSession::SendAgentToAllClients imsAgent is nullptr");
            return;
        }

        for (std::map<IRemoteObject *, ClientInfo *>::iterator it = mapClients.begin(); it != mapClients.end(); ++it) {
            ClientInfo *clientInfo = (ClientInfo *)it->second;
            if (clientInfo) {
                clientInfo->client->onInputReady(imsAgent);
            }
        }
    }

    void PerUserSession::InitInputControlChannel()
    {
        IMSA_HILOGI("PerUserSession::InitInputControlChannel");
        sptr<IInputControlChannel> inputControlChannel = new InputControlChannelStub(userId_);
        int ret = imsCore[0]->InitInputControlChannel(inputControlChannel);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGI("PerUserSession::InitInputControlChannel fail %{public}s", ErrorCode::ToString(ret));
        }
    }

    /*! Stop input. Called by an input client.
    \n Run in work thread of this user
    \param msg the parameters from remote client are saved in msg->msgContent_
    \return ErrorCode
    */
    void PerUserSession::OnStopInput(Message *msg)
    {
        IMSA_HILOGI("PerUserSession::OnStopInput");
        MessageParcel *data = msg->msgContent_;

        sptr<IRemoteObject> clientObject = data->ReadRemoteObject();
        sptr<InputClientProxy> client = new InputClientProxy(clientObject);
        HideKeyboard(client);
    }

    void PerUserSession::StopInputService(std::string imeId)
    {
        IMSA_HILOGI("PerUserSession::StopInputService");
        if (imsCore[0] == nullptr) {
            IMSA_HILOGE("imsCore[0] is nullptr");
            return;
        }
        IMSA_HILOGI("Remove death recipient");
        imsCore[0]->AsObject()->RemoveDeathRecipient(imsDeathRecipient);
        imsCore[0]->StopInputService(imeId);
    }

    bool PerUserSession::IsRestartIme(uint32_t index)
    {
        IMSA_HILOGI("PerUserSession::IsRestartIme");
        std::lock_guard<std::mutex> lock(resetLock);
        auto now = time(nullptr);
        if (difftime(now, manager[index].last) > IME_RESET_TIME_OUT) {
            manager[index] = { 0, now };
        }
        ++manager[index].num;
        return manager[index].num <= MAX_RESTART_NUM;
    }

    void PerUserSession::ResetImeError(uint32_t index)
    {
        IMSA_HILOGI("PerUserSession::ResetImeError index = %{public}d", index);
        std::lock_guard<std::mutex> lock(resetLock);
        manager[index] = { 0, 0 };
    }

    void PerUserSession::ClearImeData(uint32_t index)
    {
        IMSA_HILOGI("Clear ime...index = %{public}d", index);
        if (imsCore[index] != nullptr) {
            imsCore[index]->AsObject()->RemoveDeathRecipient(imsDeathRecipient);
            imsCore[index] = nullptr;
        }
        inputControlChannel[index] = nullptr;
        localControlChannel[index] = nullptr;
        inputMethodToken[index] = nullptr;
    }
} // namespace MiscServices
} // namespace OHOS
