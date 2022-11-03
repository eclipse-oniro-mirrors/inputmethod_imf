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

#include "input_method_system_ability.h"
#include "message_handler.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "errors.h"
#include "global.h"
#include "ui_service_mgr_client.h"
#include "bundle_mgr_proxy.h"
#include "para_handle.h"
#include "ability_manager_interface.h"
#include "ability_connect_callback_proxy.h"
#include "sa_mgr_client.h"
#include "application_info.h"
#include "common_event_support.h"
#include "im_common_event_manager.h"
#include "resource_manager.h"
#include "os_account_manager.h"
#include "input_method_status.h"

namespace OHOS {
namespace MiscServices {
    using namespace MessageID;
    using namespace AccountSA;
    REGISTER_SYSTEM_ABILITY_BY_ID(InputMethodSystemAbility, INPUT_METHOD_SYSTEM_ABILITY_ID, true);
    const std::int32_t INIT_INTERVAL = 10000L;
    const std::int32_t MAIN_USER_ID = 100;
    std::mutex InputMethodSystemAbility::instanceLock_;
    sptr<InputMethodSystemAbility> InputMethodSystemAbility::instance_;

    std::shared_ptr<AppExecFwk::EventHandler> InputMethodSystemAbility::serviceHandler_;

    /**
     * constructor
     * @param systemAbilityId
     * @param runOnCreate
     */
    InputMethodSystemAbility::InputMethodSystemAbility(int32_t systemAbilityId, bool runOnCreate)
        : SystemAbility(systemAbilityId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
    {
    }

    /**
     * constructor
     */
    InputMethodSystemAbility::InputMethodSystemAbility() : state_(ServiceRunningState::STATE_NOT_START)
    {
    }

    /**
     * Destructor
     */
    InputMethodSystemAbility::~InputMethodSystemAbility()
    {
        if (workThreadHandler.joinable()) {
            workThreadHandler.join();
        }

        std::map<int32_t, PerUserSession*>::const_iterator it;
        for (it = userSessions.cbegin(); it != userSessions.cend();) {
            PerUserSession *session = it->second;
            it = userSessions.erase(it);
            delete session;
            session = nullptr;
        }
        userSessions.clear();
        std::map<int32_t, PerUserSetting*>::const_iterator it1;
        for (it1 = userSettings.cbegin(); it1 != userSettings.cend();) {
            PerUserSetting *setting = it1->second;
            it1 = userSettings.erase(it1);
            delete setting;
            setting = nullptr;
        }
        userSettings.clear();
        std::map<int32_t, MessageHandler*>::const_iterator it2;
        for (it2 = msgHandlers.cbegin(); it2 != msgHandlers.cend();) {
            MessageHandler *handler = it2->second;
            it2 = msgHandlers.erase(it2);
            delete handler;
            handler = nullptr;
        }
        msgHandlers.clear();
    }

    sptr<InputMethodSystemAbility> InputMethodSystemAbility::GetInstance()
    {
        if (!instance_) {
            std::lock_guard<std::mutex> autoLock(instanceLock_);
            if (!instance_) {
                instance_ = new InputMethodSystemAbility;
            }
        }
        return instance_;
    }

    void InputMethodSystemAbility::OnStart()
    {
        IMSA_HILOGI("InputMethodSystemAbility::OnStart.");
        if (state_ == ServiceRunningState::STATE_RUNNING) {
            IMSA_HILOGI("ImsaService is already running.");
            return;
        }
        Initialize();
        InitServiceHandler();
        if (Init() != ErrorCode::NO_ERROR) {
            auto callback = [=]() { Init(); };
            serviceHandler_->PostTask(callback, INIT_INTERVAL);
            IMSA_HILOGE("Init failed. Try again 10s later");
            return;
        }
        InitHiTrace();
        InputmethodTrace tracer("InputMethodController Attach trace.");
        InputmethodDump::GetInstance().AddDumpAllMethod(
            std::bind(&InputMethodSystemAbility::DumpAllMethod, this, std::placeholders::_1));
        IMSA_HILOGI("Start ImsaService ErrorCode::NO_ERROR.");
        return;
    }

    int InputMethodSystemAbility::Dump(int fd, const std::vector<std::u16string> &args)
    {
        IMSA_HILOGI("InputMethodSystemAbility::Dump");
        std::vector<std::string> argsStr;
        for (auto item : args) {
            argsStr.emplace_back(Str16ToStr8(item));
        }
        InputmethodDump::GetInstance().Dump(fd, argsStr);
        return ERR_OK;
    }

    std::string InputMethodSystemAbility::GetInputMethodParam(const std::vector<InputMethodProperty> &properties)
    {
        std::string defaultIme = ParaHandle::GetDefaultIme(userId_);
        bool isBegin = true;
        std::string params = "{\"imeList\":[";
        for (const auto &property : properties) {
            params += isBegin ? "" : "},";
            isBegin = false;

            std::string imeId = Str16ToStr8(property.mPackageName) + "/" + Str16ToStr8(property.mAbilityName);
            params += "{\"ime\": \"" + imeId + "\",";
            params += "\"labelId\": \"" + std::to_string(property.labelId) + "\",";
            params += "\"descriptionId\": \"" + std::to_string(property.descriptionId) + "\",";
            std::string isDefaultIme = defaultIme == imeId ? "true" : "false";
            params += "\"isDefaultIme\": \"" + isDefaultIme + "\",";
            params += "\"label\": \"" + Str16ToStr8(property.label) + "\",";
            params += "\"description\": \"" + Str16ToStr8(property.description) + "\"";
        }
        params += "}]}";
        return params;
    }

    void InputMethodSystemAbility::DumpAllMethod(int fd)
    {
        IMSA_HILOGI("InputMethodSystemAbility::DumpAllMethod");
        std::vector<int32_t> ids;
        int errCode = OsAccountManager::QueryActiveOsAccountIds(ids);
        if (errCode != ERR_OK) {
            dprintf(fd, "\n - InputMethodSystemAbility::DumpAllMethod get Active Id failed.\n");
            return;
        }
        dprintf(fd, "\n - DumpAllMethod get Active Id succeed,count=%zu,", ids.size());
        for (auto id : ids) {
            const auto &properties = ListInputMethodByUserId(id, ALL);
            if (properties.empty()) {
                IMSA_HILOGI("The IME properties is empty.");
                dprintf(fd, "\n - The IME properties about the Active Id %d is empty.\n", id);
                continue;
            }
            const auto &params = GetInputMethodParam(properties);
            dprintf(fd, "\n - The Active Id:%d get input method:\n%s\n", id, params.c_str());
        }
        IMSA_HILOGI("InputMethodSystemAbility::DumpAllMethod end.");
    }

    int32_t InputMethodSystemAbility::Init()
    {
        bool ret = Publish(InputMethodSystemAbility::GetInstance());
        if (!ret) {
            IMSA_HILOGE("Publish failed.");
            return -1;
        }
        IMSA_HILOGI("Publish ErrorCode::NO_ERROR.");
        state_ = ServiceRunningState::STATE_RUNNING;
        std::string defaultIme = ParaHandle::GetDefaultIme(userId_);
        StartInputService(defaultIme);
        StartUserIdListener();
        return ErrorCode::NO_ERROR;
    }

    void InputMethodSystemAbility::OnStop()
    {
        IMSA_HILOGI("OnStop started.");
        if (state_ != ServiceRunningState::STATE_RUNNING) {
            return;
        }
        serviceHandler_ = nullptr;

        state_ = ServiceRunningState::STATE_NOT_START;
        IMSA_HILOGI("OnStop end.");
    }

    void InputMethodSystemAbility::InitServiceHandler()
    {
        IMSA_HILOGI("InitServiceHandler started.");
        if (serviceHandler_) {
            IMSA_HILOGI("InitServiceHandler already init.");
            return;
        }
        std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("InputMethodSystemAbility");
        serviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);

        IMSA_HILOGI("InitServiceHandler succeeded.");
    }

    /*! Initialization of Input method management service
    \n It's called after the service starts, before any transaction.
    */
    void InputMethodSystemAbility::Initialize()
    {
        IMSA_HILOGI("InputMethodSystemAbility::Initialize");
        // init work thread to handle the messages
        workThreadHandler = std::thread([this] {
            WorkThread();
        });
        PerUserSetting *setting = new PerUserSetting(MAIN_USER_ID);
        PerUserSession *session = new PerUserSession(MAIN_USER_ID);
        userSettings.insert(std::pair<int32_t, PerUserSetting*>(MAIN_USER_ID, setting));
        userSessions.insert(std::pair<int32_t, PerUserSession*>(MAIN_USER_ID, session));

        userId_ = MAIN_USER_ID;
        setting->Initialize();
    }

    void InputMethodSystemAbility::StartUserIdListener()
    {
        sptr<ImCommonEventManager> imCommonEventManager = ImCommonEventManager::GetInstance();
        bool isSuccess = imCommonEventManager->SubscribeEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
        if (isSuccess) {
            IMSA_HILOGI("InputMethodSystemAbility::Initialize subscribe service event success");
            return;
        }

        IMSA_HILOGE("StartUserIdListener failed. Try again 10s later");
        auto callback = [this]() { StartUserIdListener(); };
        serviceHandler_->PostTask(callback, INIT_INTERVAL);
    }

    bool InputMethodSystemAbility::StartInputService(std::string imeId)
    {
        IMSA_HILOGE("InputMethodSystemAbility::StartInputService() ime:%{public}s", imeId.c_str());

        PerUserSession *session = GetUserSession(MAIN_USER_ID);

        std::map<int32_t, MessageHandler*>::const_iterator it = msgHandlers.find(MAIN_USER_ID);
        if (it == msgHandlers.end()) {
            IMSA_HILOGE("InputMethodSystemAbility::StartInputService() need start handler");
            MessageHandler *handler = new MessageHandler();
            if (session) {
                IMSA_HILOGE("InputMethodSystemAbility::OnPrepareInput session is not nullptr");
                session->CreateWorkThread(*handler);
                msgHandlers.insert(std::pair<int32_t, MessageHandler*>(MAIN_USER_ID, handler));
            }
        }

        bool isStartSuccess = false;
        sptr<AAFwk::IAbilityManager> abms = GetAbilityManagerService();
        if (abms) {
            AAFwk::Want want;
            want.SetAction("action.system.inputmethod");
            std::string::size_type pos = imeId.find("/");
            want.SetElementName(imeId.substr(0, pos), imeId.substr(pos + 1));
            int32_t result = abms->StartAbility(want);
            if (result) {
                IMSA_HILOGE("InputMethodSystemAbility::StartInputService failed, result = %{public}d", result);
                isStartSuccess = false;
            } else {
                IMSA_HILOGE("InputMethodSystemAbility::StartInputService success.");
                isStartSuccess = true;
            }
        }

        if (!isStartSuccess) {
            IMSA_HILOGE("StartInputService failed. Try again 10s later");
            auto callback = [this, imeId]() { StartInputService(imeId); };
            serviceHandler_->PostTask(callback, INIT_INTERVAL);
        }
        return isStartSuccess;
    }

    void InputMethodSystemAbility::StopInputService(std::string imeId)
    {
        IMSA_HILOGE("InputMethodSystemAbility::StopInputService(%{public}s)", imeId.c_str());
        PerUserSession *session = GetUserSession(MAIN_USER_ID);
        if (!session){
            IMSA_HILOGE("InputMethodSystemAbility::StopInputService abort session is nullptr");
            return;
        }

        session->StopInputService(imeId);
    }

    /*! Get the state of user
    \n This API is added for unit test.
    \param userID the id of given user
    \return user state can be one of the values of UserState
    */
    int32_t InputMethodSystemAbility::GetUserState(int32_t userId)
    {
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting) {
            return UserState::USER_STATE_NOT_AVAILABLE;
        }
        return setting->GetUserState();
    }

    /*! Handle the transaction from the remote binder
    \n Run in binder thread
    \param code transaction code number
    \param data the params from remote binder
    \param[out] reply the result of the transaction replied to the remote binder
    \param flags the flags of handling transaction
    \return int32_t
    */
    int32_t InputMethodSystemAbility::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option)
    {
        return InputMethodSystemAbilityStub::OnRemoteRequest(code, data, reply, option);
    }

    /*! Get the display mode of keyboard
    \n Run in binder thread
    \param[out] retMode the display mode returned to the caller
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    */
    int32_t InputMethodSystemAbility::getDisplayMode(int32_t &retMode)
    {
        int32_t uid = IPCSkeleton::GetCallingUid();
        int32_t userId = getUserId(uid);
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("%s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }
        PerUserSession *session = GetUserSession(userId);
        if (session == nullptr) {
            IMSA_HILOGI("InputMethodSystemAbility::getDisplayMode session is nullptr");
            return ErrorCode::ERROR_NULL_POINTER;
        }
        retMode = session->GetDisplayMode();
        return ErrorCode::NO_ERROR;
    }

    /*! Get the window height of the current keyboard
    \n Run in binder thread
    \param[out] retHeight the window height returned to the caller
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    */
    int32_t InputMethodSystemAbility::getKeyboardWindowHeight(int32_t &retHeight)
    {
        int32_t uid = IPCSkeleton::GetCallingUid();
        int32_t userId = getUserId(uid);
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("%s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }

        PerUserSession *session = GetUserSession(userId);
        if (session == nullptr) {
            IMSA_HILOGI("InputMethodSystemAbility::getKeyboardWindowHeight session is nullptr");
            return ErrorCode::ERROR_NULL_POINTER;
        }
        int32_t ret = session->GetKeyboardWindowHeight(retHeight);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGE("Failed to get keyboard window height. ErrorCode=%d\n", ret);
        }
        return ret;
    }

    /*! Get the  current keyboard type
    \n Run in binder thread
    \param[out] retType the current keyboard type returned to the caller
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    \return ErrorCode::ERROR_NULL_POINTER current keyboard type is null
    */
    int32_t InputMethodSystemAbility::getCurrentKeyboardType(KeyboardType *retType)
    {
        int32_t uid = IPCSkeleton::GetCallingUid();
        int32_t userId = getUserId(uid);
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("%s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }

        PerUserSession *userSession = GetUserSession(userId);
        if (!userSession) {
            return ErrorCode::ERROR_NULL_POINTER;
        }
        KeyboardType *type = userSession->GetCurrentKeyboardType();
        if (!type) {
            return ErrorCode::ERROR_NULL_POINTER;
        }
        *retType = *type;
        return ErrorCode::NO_ERROR;
    }

    std::vector<InputMethodProperty> InputMethodSystemAbility::ListInputMethod(InputMethodStatus status)
    {
        return {};
    }

    std::vector<InputMethodProperty> InputMethodSystemAbility::ListAllInputMethod(int32_t userId)
    {
        IMSA_HILOGI("InputMethodSystemAbility::listAllInputMethod");
        std::vector<InputMethodProperty> properties;
        AbilityType types[] = { AbilityType::SERVICE, AbilityType::INPUTMETHOD };
        for (const auto &type : types) {
            auto property = listInputMethodByType(userId, type);
            properties.insert(properties.end(), property.begin(), property.end());
        }
        return properties;
    }

    std::vector<InputMethodProperty> InputMethodSystemAbility::ListEnabledInputMethod()
    {
        IMSA_HILOGI("InputMethodSystemAbility::listEnabledInputMethod");
        auto property = GetCurrentInputMethod();
        if (property == nullptr) {
            IMSA_HILOGE("GetCurrentInputMethod property is nullptr");
            return {};
        }
        return { *property };
    }

    std::vector<InputMethodProperty> InputMethodSystemAbility::ListDisabledInputMethod(int32_t userId)
    {
        IMSA_HILOGI("InputMethodSystemAbility::listDisabledInputMethod");
        auto properties = listInputMethodByType(userId, AbilityType::INPUTMETHOD);
        auto filter = GetCurrentInputMethod();
        if (filter == nullptr) {
            IMSA_HILOGE("GetCurrentInputMethod property is nullptr");
            return {};
        }
        for (auto iter = properties.begin(); iter != properties.end();) {
            if (iter->mPackageName == filter->mPackageName && iter->mAbilityName == filter->mAbilityName) {
                iter = properties.erase(iter);
                continue;
            }
            ++iter;
        }
        return properties;
    }

    int32_t InputMethodSystemAbility::SwitchInputMethod(const InputMethodProperty &target)
    {
        return ErrorCode::NO_ERROR;
    }

    /*! Get all of the input method engine list installed in the system
    \n Run in binder thread
    \param[out] properties input method engine list returned to the caller
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    */
    std::vector<InputMethodProperty> InputMethodSystemAbility::ListInputMethodByUserId(
        int32_t userId, InputMethodStatus status)
    {
        IMSA_HILOGI("InputMethodSystemAbility::ListInputMethodByUserId");
        if (status == InputMethodStatus::ALL) {
            return ListAllInputMethod(userId);
        }
        if (status == InputMethodStatus::ENABLE) {
            return ListEnabledInputMethod();
        }
        if (status == InputMethodStatus::DISABLE) {
            return ListDisabledInputMethod(userId);
        }
        return {};
    }

    std::vector<InputMethodProperty> InputMethodSystemAbility::listInputMethodByType(int32_t userId, AbilityType type)
    {
        IMSA_HILOGI("InputMethodSystemAbility::listInputMethodByType userId = %{public}d", userId);
        std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
        auto bundleMgr = GetBundleMgr();
        if (bundleMgr == nullptr) {
          IMSA_HILOGE("Failed to GetBundleMgr");
          return {};
        }
        bool ret = bundleMgr->QueryExtensionAbilityInfos(type, userId, extensionInfos);
        if (!ret) {
            IMSA_HILOGE("InputMethodSystemAbility::listInputMethodByType QueryExtensionAbilityInfos error");
            return {};
        }
        std::vector<InputMethodProperty> properties;
        for (auto extension : extensionInfos) {
            std::shared_ptr<Global::Resource::ResourceManager> resourceManager(
                Global::Resource::CreateResourceManager());
            if (resourceManager == nullptr) {
                IMSA_HILOGE("InputMethodSystemAbility::listInputMethodByType resourcemanager is nullptr");
                break;
            }
            AppExecFwk::ApplicationInfo applicationInfo = extension.applicationInfo;
            resourceManager->AddResource(extension.hapPath.c_str());
            std::string labelString;
            resourceManager->GetStringById(applicationInfo.labelId, labelString);
            std::string descriptionString;
            resourceManager->GetStringById(applicationInfo.descriptionId, descriptionString);
            InputMethodProperty property;
            property.mPackageName = Str8ToStr16(extension.bundleName);
            property.mAbilityName = Str8ToStr16(extension.name);
            property.labelId = applicationInfo.labelId;
            property.descriptionId = applicationInfo.descriptionId;
            property.label = Str8ToStr16(labelString);
            property.description = Str8ToStr16(descriptionString);
            properties.push_back(property);
        }
        return properties;
    }

    /*! Get the keyboard type list for the given input method engine
    \n Run in binder thread
    \param imeId the id of the given input method engine
    \param[out] types keyboard type list returned to the caller
    \return ErrorCode::NO_ERROR no error
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    */
    int32_t InputMethodSystemAbility::listKeyboardType(const std::u16string& imeId, std::vector<KeyboardType*> *types)
    {
        int32_t uid = IPCSkeleton::GetCallingUid();
        int32_t userId = getUserId(uid);
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("%s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }
        return setting->ListKeyboardType(imeId, types);
    }

    std::shared_ptr<InputMethodProperty> InputMethodSystemAbility::GetCurrentInputMethod()
    {
        IMSA_HILOGI("InputMethodSystemAbility::GetCurrentInputMethod");
        std::string ime = ParaHandle::GetDefaultIme(MAIN_USER_ID);
        if (ime.empty()) {
            IMSA_HILOGE("InputMethodSystemAbility::GetCurrentInputMethod ime is empty");
            return nullptr;
        }

        std::string::size_type pos = ime.find('/');
        if (pos == -1) {
            IMSA_HILOGE("InputMethodSystemAbility::GetCurrentInputMethod ime can not find '/'");
            return nullptr;
        }

        auto property = std::make_shared<InputMethodProperty>();
        if (property == nullptr) {
            IMSA_HILOGE("InputMethodSystemAbility property is nullptr");
            return nullptr;
        }
        property->mPackageName = Str8ToStr16(ime.substr(0, pos));
        property->mAbilityName = Str8ToStr16(ime.substr(pos + 1, ime.length() - pos - 1));
        return property;
    }

    /*! Get the instance of PerUserSetting for the given user
    \param userId the user id of the given user
    \return a pointer of the instance if the user is found
    \return null if the user is not found
    */
    PerUserSetting *InputMethodSystemAbility::GetUserSetting(int32_t userId)
    {
        std::map<int32_t, PerUserSetting*>::iterator it = userSettings.find(userId);
        if (it == userSettings.end()) {
            return nullptr;
        }
        return it->second;
    }

    /*! Get the instance of PerUserSession for the given user
    \param userId the user id of the given user
    \return a pointer of the instance if the user is found
    \return null if the user is not found
    */
    PerUserSession *InputMethodSystemAbility::GetUserSession(int32_t userId)
    {
        std::map<int32_t, PerUserSession*>::iterator it = userSessions.find(userId);
        if (it == userSessions.end()) {
            return nullptr;
        }
        return it->second;
    }

    /*! Work Thread of input method management service
    \n Remote commands which may change the state or data in the service will be handled sequentially in this thread.
    */
    void InputMethodSystemAbility::WorkThread()
    {
        while (1) {
            Message *msg = MessageHandler::Instance()->GetMessage();
            switch (msg->msgId_) {
                case MSG_ID_USER_START : {
                    OnUserStarted(msg);
                    break;
                }
                case MSG_ID_USER_STOP: {
                    OnUserStopped(msg);
                    break;
                }
                case MSG_ID_USER_UNLOCK: {
                    OnUserUnlocked(msg);
                    break;
                }
                case MSG_ID_USER_LOCK : {
                    OnUserLocked(msg);
                    break;
                }
                case MSG_ID_PACKAGE_ADDED: {
                    OnPackageAdded(msg);
                    break;
                }
                case MSG_ID_PACKAGE_REMOVED: {
                    OnPackageRemoved(msg);
                    break;
                }
                case MSG_ID_SETTING_CHANGED: {
                    OnSettingChanged(msg);
                    break;
                }
                case MSG_ID_DISPLAY_OPTIONAL_INPUT_METHOD: {
                    MessageParcel *data = msg->msgContent_;
                    int32_t userId = data->ReadInt32();
                    OnDisplayOptionalInputMethod(userId);
                    break;
                }
                case MSG_ID_PREPARE_INPUT:
                case MSG_ID_RELEASE_INPUT:
                case MSG_ID_START_INPUT:
                case MSG_ID_STOP_INPUT:
                case MSG_HIDE_CURRENT_INPUT:
                case MSG_SHOW_CURRENT_INPUT:
                case MSG_ID_SET_CORE_AND_AGENT:
                case MSG_ID_HIDE_KEYBOARD_SELF:
                case MSG_ID_SET_DISPLAY_MODE:
                case MSG_ID_CLIENT_DIED:
                case MSG_ID_IMS_DIED:
                case MSG_ID_RESTART_IMS: {
                    OnHandleMessage(msg);
                    break;
                }
                case MSG_ID_DISABLE_IMS: {
                    OnDisableIms(msg);
                    break;
                }
                case MSG_ID_ADVANCE_TO_NEXT: {
                    OnAdvanceToNext(msg);
                    break;
                }
                case MSG_ID_EXIT_SERVICE: {
                    std::map<int32_t, MessageHandler*>::const_iterator it;
                    for (it = msgHandlers.cbegin(); it != msgHandlers.cend();) {
                        MessageHandler *handler = it->second;
                        Message *destMsg = new Message(MSG_ID_EXIT_SERVICE, nullptr);
                        handler->SendMessage(destMsg);
                        PerUserSession *userSession = GetUserSession(it->first);
                        if (!userSession) {
                            IMSA_HILOGE("getUserSession fail.");
                            return;
                        }
                        userSession->JoinWorkThread();
                        it = msgHandlers.erase(it);
                        delete handler;
                        handler = nullptr;
                    }
                    delete msg;
                    msg = nullptr;
                    return;
                }
                case MSG_ID_SWITCH_INPUT_METHOD: {
                    MessageParcel *data = msg->msgContent_;
                    int32_t userId = data->ReadInt32();
                    auto target = data->ReadParcelable<InputMethodProperty>();
                    OnSwitchInputMethod(userId, *target);
                    delete target;
                    break;
                }
                case MSG_ID_START_INPUT_SERVICE: {
                    MessageParcel *data = msg->msgContent_;
                    const auto &ime = data->ReadString();
                    StartInputService(ime);
                    break;
                }
                default: {
                    break;
                }
            }
        }
    }

    /*! Called when a user is started. (EVENT_USER_STARTED is received)
    \n Run in work thread of input method management service
    \param msg the parameters are saved in msg->msgContent_
    \return ErrorCode
    */
    int32_t InputMethodSystemAbility::OnUserStarted(const Message *msg)
    {
        IMSA_HILOGI("InputMethodSystemAbility::OnUserStarted Start...\n");
        if (!msg->msgContent_) {
            IMSA_HILOGE("Aborted! %s\n", ErrorCode::ToString(ErrorCode::ERROR_BAD_PARAMETERS));
            return ErrorCode::ERROR_BAD_PARAMETERS;
        }
        std::string currentDefaultIme = ParaHandle::GetDefaultIme(userId_);
        int32_t userId = msg->msgContent_->ReadInt32();
        userId_ = userId;
        IMSA_HILOGI("InputMethodSystemAbility::OnUserStarted userId = %{public}u", userId);

        std::string newDefaultIme = ParaHandle::GetDefaultIme(userId_);

        if (newDefaultIme != currentDefaultIme) {
            StopInputService(currentDefaultIme);
            StartInputService(newDefaultIme);
        }

        PerUserSetting *setting = GetUserSetting(userId);
        if (setting) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_ALREADY_STARTED), userId);
            return ErrorCode::ERROR_USER_ALREADY_STARTED;
        }

        setting = new PerUserSetting(userId);
        setting->Initialize();
        PerUserSession *session = new PerUserSession(userId);

        userSettings.insert(std::pair<int32_t, PerUserSetting*>(userId, setting));
        userSessions.insert(std::pair<int32_t, PerUserSession*>(userId, session));
        return ErrorCode::NO_ERROR;
    }

    /*! Called when a user is stopped. (EVENT_USER_STOPPED is received)
    \n Run in work thread of input method management service
    \param msg the parameters are saved in msg->msgContent_
    \return ErrorCode
    */
    int32_t InputMethodSystemAbility::OnUserStopped(const Message *msg)
    {
        IMSA_HILOGI("Start...\n");
        if (!msg->msgContent_) {
            IMSA_HILOGE("Aborted! %s\n", ErrorCode::ToString(ErrorCode::ERROR_BAD_PARAMETERS));
            return ErrorCode::ERROR_BAD_PARAMETERS;
        }
        int32_t userId = msg->msgContent_->ReadInt32();
        PerUserSetting *setting = GetUserSetting(userId);
        PerUserSession *session = GetUserSession(userId);
        if (!setting || !session) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_STARTED), userId);
            return ErrorCode::ERROR_USER_NOT_STARTED;
        }
        if (setting->GetUserState() == UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_LOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_LOCKED;
        }
        std::map<int32_t, PerUserSession*>::iterator itSession = userSessions.find(userId);
        userSessions.erase(itSession);
        delete session;
        session = nullptr;

        std::map<int32_t, PerUserSetting*>::iterator itSetting = userSettings.find(userId);
        userSettings.erase(itSetting);
        delete setting;
        setting = nullptr;
        IMSA_HILOGI("End...[%d]\n", userId);
        return ErrorCode::NO_ERROR;
    }

    /*! Called when a user is unlocked. (EVENT_USER_UNLOCKED is received)
    \n Run in work thread of input method management service
    \param msg the parameters are saved in msg->msgContent_
    \return ErrorCode
    */
    int32_t InputMethodSystemAbility::OnUserUnlocked(const Message *msg)
    {
        IMSA_HILOGI("Start...\n");
        if (!msg->msgContent_) {
            IMSA_HILOGE("Aborted! %s\n", ErrorCode::ToString(ErrorCode::ERROR_BAD_PARAMETERS));
            return ErrorCode::ERROR_BAD_PARAMETERS;
        }
        int32_t userId = msg->msgContent_->ReadInt32();
        PerUserSetting *setting = GetUserSetting(userId);
        PerUserSession *session = GetUserSession(userId);
        if (!setting || !session) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_STARTED), userId);
            return ErrorCode::ERROR_USER_NOT_STARTED;
        }
        if (setting->GetUserState() == UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_ALREADY_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_ALREADY_UNLOCKED;
        }

        setting->Initialize();

        InputMethodProperty *ime = setting->GetSecurityInputMethod();
        session->SetSecurityIme(ime);
        ime = setting->GetCurrentInputMethod();
        session->SetCurrentIme(ime);
        session->SetInputMethodSetting(setting->GetInputMethodSetting());
        IMSA_HILOGI("End...[%d]\n", userId);
        return ErrorCode::NO_ERROR;
    }

    /*! Called when a user is locked. (EVENT_USER_LOCKED is received)
    \n Run in work thread of input method management service
    \param msg the parameters are saved in msg->msgContent_
    \return ErrorCode
    */
    int32_t InputMethodSystemAbility::OnUserLocked(const Message *msg)
    {
        IMSA_HILOGI("Start...\n");
        if (!msg->msgContent_) {
            IMSA_HILOGE("Aborted! %s\n", ErrorCode::ToString(ErrorCode::ERROR_BAD_PARAMETERS));
            return ErrorCode::ERROR_BAD_PARAMETERS;
        }
        int32_t userId = msg->msgContent_->ReadInt32();
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }
        std::map<int32_t, MessageHandler*>::iterator it = msgHandlers.find(userId);
        if (it != msgHandlers.end()) {
            MessageHandler *handler = it->second;
            Message *destMsg = new Message(MSG_ID_USER_LOCK, nullptr);
            if (destMsg) {
                handler->SendMessage(destMsg);
                PerUserSession *userSession = GetUserSession(userId);
                if (userSession) {
                    userSession->JoinWorkThread();
                }
                msgHandlers.erase(it);
                delete handler;
                handler = nullptr;
            }
        }
        setting->OnUserLocked();
        IMSA_HILOGI("End...[%d]\n", userId);
        return ErrorCode::NO_ERROR;
    }

    /*! Handle message
    \param msgId the id of message to run
    \msg the parameters are saved in msg->msgContent_
    \return ErrorCode::NO_ERROR
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    */
    int32_t InputMethodSystemAbility::OnHandleMessage(Message *msg)
    {
        MessageParcel *data = msg->msgContent_;
        int32_t userId = data->ReadInt32();
        PerUserSetting *setting = GetUserSetting(MAIN_USER_ID);
        if (!setting) {
            IMSA_HILOGE("InputMethodSystemAbility::OnHandleMessage Aborted! setting is nullptr");
        }
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("InputMethodSystemAbility::OnHandleMessage Aborted! userId = %{public}d,", userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }

        std::map<int32_t, MessageHandler*>::const_iterator it = msgHandlers.find(MAIN_USER_ID);
        if (it != msgHandlers.end()) {
            MessageHandler *handler = it->second;
            handler->SendMessage(msg);
        }
        return ErrorCode::NO_ERROR;
    }

    /*! Called when a package is installed.
    \n Run in work thread of input method management service
    \param msg the parameters are saved in msg->msgContent_
    \return ErrorCode::NO_ERROR
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    \return ErrorCode::ERROR_BAD_PARAMETERS bad parameter
    */
    int32_t InputMethodSystemAbility::OnPackageAdded(const Message *msg)
    {
        IMSA_HILOGI("Start...\n");
        MessageParcel *data = msg->msgContent_;
        int32_t userId = data->ReadInt32();
        int32_t size = data->ReadInt32();

        if (size <= 0) {
            IMSA_HILOGE("Aborted! %s\n", ErrorCode::ToString(ErrorCode::ERROR_BAD_PARAMETERS));
            return ErrorCode::ERROR_BAD_PARAMETERS;
        }
        std::u16string packageName = data->ReadString16();
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }
        bool securityImeFlag = false;
        int32_t ret = setting->OnPackageAdded(packageName, securityImeFlag);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGI("End...\n");
            return ret;
        }
        if (securityImeFlag) {
            InputMethodProperty *securityIme = setting->GetSecurityInputMethod();
            InputMethodProperty *defaultIme = setting->GetCurrentInputMethod();
            PerUserSession *session = GetUserSession(userId);
            if (session == nullptr) {
                IMSA_HILOGI("InputMethodSystemAbility::OnPackageAdded session is nullptr");
                return ErrorCode::ERROR_NULL_POINTER;
            }
            session->ResetIme(defaultIme, securityIme);
        }
        IMSA_HILOGI("End...\n");
        return 0;
    }

    /*! Called when a package is removed.
    \n Run in work thread of input method management service
    \param msg the parameters are saved in msg->msgContent_
    \return ErrorCode::NO_ERROR
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    \return ErrorCode::ERROR_BAD_PARAMETERS bad parameter
    */
    int32_t InputMethodSystemAbility::OnPackageRemoved(const Message *msg)
    {
        IMSA_HILOGI("Start...\n");
        MessageParcel *data = msg->msgContent_;
        if (!data) {
            IMSA_HILOGI("InputMethodSystemAbility::OnPackageRemoved data is nullptr");
            return ErrorCode::ERROR_NULL_POINTER;
        }
        int32_t userId = data->ReadInt32();
        int32_t size = data->ReadInt32();

        if (size <= 0) {
            IMSA_HILOGE("Aborted! %s\n", ErrorCode::ToString(ErrorCode::ERROR_BAD_PARAMETERS));
            return ErrorCode::ERROR_BAD_PARAMETERS;
        }
        std::u16string packageName = data->ReadString16();
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }
        PerUserSession *session = GetUserSession(userId);
        if (!session) {
            IMSA_HILOGI("InputMethodSystemAbility::OnPackageRemoved session is nullptr");
            return ErrorCode::ERROR_NULL_POINTER;
        }
        session->OnPackageRemoved(packageName);
        bool securityImeFlag = false;
        int32_t ret = setting->OnPackageRemoved(packageName, securityImeFlag);
        if (ret != ErrorCode::NO_ERROR) {
            IMSA_HILOGI("End...\n");
            return ret;
        }
        if (securityImeFlag) {
            InputMethodProperty *securityIme = setting->GetSecurityInputMethod();
            InputMethodProperty *defaultIme = setting->GetCurrentInputMethod();
            session->ResetIme(defaultIme, securityIme);
        }
        return 0;
    }

    /*! Called when input method setting data is changed.
    \n Run in work thread of input method management service
    \param msg the parameters from remote binder are saved in msg->msgContent_
    \return ErrorCode::NO_ERROR
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    \return ErrorCode::ERROR_BAD_PARAMETERS bad parameter
    */
    int32_t InputMethodSystemAbility::OnSettingChanged(const Message *msg)
    {
        IMSA_HILOGI("Start...\n");
        MessageParcel *data = msg->msgContent_;
        int32_t userId = data->ReadInt32();
        int32_t size = data->ReadInt32();
        if (size < 2) {
            IMSA_HILOGE("Aborted! %s\n", ErrorCode::ToString(ErrorCode::ERROR_BAD_PARAMETERS));
            return ErrorCode::ERROR_BAD_PARAMETERS;
        }
        std::u16string updatedKey = data->ReadString16();
        std::u16string updatedValue = data->ReadString16();
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }
        PerUserSession *session = GetUserSession(userId);
        if (!session) {
            return ErrorCode::ERROR_NULL_POINTER;
        }
        int32_t ret = session->OnSettingChanged(updatedKey, updatedValue);
        if (ret == ErrorCode::ERROR_SETTING_SAME_VALUE) {
            IMSA_HILOGI("End...No need to update\n");
            return ret;
        }

        // PerUserSetting does not need handle keyboard type change notification
        if (updatedKey == InputMethodSetting::CURRENT_KEYBOARD_TYPE_TAG ||
            updatedKey == InputMethodSetting::CURRENT_SYS_KEYBOARD_TYPE_TAG) {
            IMSA_HILOGI("End...\n");
            return ErrorCode::NO_ERROR;
        }

        ret = setting->OnSettingChanged(updatedKey, updatedValue);
        if (ret) {
            IMSA_HILOGI("End...No need to update\n");
            return ret;
        }

        InputMethodProperty *securityIme = setting->GetSecurityInputMethod();
        InputMethodProperty *defaultIme = setting->GetCurrentInputMethod();
        session->ResetIme(defaultIme, securityIme);
        IMSA_HILOGI("End...\n");
        return ErrorCode::NO_ERROR;
    }

    int32_t InputMethodSystemAbility::OnSwitchInputMethod(int32_t userId, const InputMethodProperty &target)
    {
        IMSA_HILOGI("InputMethodSystemAbility::OnSwitchInputMethod");
        const auto &properties = ListInputMethodByUserId(userId, ALL);
        if (properties.empty()) {
            IMSA_HILOGE("InputMethodSystemAbility::OnSwitchInputMethod has no ime");
            return ErrorCode::ERROR_BAD_PARAMETERS;
        }
        bool isTargetFound = false;
        for (const auto &property : properties) {
            if (property.mPackageName == target.mPackageName) {
                isTargetFound = true;
                IMSA_HILOGI("InputMethodSystemAbility::OnSwitchInputMethod target is found in installed packages!");
            }
        }
        if (!isTargetFound) {
            IMSA_HILOGE("InputMethodSystemAbility::OnSwitchInputMethod target is not an installed package !");
            return ErrorCode::ERROR_NOT_IME_PACKAGE;
        }

        std::string defaultIme = ParaHandle::GetDefaultIme(userId_);
        std::string targetIme = Str16ToStr8(target.mPackageName) + "/" + Str16ToStr8(target.mAbilityName);
        IMSA_HILOGI("InputMethodSystemAbility::OnSwitchInputMethod DefaultIme : %{public}s, TargetIme : %{public}s",
            defaultIme.c_str(), targetIme.c_str());
        if (defaultIme != targetIme) {
            IMSA_HILOGI("InputMethodSystemAbility::OnSwitchInputMethod DefaultIme is "
                      "not target! Start Switching IME !");
            StopInputService(defaultIme);
            if (!StartInputService(targetIme)) {
                return ErrorCode::ERROR_IME_START_FAILED;
            }
            bool setResult = ParaHandle::SetDefaultIme(userId_, targetIme);
            if (setResult) {
                IMSA_HILOGI("InputMethodSystemAbility::OnSwitchInputMethod SetDefaultIme Successfully.");
            } else {
                IMSA_HILOGI("InputMethodSystemAbility::OnSwitchInputMethod SetDefaultIme Failed. setResult = "
                            "%{public}d",
                    setResult);
                return ErrorCode::ERROR_STATUS_PERMISSION_DENIED;
            }
        } else {
            IMSA_HILOGI("InputMethodSystemAbility::OnSwitchInputMethod DefaultIme and TargetIme are the same one!");
        }
        return ErrorCode::NO_ERROR;
    }

    void InputMethodSystemAbility::OnDisplayOptionalInputMethod(int32_t userId)
    {
        IMSA_HILOGI("InputMethodSystemAbility::OnDisplayOptionalInputMethod");
        if (dialogLock_.test_and_set()) {
            IMSA_HILOGE("Dialog is showing, no need to display again");
            return;
        }
        const auto &properties = ListInputMethodByUserId(userId, ALL);
        if (properties.empty()) {
            IMSA_HILOGI("InputMethodSystemAbility::OnDisplayOptionalInputMethod has no ime");
            return;
        }
        const auto &params = GetInputMethodParam(properties);
        IMSA_HILOGI("InputMethodSystemAbility::OnDisplayOptionalInputMethod param : %{public}s", params.c_str());
        const int TITLE_HEIGHT = 62;
        const int SINGLE_IME_HEIGHT = 66;
        const int POSTION_X = 0;
        const int POSTION_Y = 200;
        const int WIDTH = 336;
        const int HEIGHT = POSTION_Y + TITLE_HEIGHT + SINGLE_IME_HEIGHT * properties.size();
        Ace::UIServiceMgrClient::GetInstance()->ShowDialog(
            "input_method_choose_dialog",
            params,
            OHOS::Rosen::WindowType::WINDOW_TYPE_SYSTEM_ALARM_WINDOW,
            POSTION_X,
            POSTION_Y,
            WIDTH,
            HEIGHT,
            [this](int32_t id, const std::string& event, const std::string& params) {
                IMSA_HILOGI("Dialog callback: %{public}s, %{public}s", event.c_str(), params.c_str());
                if (event == "EVENT_CHANGE_IME") {
                    std::string defaultIme = ParaHandle::GetDefaultIme(userId_);
                    if (defaultIme != params) {
                        StopInputService(defaultIme);
                        StartInputService(params);
                        ParaHandle::SetDefaultIme(userId_, params);
                    }
                    Ace::UIServiceMgrClient::GetInstance()->CancelDialog(id);
                    dialogLock_.clear();
                } else if (event == "EVENT_START_IME_SETTING") {
                    Ace::UIServiceMgrClient::GetInstance()->CancelDialog(id);
                    dialogLock_.clear();
                }
        });
    }

    /*! Disable input method service. Called from PerUserSession module
    \n Run in work thread of input method management service
    \param msg the parameters are saved in msg->msgContent_
    \return ErrorCode::NO_ERROR
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    */
    int32_t InputMethodSystemAbility::OnDisableIms(const Message *msg)
    {
        IMSA_HILOGI("Start...\n");
        MessageParcel *data = msg->msgContent_;
        int32_t userId = data->ReadInt32();
        std::u16string imeId = data->ReadString16();
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }

        InputMethodSetting tmpSetting;
        std::u16string key = InputMethodSetting::ENABLED_INPUT_METHODS_TAG;
        tmpSetting.SetValue(key, setting->GetInputMethodSetting()->GetValue(key));
        tmpSetting.RemoveEnabledInputMethod(imeId);
        IMSA_HILOGI("End...\n");
        return ErrorCode::NO_ERROR;
    }

    /*! Switch to next ime or next keyboard type. It's called by input method service
    \n Run in work thread of input method management service or the work thread of PerUserSession
    \param msg the parameters from remote binder are saved in msg->msgContent_
    \return ErrorCode::NO_ERROR
    \return ErrorCode::ERROR_USER_NOT_UNLOCKED user not unlocked
    */
    int32_t InputMethodSystemAbility::OnAdvanceToNext(const Message *msg)
    {
        IMSA_HILOGI("Start...\n");
        MessageParcel *data = msg->msgContent_;
        int32_t userId = data->ReadInt32();
        bool isCurrentIme = data->ReadBool();
        PerUserSetting *setting = GetUserSetting(userId);
        if (!setting || setting->GetUserState() != UserState::USER_STATE_UNLOCKED) {
            IMSA_HILOGE("Aborted! %s %d\n", ErrorCode::ToString(ErrorCode::ERROR_USER_NOT_UNLOCKED), userId);
            return ErrorCode::ERROR_USER_NOT_UNLOCKED;
        }
        if (isCurrentIme) {
            std::map<int32_t, MessageHandler*>::const_iterator it = msgHandlers.find(userId);
            if (it != msgHandlers.end()) {
                Message *destMsg = new Message(msg->msgId_, nullptr);
                it->second->SendMessage(destMsg);
            }
        } else {
            setting->OnAdvanceToNext();
        }
        IMSA_HILOGI("End...\n");
        return ErrorCode::NO_ERROR;
    }

    sptr<OHOS::AppExecFwk::IBundleMgr> InputMethodSystemAbility::GetBundleMgr()
    {
        IMSA_HILOGI("InputMethodSystemAbility::GetBundleMgr");
        sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (!systemAbilityManager) {
            IMSA_HILOGI("InputMethodSystemAbility::GetBundleMgr systemAbilityManager is nullptr");
            return nullptr;
        }
        sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        return iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    }

    sptr<AAFwk::IAbilityManager> InputMethodSystemAbility::GetAbilityManagerService()
    {
        IMSA_HILOGE("InputMethodSystemAbility::GetAbilityManagerService start");
        sptr<IRemoteObject> abilityMsObj =
        OHOS::DelayedSingleton<AAFwk::SaMgrClient>::GetInstance()->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
        if (!abilityMsObj) {
            IMSA_HILOGE("failed to get ability manager service");
            return nullptr;
        }
        return iface_cast<AAFwk::IAbilityManager>(abilityMsObj);
    }
} // namespace MiscServices
} // namespace OHOS
