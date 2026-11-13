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
#include "global.h"
#include "native_inputmethod_types.h"
#include "text_editor_proxy_manager.h"

using namespace OHOS::MiscServices;
InputMethod_TextEditorProxy *OH_TextEditorProxy_Create(void)
{
    auto *raw = new (std::nothrow) InputMethod_TextEditorProxy();
    if (raw == nullptr) {
        IMSA_HILOGE("new InputMethod_TextEditorProxy failed");
        return nullptr;
    }
    TextEditorProxyManager::GetInstance().Register(raw);
    return raw;
}

void OH_TextEditorProxy_Destroy(InputMethod_TextEditorProxy *proxy)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return;
    }
    TextEditorProxyManager::GetInstance().Unregister(proxy);
}

InputMethod_ErrorCode OH_TextEditorProxy_SetGetTextConfigFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_GetTextConfigFunc getTextConfigFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (getTextConfigFunc == nullptr) {
        IMSA_HILOGE("getTextConfigFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->getTextConfigFunc.store(getTextConfigFunc);
    return IME_ERR_OK;
}
InputMethod_ErrorCode OH_TextEditorProxy_SetInsertTextFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_InsertTextFunc insertTextFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (insertTextFunc == nullptr) {
        IMSA_HILOGE("insertTextFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->insertTextFunc.store(insertTextFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetDeleteForwardFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_DeleteForwardFunc deleteForwardFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (deleteForwardFunc == nullptr) {
        IMSA_HILOGE("deleteForwardFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->deleteForwardFunc.store(deleteForwardFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetDeleteBackwardFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_DeleteBackwardFunc deleteBackwardFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (deleteBackwardFunc == nullptr) {
        IMSA_HILOGE("deleteBackwardFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->deleteBackwardFunc.store(deleteBackwardFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetSendKeyboardStatusFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_SendKeyboardStatusFunc sendKeyboardStatusFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (sendKeyboardStatusFunc == nullptr) {
        IMSA_HILOGE("sendKeyboardStatusFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->sendKeyboardStatusFunc.store(sendKeyboardStatusFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetSendEnterKeyFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_SendEnterKeyFunc sendEnterKeyFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (sendEnterKeyFunc == nullptr) {
        IMSA_HILOGE("sendEnterKeyFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->sendEnterKeyFunc.store(sendEnterKeyFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetMoveCursorFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_MoveCursorFunc moveCursorFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (moveCursorFunc == nullptr) {
        IMSA_HILOGE("moveCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->moveCursorFunc.store(moveCursorFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetHandleSetSelectionFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_HandleSetSelectionFunc handleSetSelectionFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (handleSetSelectionFunc == nullptr) {
        IMSA_HILOGE("handleSetSelectionFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->handleSetSelectionFunc.store(handleSetSelectionFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetHandleExtendActionFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_HandleExtendActionFunc handleExtendActionFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (handleExtendActionFunc == nullptr) {
        IMSA_HILOGE("handleExtendActionFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->handleExtendActionFunc.store(handleExtendActionFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetGetLeftTextOfCursorFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_GetLeftTextOfCursorFunc getLeftTextOfCursorFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (getLeftTextOfCursorFunc == nullptr) {
        IMSA_HILOGE("getLeftTextOfCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->getLeftTextOfCursorFunc.store(getLeftTextOfCursorFunc);
    return IME_ERR_OK;
}
InputMethod_ErrorCode OH_TextEditorProxy_SetGetRightTextOfCursorFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_GetRightTextOfCursorFunc getRightTextOfCursorFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (getRightTextOfCursorFunc == nullptr) {
        IMSA_HILOGE("getRightTextOfCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->getRightTextOfCursorFunc.store(getRightTextOfCursorFunc);
    return IME_ERR_OK;
}
InputMethod_ErrorCode OH_TextEditorProxy_SetGetTextIndexAtCursorFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_GetTextIndexAtCursorFunc getTextIndexAtCursorFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (getTextIndexAtCursorFunc == nullptr) {
        IMSA_HILOGE("getTextIndexAtCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->getTextIndexAtCursorFunc.store(getTextIndexAtCursorFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetReceivePrivateCommandFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_ReceivePrivateCommandFunc receivePrivateCommandFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (receivePrivateCommandFunc == nullptr) {
        IMSA_HILOGE("receivePrivateCommandFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->receivePrivateCommandFunc.store(receivePrivateCommandFunc);
    return IME_ERR_OK;
}
InputMethod_ErrorCode OH_TextEditorProxy_SetSetPreviewTextFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_SetPreviewTextFunc setPreviewTextFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (setPreviewTextFunc == nullptr) {
        IMSA_HILOGE("setPreviewTextFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->setPreviewTextFunc.store(setPreviewTextFunc);
    return IME_ERR_OK;
}
InputMethod_ErrorCode OH_InputMethod_TextEditorProxy_SetSetPreviewTextWithStyleFunc(InputMethod_TextEditorProxy *proxy,
    OH_InputMethod_TextEditorProxy_SetPreviewTextWithStyleFunc setPreviewTextWithStyleFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (setPreviewTextWithStyleFunc == nullptr) {
        IMSA_HILOGE("setPreviewTextWithStyleFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    proxy->setPreviewTextWithStyleFunc = setPreviewTextWithStyleFunc;
    return IME_ERR_OK;
}
InputMethod_ErrorCode OH_TextEditorProxy_SetFinishTextPreviewFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_FinishTextPreviewFunc finishTextPreviewFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (finishTextPreviewFunc == nullptr) {
        IMSA_HILOGE("finishTextPreviewFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->finishTextPreviewFunc.store(finishTextPreviewFunc);
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetGetTextConfigFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_GetTextConfigFunc *getTextConfigFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (getTextConfigFunc == nullptr) {
        IMSA_HILOGE("getTextConfigFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *getTextConfigFunc = lease->getTextConfigFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetInsertTextFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_InsertTextFunc *insertTextFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (insertTextFunc == nullptr) {
        IMSA_HILOGE("insertTextFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *insertTextFunc = lease->insertTextFunc.load();
    return IME_ERR_OK;
}
InputMethod_ErrorCode OH_TextEditorProxy_GetDeleteForwardFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_DeleteForwardFunc *deleteForwardFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (deleteForwardFunc == nullptr) {
        IMSA_HILOGE("deleteForwardFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *deleteForwardFunc = lease->deleteForwardFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetDeleteBackwardFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_DeleteBackwardFunc *deleteBackwardFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (deleteBackwardFunc == nullptr) {
        IMSA_HILOGE("deleteBackwardFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *deleteBackwardFunc = lease->deleteBackwardFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetSendKeyboardStatusFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_SendKeyboardStatusFunc *sendKeyboardStatusFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (sendKeyboardStatusFunc == nullptr) {
        IMSA_HILOGE("sendKeyboardStatusFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *sendKeyboardStatusFunc = lease->sendKeyboardStatusFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetSendEnterKeyFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_SendEnterKeyFunc *sendEnterKeyFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (sendEnterKeyFunc == nullptr) {
        IMSA_HILOGE("sendEnterKeyFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *sendEnterKeyFunc = lease->sendEnterKeyFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetMoveCursorFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_MoveCursorFunc *moveCursorFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (moveCursorFunc == nullptr) {
        IMSA_HILOGE("moveCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *moveCursorFunc = lease->moveCursorFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetHandleSetSelectionFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_HandleSetSelectionFunc *handleSetSelectionFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (handleSetSelectionFunc == nullptr) {
        IMSA_HILOGE("handleSetSelectionFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *handleSetSelectionFunc = lease->handleSetSelectionFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetHandleExtendActionFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_HandleExtendActionFunc *handleExtendActionFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (handleExtendActionFunc == nullptr) {
        IMSA_HILOGE("handleExtendActionFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *handleExtendActionFunc = lease->handleExtendActionFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetGetLeftTextOfCursorFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_GetLeftTextOfCursorFunc *getLeftTextOfCursorFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (getLeftTextOfCursorFunc == nullptr) {
        IMSA_HILOGE("getLeftTextOfCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *getLeftTextOfCursorFunc = lease->getLeftTextOfCursorFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetGetRightTextOfCursorFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_GetRightTextOfCursorFunc *getRightTextOfCursorFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (getRightTextOfCursorFunc == nullptr) {
        IMSA_HILOGE("getRightTextOfCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *getRightTextOfCursorFunc = lease->getRightTextOfCursorFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetGetTextIndexAtCursorFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_GetTextIndexAtCursorFunc *getTextIndexAtCursorFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (getTextIndexAtCursorFunc == nullptr) {
        IMSA_HILOGE("getTextIndexAtCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *getTextIndexAtCursorFunc = lease->getTextIndexAtCursorFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetReceivePrivateCommandFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_ReceivePrivateCommandFunc *receivePrivateCommandFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (receivePrivateCommandFunc == nullptr) {
        IMSA_HILOGE("receivePrivateCommandFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *receivePrivateCommandFunc = lease->receivePrivateCommandFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetSetPreviewTextFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_SetPreviewTextFunc *setPreviewTextFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (setPreviewTextFunc == nullptr) {
        IMSA_HILOGE("setPreviewTextFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *setPreviewTextFunc = lease->setPreviewTextFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_InputMethod_TextEditorProxy_GetSetPreviewTextWithStyleFunc(InputMethod_TextEditorProxy *proxy,
    OH_InputMethod_TextEditorProxy_SetPreviewTextWithStyleFunc *setPreviewTextWithStyleFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (setPreviewTextWithStyleFunc == nullptr) {
        IMSA_HILOGE("setPreviewTextWithStyleFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    *setPreviewTextWithStyleFunc = proxy->setPreviewTextWithStyleFunc;
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_GetFinishTextPreviewFunc(
    InputMethod_TextEditorProxy *proxy, OH_TextEditorProxy_FinishTextPreviewFunc *finishTextPreviewFunc)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (finishTextPreviewFunc == nullptr) {
        IMSA_HILOGE("finishTextPreviewFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    *finishTextPreviewFunc = lease->finishTextPreviewFunc.load();
    return IME_ERR_OK;
}

InputMethod_ErrorCode OH_TextEditorProxy_SetCallbackInMainThread(
    InputMethod_TextEditorProxy *proxy, bool isCallbackInMainThread)
{
    if (proxy == nullptr) {
        IMSA_HILOGE("proxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    IMSA_HILOGI("isCallbackInMainThread: %{public}d", isCallbackInMainThread);
    auto lease = TextEditorProxyManager::GetInstance().GetWeak(proxy).lock();
    if (lease == nullptr) {
        IMSA_HILOGE("TextEditorProxy is unregistered or destroyed.");
        return IME_ERR_NULL_POINTER;
    }
    lease->isCallbackInMainThread = isCallbackInMainThread;
    return IME_ERR_OK;
}