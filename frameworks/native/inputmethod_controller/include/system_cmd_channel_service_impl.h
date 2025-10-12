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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_CLIENT_IMPL_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_CLIENT_IMPL_H

#include "system_ability.h"

#include "isystem_cmd_channel.h"
#include "system_cmd_channel_stub.h"
#include "iremote_object.h"

namespace OHOS {
namespace MiscServices {
class SystemCmdChannelServiceImpl final : public SystemCmdChannelStub,
    public std::enable_shared_from_this<SystemCmdChannelServiceImpl> {
    DISALLOW_COPY_AND_MOVE(SystemCmdChannelServiceImpl);

public:
    SystemCmdChannelServiceImpl();
    ~SystemCmdChannelServiceImpl();
    ErrCode SendPrivateCommand(const Value &value) override;
    ErrCode NotifyPanelStatus(const SysPanelStatus &sysPanelStatus) override;
    ErrCode SetPanelShadow(const Shadow &shadow) override;
};
}  // namespace MiscServices
}  // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_CLIENT_IMPL_H