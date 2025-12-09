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
int32_t AniMessageHandler::OnTerminated()
{
    UndefinedType_t type = UndefinedType_t::make_undefined();
    handler_.onTerminated(type);
    return ErrorCode::NO_ERROR;
}

int32_t AniMessageHandler::OnMessage(const ArrayBuffer &arrayBuffer)
{
    if (!ArrayBuffer::IsSizeValid(arrayBuffer)) {
        IMSA_HILOGE("msgId limit 256B and msgParam limit 128KB.");
        return ErrorCode::ERROR_PARAMETER_CHECK_FAILED;
    }
    ::taihe::array<uint8_t> thArray =
        ::taihe::array<uint8_t>(taihe::copy_data_t{}, arrayBuffer.msgParam.data(), arrayBuffer.msgParam.size());
    handler_.onMessage(::taihe::string(arrayBuffer.msgId),
        taihe::optional<::taihe::array<uint8_t>>(std::in_place_t{}, thArray));
    return ErrorCode::NO_ERROR;
}
} // namespace MiscServices
} // namespace OHOS