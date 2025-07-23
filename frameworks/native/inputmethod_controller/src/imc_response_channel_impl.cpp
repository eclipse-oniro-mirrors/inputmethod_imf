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

#include "imc_response_channel_impl.h"

#include "imc_service_proxy.h"

namespace OHOS {
namespace MiscServices {

ImcResponseChannelImpl::ImcResponseChannelImpl()
{
}

ImcResponseChannelImpl::~ImcResponseChannelImpl()
{
}

ErrCode ImcResponseChannelImpl::OnResponse(
    uint32_t requestId, int32_t resultErrCode, const ServiceResponseDataInner &response)
{
    ServiceResponse serviceResponse = { .result = resultErrCode, .responseData = response.data };
    ImcServiceProxy::GetInstance().OnResponse(requestId, serviceResponse);
    return ERR_OK;
}
} // namespace MiscServices
} // namespace OHOS