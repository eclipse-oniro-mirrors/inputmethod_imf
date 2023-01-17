/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "para_handle.h"

#include "parameter.h"
#include "global.h"
namespace OHOS {
namespace MiscServices {
const char *ParaHandle::DEFAULT_IME_KEY = "persist.sys.default_ime";
std::string ParaHandle::GetDefaultIme()
{
    IMSA_HILOGI("GetDefaultIme::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    char value[CONFIG_LEN] = { 0 };
    int code = 0;
    code = GetParameter(DEFAULT_IME_KEY, "", value, CONFIG_LEN);
    if (code > 0) {
        IMSA_HILOGI("GetDefaultIme::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
        return value;
    }
    return "";
}
} // namespace MiscServices
} // namespace OHOS
