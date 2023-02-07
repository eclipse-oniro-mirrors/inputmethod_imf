/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef INPUTMETHOD_IMF_CONTROLLER_LISTENER_H
#define INPUTMETHOD_IMF_CONTROLLER_LISTENER_H

namespace OHOS {
namespace MiscServices {
class ControllerListener {
public:
    virtual ~ControllerListener() = default;
    virtual void OnSelectByRange(int32_t start, int32_t end) = 0;
    virtual void OnSelectByMovement(int32_t direction) = 0;
};
} // namespace MiscServices
} // namespace OHOS
#endif // INPUTMETHOD_IMF_CONTROLLER_LISTENER_H