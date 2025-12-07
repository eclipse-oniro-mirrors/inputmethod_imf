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
#ifndef TAIHE_INPUT_METHOD_CLIENT_IMPL_H
#define TAIHE_INPUT_METHOD_CLIENT_IMPL_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ani_common_engine.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"
#include "text_input_client_listener.h"
namespace OHOS {
namespace MiscServices {
class InputMethodClientImpl : public TextInputClientListener {
public:
    static std::shared_ptr<InputMethodClientImpl> GetInstance();
    static ani_ref GetInputClientInstance(ani_env *env);
    static bool InitTextInputClientEngine();
    static bool Init();
    void RegisterListener(std::string const &type, callbackTypes &&cb, uintptr_t opq);
    void UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq);
    void OnAttachOptionsChanged(const AttachOptions &attachOptions) override;
private:
    std::mutex mutex_;
    std::map<std::string, std::vector<std::unique_ptr<CallbackObjects>>> jsCbMap_;
    static std::mutex engineMutex_;
    static ani_ref TICRef_;
    static std::shared_ptr<InputMethodClientImpl> textInputClientEngine_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_INPUT_METHOD_CLIENT_IMPL_H