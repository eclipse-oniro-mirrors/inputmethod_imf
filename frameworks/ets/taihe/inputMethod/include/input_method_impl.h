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
#ifndef TAIHE_INPUT_METHOD_IMPL_H
#define TAIHE_INPUT_METHOD_IMPL_H
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <set>

#include "ani_common.h"
#include "input_method_utils.h"
#include "ohos.inputMethod.impl.hpp"
#include "ohos.inputMethod.proj.hpp"
#include "imc_inner_listener.h"
namespace OHOS {
namespace MiscServices {
class InputMethodImpl : public ImcInnerListener {
public:
    static std::shared_ptr<InputMethodImpl> GetInstance();
    void RegisterListener(std::string const &type, callbackType &&cb, uintptr_t opq);
    void UnRegisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq);
    static void OnAttachmentDidFail(AttachFailureReason reason, const std::shared_ptr<CallbackObject> &jsCbObject);
    void OnAttachmentDidFail(AttachFailureReason reason) override;
private:
    static std::mutex jsCbsLock_;
    static std::mutex listenerMutex_;
    static std::shared_ptr<InputMethodImpl> listener_;
    static constexpr const char *ATTACH_FAIL_CB_EVENT_TYPE = "attachmentDidFail";
    static std::unordered_map<std::string, std::vector<std::shared_ptr<CallbackObject>>> jsCbMap_;
    static void SetImcInnerListener();
    std::vector<std::shared_ptr<CallbackObject>> GetJsCbObjects(const std::string &type);
};
} // namespace MiscServices
} // namespace OHOS
#endif // TAIHE_INPUT_METHOD_IMPL_H