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
#ifndef TEXT_EDITOR_PROXY_MANAGER_H
#define TEXT_EDITOR_PROXY_MANAGER_H

#include <memory>
#include <mutex>
#include <unordered_map>

#include "native_inputmethod_types.h"

namespace OHOS {
namespace MiscServices {
class TextEditorProxyManager {
public:
    static TextEditorProxyManager &GetInstance();
    void Register(InputMethod_TextEditorProxy *raw);
    void Unregister(InputMethod_TextEditorProxy *raw);
    std::weak_ptr<InputMethod_TextEditorProxy> GetWeak(InputMethod_TextEditorProxy *raw);

private:
    TextEditorProxyManager() = default;
    ~TextEditorProxyManager() = default;
    TextEditorProxyManager(const TextEditorProxyManager &) = delete;
    TextEditorProxyManager &operator=(const TextEditorProxyManager &) = delete;

    std::mutex proxiesMtx_;
    std::unordered_map<InputMethod_TextEditorProxy *, std::shared_ptr<InputMethod_TextEditorProxy>> proxies_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // TEXT_EDITOR_PROXY_MANAGER_H
