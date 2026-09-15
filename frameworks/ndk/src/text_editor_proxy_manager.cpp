/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "text_editor_proxy_manager.h"

#include "global.h"
namespace OHOS {
namespace MiscServices {
TextEditorProxyManager &TextEditorProxyManager::GetInstance()
{
    static TextEditorProxyManager instance;
    return instance;
}

void TextEditorProxyManager::Register(InputMethod_TextEditorProxy *raw)
{
    if (raw == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(proxiesMtx_);
    auto sp = std::shared_ptr<InputMethod_TextEditorProxy>(raw);
    proxies_.try_emplace(raw, std::move(sp));
}

void TextEditorProxyManager::Unregister(InputMethod_TextEditorProxy *raw)
{
    if (raw == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(proxiesMtx_);
    proxies_.erase(raw);
}

std::weak_ptr<InputMethod_TextEditorProxy> TextEditorProxyManager::GetWeak(InputMethod_TextEditorProxy *raw)
{
    if (raw == nullptr) {
        return {};
    }
    std::lock_guard<std::mutex> lock(proxiesMtx_);
    auto it = proxies_.find(raw);
    if (it == proxies_.end()) {
        IMSA_HILOGE("raw not find in proxies_");
        return {};
    }
    return std::weak_ptr<InputMethod_TextEditorProxy>(it->second);
}
} // namespace MiscServices
} // namespace OHOS
