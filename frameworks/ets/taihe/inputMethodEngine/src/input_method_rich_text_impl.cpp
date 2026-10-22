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
#include "input_method_rich_text_impl.h"

namespace OHOS {
namespace MiscServices {
ohos::inputMethodEngine::SpanType RichTextSpanImpl::GetType()
{
    return ohos::inputMethodEngine::SpanType::from_value(static_cast<uint32_t>(type_));
}

taihe::string RichTextSpanImpl::GetContent()
{
    return taihe::string(content_);
}

ohos::inputMethodEngine::Range RichTextSpanImpl::GetRange()
{
    return ohos::inputMethodEngine::Range{range_.start, range_.end};
}

taihe::string InputMethodRichTextImpl::GetString()
{
    std::string result;
    for (const auto &span : richText_.spans) {
        if (span.type == SpanType::TEXT || span.type == SpanType::SYMBOL) {
            result += span.content;
        } else {
            result += " ";
        }
    }
    return taihe::string(result);
}

taihe::array<ohos::inputMethodEngine::RichTextSpan> InputMethodRichTextImpl::GetSpans()
{
    std::vector<ohos::inputMethodEngine::RichTextSpan> vecSpans;
    for (const auto &span : richText_.spans) {
        auto spanImpl = taihe::make_holder<RichTextSpanImpl, ohos::inputMethodEngine::RichTextSpan>(
            span.type, span.content, span.range);
        vecSpans.push_back(ohos::inputMethodEngine::RichTextSpan(std::move(spanImpl)));
    }
    return taihe::array<ohos::inputMethodEngine::RichTextSpan>(vecSpans);
}
} // namespace MiscServices
} // namespace OHOS
