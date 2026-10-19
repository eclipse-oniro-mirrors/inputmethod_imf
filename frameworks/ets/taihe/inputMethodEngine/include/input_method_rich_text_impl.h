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
#ifndef INPUT_METHOD_RICH_TEXT_IMPL_H
#define INPUT_METHOD_RICH_TEXT_IMPL_H

#include "input_method_utils.h"
#include "ohos.inputMethodEngine.proj.hpp"
#include "ohos.inputMethodEngine.impl.hpp"

namespace OHOS {
namespace MiscServices {
class RichTextSpanImpl {
public:
    explicit RichTextSpanImpl(const SpanType &type, const std::string &content, const Range &range)
        : type_(type), content_(content), range_(range) {}
    ~RichTextSpanImpl() = default;

    ohos::inputMethodEngine::SpanType GetType();
    taihe::string GetContent();
    ohos::inputMethodEngine::Range GetRange();

private:
    SpanType type_;
    std::string content_;
    Range range_;
};

class InputMethodRichTextImpl {
public:
    explicit InputMethodRichTextImpl(const RichTextData &richText) : richText_(richText) {}
    ~InputMethodRichTextImpl() = default;

    taihe::string GetString();
    taihe::array<ohos::inputMethodEngine::RichTextSpan> GetSpans();

private:
    RichTextData richText_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // INPUT_METHOD_RICH_TEXT_IMPL_H
