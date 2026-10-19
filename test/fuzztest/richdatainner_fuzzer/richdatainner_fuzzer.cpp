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

#include "richdatainner_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "global.h"
#include "input_method_utils.h"
#include "message_parcel.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::MiscServices;
namespace OHOS {
constexpr size_t THRESHOLD = 4;
constexpr size_t MAX_FUZZ_STRING_LEN = 256;

bool FuzzRichDataInner(FuzzedDataProvider &provider)
{
    uint32_t spanCount = provider.ConsumeIntegral<uint32_t>() % 20;
    RichTextDataInner inner;
    for (uint32_t i = 0; i < spanCount; i++) {
        RichTextSpan span;
        span.type = static_cast<SpanType>(provider.ConsumeIntegral<uint32_t>() % SPAN_TYPE_COUNT);
        span.range.start = provider.ConsumeIntegral<int32_t>();
        span.range.end = provider.ConsumeIntegral<int32_t>();
        span.content = provider.ConsumeRandomLengthString(MAX_FUZZ_STRING_LEN);
        inner.richTextData.spans.push_back(span);
    }

    Parcel parcel;
    inner.Marshalling(parcel);
    parcel.RewindRead(0);
    auto *readInner = RichTextDataInner::Unmarshalling(parcel);
    if (readInner != nullptr) {
        delete readInner;
    }
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::FuzzRichDataInner(provider);
    return 0;
}
