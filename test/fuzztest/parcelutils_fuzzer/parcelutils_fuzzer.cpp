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

#include "parcelutils_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "input_method_utils.h"
#include "message_parcel.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace MiscServices {

namespace {
constexpr size_t MIN_INPUT_SIZE = 10;
constexpr size_t MAX_INPUT_SIZE = 2000;
constexpr size_t MAX_MAP_SIZE = 10;
constexpr size_t MAX_KEY_LENGTH = 50;
constexpr size_t MAX_MODE_LENGTH = 20;
constexpr size_t MAX_MSG_ID_LENGTH = 100;
constexpr size_t MAX_MSG_PARAM_SIZE = 100;
constexpr size_t MAX_RAW_DATA_SIZE = 500;
constexpr int32_t FUZZ_VALUE_TYPE_STRING = 0;
constexpr int32_t FUZZ_VALUE_TYPE_BOOL = 1;
constexpr int32_t FUZZ_VALUE_TYPE_NUMBER = 2;
constexpr uint32_t MAP_VALUE_COUNT = 2;
constexpr uint32_t MAP_VALUE_COUNT_THREE = 3;
constexpr int32_t SPECIAL_TEST_VALUE = 12345;
constexpr uint8_t PARCEL_CHOICE_COUNT = 5;
constexpr uint8_t CURSOR_INFO_TYPE = 2;
constexpr uint8_t RANGE_TYPE = 3;
constexpr uint8_t ARRAY_BUFFER_TYPE = 4;
} // namespace

void FuzzTextSelectionInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.RewindRead(0);

    TextSelectionInner *result = TextSelectionInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzTextSelectionInnerMarshalling(FuzzedDataProvider &provider)
{
    TextSelectionInner selection;
    selection.oldBegin = provider.ConsumeIntegral<int32_t>();
    selection.oldEnd = provider.ConsumeIntegral<int32_t>();
    selection.newBegin = provider.ConsumeIntegral<int32_t>();
    selection.newEnd = provider.ConsumeIntegral<int32_t>();

    MessageParcel parcel;
    selection.Marshalling(parcel);
}

void FuzzValueUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    uint32_t mapSize = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_MAP_SIZE);
    parcel.WriteUint32(mapSize);

    for (uint32_t i = 0; i < mapSize; i++) {
        std::string key = provider.ConsumeRandomLengthString(MAX_KEY_LENGTH);
        parcel.WriteString(key);
        int32_t valueType = provider.ConsumeIntegralInRange<int32_t>(FUZZ_VALUE_TYPE_STRING, FUZZ_VALUE_TYPE_NUMBER);
        parcel.WriteInt32(valueType);
        if (valueType == FUZZ_VALUE_TYPE_STRING) {
            parcel.WriteString(provider.ConsumeRandomLengthString(MAX_KEY_LENGTH));
        } else if (valueType == FUZZ_VALUE_TYPE_BOOL) {
            parcel.WriteBool(provider.ConsumeBool());
        } else {
            parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
        }
    }
    parcel.RewindRead(0);

    Value *result = Value::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzValueMapWithStringValues(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteUint32(MAP_VALUE_COUNT);
    parcel.WriteString("key1");
    parcel.WriteInt32(FUZZ_VALUE_TYPE_STRING);
    parcel.WriteString(provider.ConsumeRandomLengthString(MAX_MODE_LENGTH));
    parcel.WriteString("key2");
    parcel.WriteInt32(FUZZ_VALUE_TYPE_STRING);
    parcel.WriteString(provider.ConsumeRandomLengthString(MAX_MODE_LENGTH));
    parcel.RewindRead(0);

    Value *result = Value::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzValueMapWithBoolValues(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteUint32(MAP_VALUE_COUNT);
    parcel.WriteString("boolKey1");
    parcel.WriteInt32(FUZZ_VALUE_TYPE_BOOL);
    parcel.WriteBool(provider.ConsumeBool());
    parcel.WriteString("boolKey2");
    parcel.WriteInt32(FUZZ_VALUE_TYPE_BOOL);
    parcel.WriteBool(provider.ConsumeBool());
    parcel.RewindRead(0);

    Value *result = Value::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzValueMapWithNumberValues(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteUint32(MAP_VALUE_COUNT);
    parcel.WriteString("numKey1");
    parcel.WriteInt32(FUZZ_VALUE_TYPE_NUMBER);
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.WriteString("numKey2");
    parcel.WriteInt32(FUZZ_VALUE_TYPE_NUMBER);
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.RewindRead(0);

    Value *result = Value::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzValueMapWithMixedValues(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteUint32(MAP_VALUE_COUNT_THREE);
    parcel.WriteString("strKey");
    parcel.WriteInt32(FUZZ_VALUE_TYPE_STRING);
    parcel.WriteString("testString");
    parcel.WriteString("boolKey");
    parcel.WriteInt32(FUZZ_VALUE_TYPE_BOOL);
    parcel.WriteBool(true);
    parcel.WriteString("numKey");
    parcel.WriteInt32(FUZZ_VALUE_TYPE_NUMBER);
    parcel.WriteInt32(SPECIAL_TEST_VALUE);
    parcel.RewindRead(0);

    Value *result = Value::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzCursorInfoInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>());
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>());
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>());
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>());
    parcel.RewindRead(0);

    CursorInfoInner *result = CursorInfoInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzRangeInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
    parcel.RewindRead(0);

    RangeInner *result = RangeInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzArrayBufferUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteUint64(provider.ConsumeIntegral<uint64_t>());
    parcel.WriteString(provider.ConsumeRandomLengthString(MAX_MSG_ID_LENGTH));
    std::vector<uint8_t> msgParam = provider.ConsumeBytes<uint8_t>(
        provider.ConsumeIntegralInRange<size_t>(0, MAX_MSG_PARAM_SIZE));
    parcel.WriteUInt8Vector(msgParam);
    parcel.RewindRead(0);

    ArrayBuffer *result = ArrayBuffer::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzParcelWithRawData(FuzzedDataProvider &provider)
{
    std::vector<uint8_t> rawData = provider.ConsumeBytes<uint8_t>(
        provider.ConsumeIntegralInRange<size_t>(0, MAX_RAW_DATA_SIZE));

    MessageParcel parcel;
    if (!rawData.empty()) {
        parcel.WriteBuffer(rawData.data(), rawData.size());
        parcel.RewindRead(0);

        uint8_t choice = provider.ConsumeIntegral<uint8_t>() % PARCEL_CHOICE_COUNT;
        switch (choice) {
            case 0: {
                TextSelectionInner *result = TextSelectionInner::Unmarshalling(parcel);
                if (result) {
                    delete result;
                }
                break;
            }
            case 1: {
                Value *result = Value::Unmarshalling(parcel);
                if (result) {
                    delete result;
                }
                break;
            }
            case CURSOR_INFO_TYPE: {
                CursorInfoInner *result = CursorInfoInner::Unmarshalling(parcel);
                if (result) {
                    delete result;
                }
                break;
            }
            case RANGE_TYPE: {
                RangeInner *result = RangeInner::Unmarshalling(parcel);
                if (result) {
                    delete result;
                }
                break;
            }
            case ARRAY_BUFFER_TYPE: {
                ArrayBuffer *result = ArrayBuffer::Unmarshalling(parcel);
                if (result) {
                    delete result;
                }
                break;
            }
            default:
                break;
        }
    }
}

} // namespace MiscServices
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::MiscServices::MIN_INPUT_SIZE) {
        return 0;
    }

    if (size > OHOS::MiscServices::MAX_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);

    OHOS::MiscServices::FuzzTextSelectionInnerUnmarshalling(provider);
    OHOS::MiscServices::FuzzTextSelectionInnerMarshalling(provider);
    OHOS::MiscServices::FuzzValueUnmarshalling(provider);
    OHOS::MiscServices::FuzzValueMapWithStringValues(provider);
    OHOS::MiscServices::FuzzValueMapWithBoolValues(provider);
    OHOS::MiscServices::FuzzValueMapWithNumberValues(provider);
    OHOS::MiscServices::FuzzValueMapWithMixedValues(provider);
    OHOS::MiscServices::FuzzCursorInfoInnerUnmarshalling(provider);
    OHOS::MiscServices::FuzzRangeInnerUnmarshalling(provider);
    OHOS::MiscServices::FuzzArrayBufferUnmarshalling(provider);
    OHOS::MiscServices::FuzzParcelWithRawData(provider);

    return 0;
}
