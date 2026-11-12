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
#ifndef NATIVE_OBJECT_REGISTRY_H
#define NATIVE_OBJECT_REGISTRY_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <unordered_map>

#include "global.h"

namespace OHOS {
namespace MiscServices {
template <typename T>
class NativeObjectRegistry {
public:
    static NativeObjectRegistry &GetInstance()
    {
        static NativeObjectRegistry instance;
        return instance;
    }

    T *Register(T *raw)
    {
        if (raw == nullptr) {
            IMSA_HILOGE("Object allocation failed.");
            return nullptr;
        }
        auto object = std::shared_ptr<T>(raw);
        auto lifetime = std::make_shared<uint8_t>(0);
        std::lock_guard<std::mutex> lock(mutex_);
        objects_.insert_or_assign(raw, Entry { object, object, lifetime, lifetime });
        return raw;
    }

    void RegisterBorrowed(const std::shared_ptr<T> &object)
    {
        auto lifetime = std::make_shared<uint8_t>(0);
        std::lock_guard<std::mutex> lock(mutex_);
        objects_.insert_or_assign(object.get(), Entry { nullptr, object, lifetime, lifetime });
    }

    bool RegisterView(const std::shared_ptr<T> &object, const std::weak_ptr<uint8_t> &lifetime)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = objects_.begin(); it != objects_.end();) {
            if (it->second.validity.expired()) {
                it = objects_.erase(it);
            } else {
                ++it;
            }
        }
        if (lifetime.expired()) {
            return false;
        }
        objects_.insert_or_assign(object.get(), Entry { nullptr, object, nullptr, lifetime });
        return true;
    }

    std::weak_ptr<uint8_t> GetLifetime(T *raw)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = objects_.find(raw);
        return it == objects_.end() ? std::weak_ptr<uint8_t>() : it->second.validity;
    }

    std::shared_ptr<T> Get(T *raw)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = objects_.find(raw);
        return it == objects_.end() || it->second.validity.expired() ? nullptr : it->second.object.lock();
    }

    void UnregisterBorrowed(T *raw)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = objects_.find(raw);
        if (it != objects_.end() && it->second.owner == nullptr) {
            objects_.erase(it);
        }
    }

    bool Destroy(T *raw)
    {
        Entry retired;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = objects_.find(raw);
            if (it == objects_.end() || it->second.owner == nullptr) {
                IMSA_HILOGE("Destroy rejected: object is borrowed, unregistered or already destroyed.");
                return false;
            }
            retired = std::move(it->second);
            objects_.erase(it);
        }
        // A dispatch that already acquired a lease may finish, without holding the registry lock.
        return true;
    }

private:
    struct Entry {
        std::shared_ptr<T> owner;
        std::weak_ptr<T> object;
        std::shared_ptr<uint8_t> lifetime;
        std::weak_ptr<uint8_t> validity;
    };
    NativeObjectRegistry() = default;
    std::mutex mutex_;
    std::unordered_map<T *, Entry> objects_;
};

// Callback objects are borrowed, but an accessor's lease still keeps their storage alive across callback return.
template <typename T>
class NativeObjectScope {
public:
    NativeObjectScope() : object_(new(std::nothrow) T())
    {
        if (object_ != nullptr) {
            NativeObjectRegistry<T>::GetInstance().RegisterBorrowed(object_);
        }
    }
    NativeObjectScope(const NativeObjectScope &) = delete;
    NativeObjectScope &operator=(const NativeObjectScope &) = delete;
    NativeObjectScope(NativeObjectScope &&) = default;
    ~NativeObjectScope()
    {
        Close();
    }
    void Close()
    {
        if (object_ != nullptr) {
            NativeObjectRegistry<T>::GetInstance().UnregisterBorrowed(object_.get());
        }
    }
    T *Get() const
    {
        return object_.get();
    }

private:
    std::shared_ptr<T> object_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // NATIVE_OBJECT_REGISTRY_H
