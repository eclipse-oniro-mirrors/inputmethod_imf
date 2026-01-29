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

#ifndef FOUNDATION_ABILITYRUNTIME_OHOS_ETS_INPUTMETHOD_EXTENSION_H
#define FOUNDATION_ABILITYRUNTIME_OHOS_ETS_INPUTMETHOD_EXTENSION_H

#include <vector>
#include "configuration.h"
#include "display_manager.h"
#include "inputmethod_extension.h"
#include "ets_runtime.h"
#include "ability_handler.h"
#include "ets_native_reference.h"

namespace OHOS {
namespace MiscServices {
class ETSInputMethodExtension : public AbilityRuntime::InputMethodExtension {
public:
    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
              const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
              std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
              const sptr<IRemoteObject> &token) override;

public:
    static ETSInputMethodExtension *Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime);

    virtual void OnStart(const AAFwk::Want &want) override;
    virtual void OnStop() override;

    virtual sptr<IRemoteObject> OnConnect(const AAFwk::Want &want) override;
    virtual void OnDisconnect(const AAFwk::Want &want) override;
    virtual void OnCommand(const AAFwk::Want &want, bool restart, int startId) override;
    virtual void OnConfigurationUpdated(const AppExecFwk::Configuration &config) override;

    void ConfigurationUpdated();

public:
    explicit ETSInputMethodExtension(AbilityRuntime::ETSRuntime &etsRuntime);
    virtual ~ETSInputMethodExtension();

private:
    void BindContext(std::shared_ptr<AbilityRuntime::AbilityInfo> &abilityInfo, std::shared_ptr<AAFwk::Want> want,
        const std::string &moduleName, const std::string &srcPath);
    void UpdateInputMethodExtensionObj(std::shared_ptr<AbilityRuntime::AbilityInfo> &abilityInfo,
        const std::string &moduleName, const std::string &srcPath);
    void InitDisplayCache();
    void ListenWindowManager();
    void GetSrcPath(std::string &srcPath);
    ani_ref CallObjectMethod(bool withResult, const char *name, const char *signature, ...);
private:
struct CacheDisplay {
    int32_t displayWidth = 0;
    int32_t displayHeight = 0;
    Rosen::Rotation displayRotation = Rosen::Rotation::ROTATION_0;
    Rosen::FoldStatus displayFoldStatus = Rosen::FoldStatus::UNKNOWN;
    bool IsEmpty()
    {
        return displayWidth == 0 && displayHeight == 0 && displayRotation == Rosen::Rotation::ROTATION_0 &&
            displayFoldStatus == Rosen::FoldStatus::UNKNOWN;
    };
    void SetCacheDisplay(int32_t width, int32_t height, Rosen::Rotation rotation, Rosen::FoldStatus foldStatus)
    {
        displayWidth = width;
        displayHeight = height;
        displayRotation = rotation;
        displayFoldStatus = foldStatus;
    };
};
    AbilityRuntime::ETSRuntime &etsRuntime_;
    std::shared_ptr<AppExecFwk::ETSNativeReference> etsAbilityObj_;
    std::shared_ptr<AppExecFwk::AbilityHandler> handler_ = nullptr;
    CacheDisplay cacheDisplay_;

protected:
    class EtsInputMethodExtensionDisplayAttributeListener : public Rosen::DisplayManager::IDisplayAttributeListener {
    public:
        explicit EtsInputMethodExtensionDisplayAttributeListener(
            const std::weak_ptr<ETSInputMethodExtension> &extension)
        {
            etsInputMethodExtension_ = extension;
        }

        void OnAttributeChange(Rosen::DisplayId displayId, const std::vector<std::string>& attributes) override
        {
            auto inputMethodSptr = etsInputMethodExtension_.lock();
            if (inputMethodSptr != nullptr) {
                inputMethodSptr->ListenerCheckNeedAdjustKeyboard(displayId);
                inputMethodSptr->OnListenerChange(displayId);
            }
        }

    private:
        std::weak_ptr<ETSInputMethodExtension> etsInputMethodExtension_;
    };

    void OnListenerChange(Rosen::DisplayId displayId);
    void ListenerCheckNeedAdjustKeyboard(Rosen::DisplayId displayId);

private:
    sptr<EtsInputMethodExtensionDisplayAttributeListener> displayListener_ = nullptr;
};
}
}

#endif // FOUNDATION_ABILITYRUNTIME_OHOS_ETS_INPUTMETHOD_EXTENSION_H
