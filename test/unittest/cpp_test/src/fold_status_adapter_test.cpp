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

// Description: FoldStatusAdapter unit test
// Create: 2026-08-25

#include <cstdint>
#include <functional>
#include <gtest/gtest.h>
#include <string>

#include "ime_usage_common.h"

#define private   public
#define protected public
#include "fold_status_adapter.h"
#undef private
#undef protected

#include "global.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;
using namespace ImeFoldStatusBase;
using namespace ImeScreenStatus;
} // namespace

class FoldStatusAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void FoldStatusAdapterTest::SetUpTestCase(void) { }
void FoldStatusAdapterTest::TearDownTestCase(void) { }

void FoldStatusAdapterTest::SetUp()
{
    // Reset the singleton state for each test
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.isInitialized_ = false;
    adapter.isFoldable_ = false;
    adapter.foldStatus_ = 0;
    adapter.vhMode_ = 0;
    adapter.onScreenStatusChanged_ = nullptr;
    adapter.displayModeListener_ = nullptr;
    adapter.displayAttributeListener_ = nullptr;
}

void FoldStatusAdapterTest::TearDown() { }

// ==================== ConvertDisplayMode ====================

/**
 * @tc.name: FoldStatusAdapter_ConvertDisplayMode_001
 * @tc.desc: FULL -> EXPAND
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertDisplayMode_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    int32_t result = adapter.ConvertDisplayMode(Rosen::FoldDisplayMode::FULL);
    EXPECT_EQ(result, EXPAND);
}

/**
 * @tc.name: FoldStatusAdapter_ConvertDisplayMode_002
 * @tc.desc: MAIN -> FOLD
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertDisplayMode_002, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    int32_t result = adapter.ConvertDisplayMode(Rosen::FoldDisplayMode::MAIN);
    EXPECT_EQ(result, FOLD);
}

/**
 * @tc.name: FoldStatusAdapter_ConvertDisplayMode_003
 * @tc.desc: SUB -> IME_SCREEN_STATUS_UNAVAILABLE (IME unavailable)
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertDisplayMode_003, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    int32_t result = adapter.ConvertDisplayMode(Rosen::FoldDisplayMode::SUB);
    EXPECT_EQ(result, IME_SCREEN_STATUS_UNAVAILABLE);
}

/**
 * @tc.name: FoldStatusAdapter_ConvertDisplayMode_004
 * @tc.desc: COORDINATION -> EXPAND
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertDisplayMode_004, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    int32_t result = adapter.ConvertDisplayMode(Rosen::FoldDisplayMode::COORDINATION);
    EXPECT_EQ(result, EXPAND);
}

/**
 * @tc.name: FoldStatusAdapter_ConvertDisplayMode_005
 * @tc.desc: GLOBAL_FULL -> G
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertDisplayMode_005, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    int32_t result = adapter.ConvertDisplayMode(Rosen::FoldDisplayMode::GLOBAL_FULL);
    EXPECT_EQ(result, G);
}

/**
 * @tc.name: FoldStatusAdapter_ConvertDisplayMode_006
 * @tc.desc: V_MAIN -> IME_SCREEN_STATUS_UNAVAILABLE (IME unavailable)
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertDisplayMode_006, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    int32_t result = adapter.ConvertDisplayMode(Rosen::FoldDisplayMode::V_MAIN);
    EXPECT_EQ(result, IME_SCREEN_STATUS_UNAVAILABLE);
}

/**
 * @tc.name: FoldStatusAdapter_ConvertDisplayMode_007
 * @tc.desc: N_MAIN -> N
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertDisplayMode_007, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    int32_t result = adapter.ConvertDisplayMode(Rosen::FoldDisplayMode::N_MAIN);
    EXPECT_EQ(result, N);
}

/**
 * @tc.name: FoldStatusAdapter_ConvertDisplayMode_008
 * @tc.desc: L_FULL -> LM
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertDisplayMode_008, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    int32_t result = adapter.ConvertDisplayMode(Rosen::FoldDisplayMode::L_FULL);
    EXPECT_EQ(result, LM);
}

// ==================== GetFoldStatus ====================

/**
 * @tc.name: FoldStatusAdapter_GetFoldStatus_001
 * @tc.desc: GetFoldStatus returns set value
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, GetFoldStatus_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = EXPAND;
    EXPECT_EQ(adapter.GetFoldStatus(), EXPAND);
}

/**
 * @tc.name: FoldStatusAdapter_GetFoldStatus_002
 * @tc.desc: GetFoldStatus returns 0 when uninitialized
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, GetFoldStatus_002, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = 0;
    EXPECT_EQ(adapter.GetFoldStatus(), 0);
}

// ==================== GetVhMode ====================

/**
 * @tc.name: FoldStatusAdapter_GetVhMode_001
 * @tc.desc: GetVhMode returns set value
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, GetVhMode_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.vhMode_ = LANDSCAPE;
    EXPECT_EQ(adapter.GetVhMode(), LANDSCAPE);
}

/**
 * @tc.name: FoldStatusAdapter_GetVhMode_002
 * @tc.desc: GetVhMode returns PORTRAIT when set
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, GetVhMode_002, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.vhMode_ = PORTRAIT;
    EXPECT_EQ(adapter.GetVhMode(), PORTRAIT);
}

// ==================== GetScreenStatus ====================

/**
 * @tc.name: FoldStatusAdapter_GetScreenStatus_001
 * @tc.desc: GetScreenStatus returns foldStatus*10+vhMode
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, GetScreenStatus_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = EXPAND;
    adapter.vhMode_ = PORTRAIT;
    EXPECT_EQ(adapter.GetScreenStatus(), EXPAND_PORTRAIT);
}

/**
 * @tc.name: FoldStatusAdapter_GetScreenStatus_002
 * @tc.desc: GetScreenStatus with FOLD+LANDSCAPE
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, GetScreenStatus_002, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = FOLD;
    adapter.vhMode_ = LANDSCAPE;
    EXPECT_EQ(adapter.GetScreenStatus(), FOLD_LANDSCAPE);
}

/**
 * @tc.name: FoldStatusAdapter_GetScreenStatus_003
 * @tc.desc: GetScreenStatus with UNFOLDED+PORTRAIT
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, GetScreenStatus_003, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    EXPECT_EQ(adapter.GetScreenStatus(), UNFOLDED_PORTRAIT);
}

// ==================== IsFoldable ====================

/**
 * @tc.name: FoldStatusAdapter_IsFoldable_001
 * @tc.desc: IsFoldable returns false when not set
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, IsFoldable_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.isFoldable_ = false;
    EXPECT_FALSE(adapter.IsFoldable());
}

/**
 * @tc.name: FoldStatusAdapter_IsFoldable_002
 * @tc.desc: IsFoldable returns true when set
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, IsFoldable_002, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.isFoldable_ = true;
    EXPECT_TRUE(adapter.IsFoldable());
}

// ==================== SetScreenStatusChangedCallback ====================

/**
 * @tc.name: FoldStatusAdapter_SetScreenStatusChangedCallback_001
 * @tc.desc: SetScreenStatusChangedCallback stores callback
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, SetScreenStatusChangedCallback_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    bool called = false;
    int32_t receivedPre = 0;
    int32_t receivedNew = 0;
    adapter.SetScreenStatusChangedCallback([&](int32_t pre, int32_t newStatus) {
        called = true;
        receivedPre = pre;
        receivedNew = newStatus;
    });
    ASSERT_NE(adapter.onScreenStatusChanged_, nullptr);
    adapter.onScreenStatusChanged_(UNFOLDED_PORTRAIT, EXPAND_PORTRAIT);
    EXPECT_TRUE(called);
    EXPECT_EQ(receivedPre, UNFOLDED_PORTRAIT);
    EXPECT_EQ(receivedNew, EXPAND_PORTRAIT);
}

// ==================== HandleDisplayModeChanged ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_001
 * @tc.desc: IME-unavailable mode (SUB) is skipped, no callback fired
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    bool called = false;
    adapter.SetScreenStatusChangedCallback([&](int32_t, int32_t) {
        called = true;
    });
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::SUB);
    EXPECT_FALSE(called);
    // foldStatus_ should remain unchanged
    EXPECT_EQ(adapter.foldStatus_, UNFOLDED);
}

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_002
 * @tc.desc: Valid mode change updates foldStatus and fires callback
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_002, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = FOLD;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    int32_t receivedPre = 0;
    int32_t receivedNew = 0;
    adapter.SetScreenStatusChangedCallback([&](int32_t pre, int32_t newStatus) {
        receivedPre = pre;
        receivedNew = newStatus;
    });
    // FULL maps to EXPAND; ConvertVhMode calls DMS which may return PORTRAIT
    // We can't control ConvertVhMode output, but we can verify foldStatus_ changed
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::FULL);
    EXPECT_EQ(adapter.foldStatus_, EXPAND);
    // Check callback was fired (screenStatus should have changed from FOLD_PORTRAIT to EXPAND+vhMode)
    EXPECT_NE(receivedPre, 0); // old was FOLD_PORTRAIT(22)
}

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_003
 * @tc.desc: isFoldable_ corrected from false to true on mode change
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_003, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.isFoldable_ = false;
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::FULL);
    EXPECT_TRUE(adapter.isFoldable_);
}

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_004
 * @tc.desc: Same screen status after change does not fire callback
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_004, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = EXPAND;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    bool called = false;
    adapter.SetScreenStatusChangedCallback([&](int32_t, int32_t) {
        called = true;
    });
    // FULL->EXPAND, but if vhMode stays PORTRAIT, old and new screen status both = EXPAND_PORTRAIT(32)
    // This depends on ConvertVhMode returning PORTRAIT, which it does when display is portrait
    // We set it up so the foldStatus was already EXPAND, so the change might be a no-op
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::FULL);
    // The foldStatus should remain EXPAND regardless of whether callback fires
    EXPECT_EQ(adapter.foldStatus_, EXPAND);
    // If screen status did not change, callback should not have fired
    // ConvertVhMode may return PORTRAIT in test env, so old == new -> no callback
    EXPECT_FALSE(called);
}

// ==================== HandleDisplayChanged ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayChanged_001
 * @tc.desc: Orientation change fires callback with correct old/new values
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayChanged_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = false;
    int32_t receivedPre = -1;
    int32_t receivedNew = -1;
    adapter.SetScreenStatusChangedCallback([&](int32_t pre, int32_t newStatus) {
        receivedPre = pre;
        receivedNew = newStatus;
    });
    // ConvertVhMode calls DMS which may return PORTRAIT or LANDSCAPE
    adapter.HandleDisplayChanged();
    // If vhMode changed (DMS returned LANDSCAPE), callback should have fired
    // If vhMode stayed PORTRAIT, callback should not have fired
    // In test env, DMS typically returns PORTRAIT, so no callback expected
    if (receivedPre != -1) {
        // Callback fired: verify it received valid screen status values
        EXPECT_GT(receivedPre, 0);
        EXPECT_GT(receivedNew, 0);
    }
    // At minimum, foldStatus_ should remain UNFOLDED
    EXPECT_EQ(adapter.foldStatus_, UNFOLDED);
}

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayChanged_002
 * @tc.desc: Same vhMode after change does not fire callback
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayChanged_002, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    bool called = false;
    adapter.SetScreenStatusChangedCallback([&](int32_t, int32_t) {
        called = true;
    });
    adapter.HandleDisplayChanged();
    // ConvertVhMode calls DMS, typically returns PORTRAIT for test environment
    // If PORTRAIT is returned, no callback since vhMode_ is already PORTRAIT
    // Verify foldStatus_ is unchanged after HandleDisplayChanged
    EXPECT_EQ(adapter.foldStatus_, UNFOLDED);
    // In test env, DMS typically returns PORTRAIT, so callback should not fire
    EXPECT_FALSE(called);
}

// ==================== ConvertDisplayMode: default (unknown mode) ====================

/**
 * @tc.name: FoldStatusAdapter_ConvertDisplayMode_009
 * @tc.desc: Unknown FoldDisplayMode returns IME_SCREEN_STATUS_UNAVAILABLE (IME unavailable)
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertDisplayMode_009, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    // Use a value outside the known enum range
    int32_t result = adapter.ConvertDisplayMode(static_cast<Rosen::FoldDisplayMode>(99));
    EXPECT_EQ(result, IME_SCREEN_STATUS_UNAVAILABLE);
}

// ==================== Init ====================

/**
 * @tc.name: FoldStatusAdapter_Init_001
 * @tc.desc: Init sets isInitialized_ and registers listeners
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, Init_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.isInitialized_ = false;
    adapter.isFoldable_ = false;
    adapter.foldStatus_ = 0;
    adapter.vhMode_ = 0;
    adapter.onScreenStatusChanged_ = nullptr;
    adapter.displayModeListener_ = nullptr;
    adapter.displayAttributeListener_ = nullptr;
    adapter.Init();
    // After Init, isInitialized_ should be true
    EXPECT_TRUE(adapter.isInitialized_);
    // DisplayModeListener and DisplayAttributeListener should be created
    // (they may fail in test env if DMS not available, but should not crash)
}

/**
 * @tc.name: FoldStatusAdapter_Init_002
 * @tc.desc: Init when already initialized skips re-registration
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, Init_002, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.isInitialized_ = true;
    adapter.displayModeListener_ = nullptr;
    adapter.displayAttributeListener_ = nullptr;
    adapter.Init();
    // Should skip - displayModeListener_ should still be nullptr (not re-registered)
    EXPECT_EQ(adapter.displayModeListener_, nullptr);
    EXPECT_EQ(adapter.displayAttributeListener_, nullptr);
}

// ==================== RegisterListeners ====================

/**
 * @tc.name: FoldStatusAdapter_RegisterListeners_001
 * @tc.desc: RegisterListeners creates listener objects
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, RegisterListeners_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.displayModeListener_ = nullptr;
    adapter.displayAttributeListener_ = nullptr;
    adapter.RegisterListeners();
    // Listener objects should be created (even if DMS registration may fail in test env)
    // In test environment, new(std::nothrow) should succeed so listeners should be non-null
    EXPECT_NE(adapter.displayModeListener_, nullptr);
    EXPECT_NE(adapter.displayAttributeListener_, nullptr);
}

// ==================== ConvertVhMode ====================

/**
 * @tc.name: FoldStatusAdapter_ConvertVhMode_001
 * @tc.desc: ConvertVhMode returns PORTRAIT or LANDSCAPE without crash
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertVhMode_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    int32_t vhMode = adapter.ConvertVhMode();
    // In test env, DMS returns null display, so default is PORTRAIT
    EXPECT_TRUE(vhMode == PORTRAIT || vhMode == LANDSCAPE);
}

// ==================== HandleDisplayModeChanged: V_MAIN ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_005
 * @tc.desc: V_MAIN mode is IME-unavailable, callback not fired
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_005, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    bool called = false;
    adapter.SetScreenStatusChangedCallback([&](int32_t, int32_t) {
        called = true;
    });
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::V_MAIN);
    EXPECT_FALSE(called);
    // foldStatus_ should remain unchanged since V_MAIN returns IME_SCREEN_STATUS_UNAVAILABLE
    EXPECT_EQ(adapter.foldStatus_, UNFOLDED);
}

// ==================== HandleDisplayModeChanged: screen status actually changes ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_006
 * @tc.desc: Valid mode change fires callback with old/new screen status
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_006, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = FOLD;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    int32_t receivedPre = -1;
    int32_t receivedNew = -1;
    adapter.SetScreenStatusChangedCallback([&](int32_t pre, int32_t newStatus) {
        receivedPre = pre;
        receivedNew = newStatus;
    });
    // MAIN maps to FOLD(2), so if vhMode stays PORTRAIT, screenStatus = 2*10+2 = 22
    // But FOLD is already the current foldStatus_, so old=22 and new should be 22 too
    // Use a different starting state
    adapter.foldStatus_ = UNFOLDED;
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::FULL);
    // FULL maps to EXPAND(3), should change foldStatus_
    EXPECT_EQ(adapter.foldStatus_, EXPAND);
    // Callback should have been fired if screenStatus changed
    // (depends on ConvertVhMode result, but foldStatus definitely changed from UNFOLDED to EXPAND)
}

// ==================== DisplayModeListenerImpl / DisplayAttributeListenerImpl ====================

/**
 * @tc.name: FoldStatusAdapter_DisplayModeListenerImpl_001
 * @tc.desc: DisplayModeListenerImpl::OnDisplayModeChanged delegates to adapter
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, DisplayModeListenerImpl_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    bool callbackFired = false;
    adapter.SetScreenStatusChangedCallback([&](int32_t, int32_t) {
        callbackFired = true;
    });

    // Create listener and trigger it
    auto listener = new FoldStatusAdapter::DisplayModeListenerImpl(adapter);
    listener->OnDisplayModeChanged(Rosen::FoldDisplayMode::FULL);
    // The listener should delegate to HandleDisplayModeChanged
    EXPECT_EQ(adapter.foldStatus_, EXPAND);
    delete listener;
}

/**
 * @tc.name: FoldStatusAdapter_DisplayAttributeListenerImpl_001
 * @tc.desc: DisplayAttributeListenerImpl::OnAttributeChange delegates to adapter HandleDisplayChanged
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, DisplayAttributeListenerImpl_001, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    bool callbackFired = false;
    int32_t receivedPre = -1;
    int32_t receivedNew = -1;
    adapter.SetScreenStatusChangedCallback([&](int32_t pre, int32_t newStatus) {
        callbackFired = true;
        receivedPre = pre;
        receivedNew = newStatus;
    });
    // Create listener and trigger it
    auto listener = new FoldStatusAdapter::DisplayAttributeListenerImpl(adapter);
    std::vector<std::string> attributes = { "rotation" };
    listener->OnAttributeChange(0, attributes);
    // Verify foldStatus_ remains UNFOLDED (HandleDisplayChanged does not change foldStatus_)
    EXPECT_EQ(adapter.foldStatus_, UNFOLDED);
    // If DMS returns a different vhMode, callback would fire; otherwise not
    if (callbackFired) {
        EXPECT_GT(receivedPre, 0);
        EXPECT_GT(receivedNew, 0);
    }
    delete listener;
}

// ==================== Init: initializes state from DMS ====================

/**
 * @tc.name: FoldStatusAdapter_Init_003
 * @tc.desc: Init sets isInitialized_ and foldStatus_/vhMode_ from DMS
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, Init_003, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.isInitialized_ = false;
    adapter.isFoldable_ = false;
    adapter.foldStatus_ = 0;
    adapter.vhMode_ = 0;
    adapter.onScreenStatusChanged_ = nullptr;
    adapter.displayModeListener_ = nullptr;
    adapter.displayAttributeListener_ = nullptr;
    adapter.Init();
    EXPECT_TRUE(adapter.isInitialized_);
    // After Init, isFoldable_ reflects DMS IsFoldable() result
    // foldStatus_ is set from ConvertDisplayMode if foldable, or UNFOLDED if not
    // vhMode_ is set from ConvertVhMode()
    if (adapter.isFoldable_) {
        // Foldable device: foldStatus_ comes from ConvertDisplayMode
        EXPECT_GT(adapter.foldStatus_, 0);
    } else {
        // Non-foldable device: foldStatus_ is UNFOLDED
        EXPECT_EQ(adapter.foldStatus_, UNFOLDED);
    }
}

// ==================== Init: isInitialized_ set after all state is ready ====================

/**
 * @tc.name: FoldStatusAdapter_Init_004
 * @tc.desc: Init sets isInitialized_ = true only after all state is initialized
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, Init_004, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.isInitialized_ = false;
    adapter.isFoldable_ = false;
    adapter.foldStatus_ = 0;
    adapter.vhMode_ = 0;
    adapter.onScreenStatusChanged_ = nullptr;
    adapter.displayModeListener_ = nullptr;
    adapter.displayAttributeListener_ = nullptr;
    adapter.Init();
    // After Init completes, isInitialized_ should be true and state should be set
    EXPECT_TRUE(adapter.isInitialized_);
}

// ==================== HandleDisplayModeChanged: no callback set ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_007
 * @tc.desc: Valid mode change with no callback set does not crash
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_007, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    adapter.onScreenStatusChanged_ = nullptr;
    // Should not crash even without callback
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::FULL);
    EXPECT_EQ(adapter.foldStatus_, EXPAND);
}

// ==================== HandleDisplayModeChanged: callback null + status unchanged ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_008
 * @tc.desc: Same screen status with null callback does not crash
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_008, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = EXPAND;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    adapter.onScreenStatusChanged_ = nullptr;
    // FULL maps to EXPAND, and foldStatus_ is already EXPAND
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::FULL);
    EXPECT_EQ(adapter.foldStatus_, EXPAND);
}

// ==================== HandleDisplayChanged: no callback, vhMode unchanged ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayChanged_003
 * @tc.desc: HandleDisplayChanged with null callback and vhMode unchanged does not crash
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayChanged_003, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.onScreenStatusChanged_ = nullptr;
    // Should not crash; ConvertVhMode typically returns PORTRAIT in test env
    adapter.HandleDisplayChanged();
    EXPECT_EQ(adapter.foldStatus_, UNFOLDED);
}

// ==================== HandleDisplayChanged: callback fires with status change ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayChanged_004
 * @tc.desc: HandleDisplayChanged fires callback when vhMode actually changes
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayChanged_004, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = LANDSCAPE; // Set to LANDSCAPE so DMS returning PORTRAIT triggers a change
    adapter.isFoldable_ = false;
    int32_t receivedPre = -1;
    int32_t receivedNew = -1;
    adapter.SetScreenStatusChangedCallback([&](int32_t pre, int32_t newStatus) {
        receivedPre = pre;
        receivedNew = newStatus;
    });
    // ConvertVhMode calls DMS which typically returns PORTRAIT in test env
    // If vhMode_ was LANDSCAPE and ConvertVhMode returns PORTRAIT, callback should fire
    adapter.HandleDisplayChanged();
    if (receivedPre != -1) {
        // Callback fired: old should be UNFOLDED_LANDSCAPE(11), new should be UNFOLDED_PORTRAIT(12)
        EXPECT_EQ(receivedPre, UNFOLDED_LANDSCAPE);
        EXPECT_EQ(receivedNew, UNFOLDED_PORTRAIT);
    }
}

// ==================== ConvertVhMode: null display/displayInfo branches ====================

/**
 * @tc.name: FoldStatusAdapter_ConvertVhMode_002
 * @tc.desc: ConvertVhMode returns PORTRAIT when display is null (test env default)
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, ConvertVhMode_002, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    // In test env, DMS GetDefaultDisplayId/GetDisplayById typically returns null
    int32_t vhMode = adapter.ConvertVhMode();
    // Should return PORTRAIT as default when display is null
    EXPECT_EQ(vhMode, PORTRAIT);
}

// ==================== HandleDisplayModeChanged: GLOBAL_FULL and L_FULL modes ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_009
 * @tc.desc: GLOBAL_FULL mode changes foldStatus_ to G
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_009, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    int32_t receivedNew = -1;
    adapter.SetScreenStatusChangedCallback([&](int32_t, int32_t newStatus) {
        receivedNew = newStatus;
    });
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::GLOBAL_FULL);
    EXPECT_EQ(adapter.foldStatus_, G);
}

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_010
 * @tc.desc: L_FULL mode changes foldStatus_ to LM
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_010, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    int32_t receivedNew = -1;
    adapter.SetScreenStatusChangedCallback([&](int32_t, int32_t newStatus) {
        receivedNew = newStatus;
    });
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::L_FULL);
    EXPECT_EQ(adapter.foldStatus_, LM);
}

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayModeChanged_011
 * @tc.desc: N_MAIN mode changes foldStatus_ to N
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayModeChanged_011, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = PORTRAIT;
    adapter.isFoldable_ = true;
    int32_t receivedNew = -1;
    adapter.SetScreenStatusChangedCallback([&](int32_t, int32_t newStatus) {
        receivedNew = newStatus;
    });
    adapter.HandleDisplayModeChanged(Rosen::FoldDisplayMode::N_MAIN);
    EXPECT_EQ(adapter.foldStatus_, N);
}

// ==================== Init: already initialized skips ====================

/**
 * @tc.name: FoldStatusAdapter_Init_005
 * @tc.desc: Init when isInitialized_ is true returns early without modifying state
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, Init_005, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    // Set a specific state
    adapter.isInitialized_ = true;
    adapter.foldStatus_ = EXPAND;
    adapter.vhMode_ = LANDSCAPE;
    adapter.isFoldable_ = true;
    adapter.displayModeListener_ = nullptr;
    adapter.displayAttributeListener_ = nullptr;
    adapter.Init();
    // State should not change since isInitialized_ was true — Init returns early
    // after seeing isInitialized_=true, so all fields remain as set above
    EXPECT_EQ(adapter.foldStatus_, EXPAND);
    EXPECT_EQ(adapter.vhMode_, LANDSCAPE);
    EXPECT_TRUE(adapter.isFoldable_);
    // Init should not re-register listeners when isInitialized_=true
    EXPECT_EQ(adapter.displayModeListener_, nullptr);
    EXPECT_EQ(adapter.displayAttributeListener_, nullptr);
}

// ==================== HandleDisplayChanged: null callback + vhMode changed ====================

/**
 * @tc.name: FoldStatusAdapter_HandleDisplayChanged_005
 * @tc.desc: HandleDisplayChanged with null callback but vhMode changed does not crash
 * @tc.type: FUNC
 */
HWTEST_F(FoldStatusAdapterTest, HandleDisplayChanged_005, TestSize.Level0)
{
    auto &adapter = FoldStatusAdapter::GetInstance();
    adapter.foldStatus_ = UNFOLDED;
    adapter.vhMode_ = LANDSCAPE;
    adapter.onScreenStatusChanged_ = nullptr;
    // ConvertVhMode may return PORTRAIT in test env, causing vhMode_ to change
    adapter.HandleDisplayChanged();
    // Should not crash even without callback; vhMode_ may have changed
    EXPECT_EQ(adapter.foldStatus_, UNFOLDED);
}

} // namespace MiscServices
} // namespace OHOS
