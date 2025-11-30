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

import Want from '@ohos.app.ability.Want';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import InputMethodExtensionContext from '@ohos.InputMethodExtensionContext';

export default class InputMethodExtensionAbility {
  public context: InputMethodExtensionContext = {};

  onCreate(want: Want): void {
    console.log(`InputMethodExtensionAbility onCreate, want: ${want}`);
  }

  onDestroy(): void {
    console.log(`InputMethodExtensionAbility onDestroy`);
  }

  onRequest(want: Want, startId: int): void {
    console.log('onRequest, want:' + want.abilityName + ', startId:' + startId);
  }

  onConnect(want: Want): void {
    console.log('onConnect, want:' + want.abilityName);
  }

  onDisconnect(want: Want): void {
    console.log('onDisconnect');
  }

}