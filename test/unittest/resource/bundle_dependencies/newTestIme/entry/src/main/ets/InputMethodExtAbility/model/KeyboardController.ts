/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import commonEventManager from '@ohos.commonEventManager';
import inputMethodEngine from '@ohos.inputMethodEngine'
import { JSON } from '@kit.ArkTS';

globalThis.inputEngine = inputMethodEngine.getInputMethodAbility()

export class KeyboardController {
    private TAG: string = 'inputDemo: KeyboardController ';

    constructor(context) {
        this.addLog('constructor');
        this.mContext = context;
    }

    public onCreate(): void {
        this.addLog('onCreate');
        this.registerListener();
    }

    private registerListener(): void {
        this.addLog('registerListener')
        this.registerInputListener();
    }

    private registerInputListener() {
        globalThis.inputEngine.on('inputStart', (kbController, textInputClient) => {
            globalThis.textInputClient = textInputClient;
            globalThis.keyboardController = kbController;
            let attr = textInputClient.getEditorAttributeSync();
            this.publishCommonEvent(attr);
        })
        globalThis.inputEngine.on('inputStop', (imeId) => {
            this.addLog("[inputDemo] inputStop:" + imeId);
            if (imeId == "com.example.kikainput/InputDemoService") {
                this.onDestroy();
            }
        });
        globalThis.inputEngine.on('discardTypingText', () => {
            console.log('[registerInputListener] discardTypingText start:' )
        });
    }

    private unRegisterListener(): void {
        this.addLog("unRegisterListener");
        globalThis.inputEngine.off('inputStart');
        globalThis.inputEngine.off('inputStop');
        globalThis.inputEngine.off('discardTypingText');
    }

    public onDestroy(): void {
        this.addLog('onDestroy');
        this.unRegisterListener();
        this.mContext.destroy();
    }

    private addLog(message): void {
        console.log(this.TAG + message)
    }

    public publishCommonEvent(editorAttrbute: inputMethodEngine.EditorAttribute): void {
        let event: string = 'EditorAttributeChangedTest'
        this.addLog(`[EditorAttributeChangedTest] publish event, event= ${event}, editorAttrbute= ${editorAttrbute}`);
        let options:CommonEventManager.CommonEventPublishData = {
            code: 0,
            data: JSON.stringify(editorAttrbute),
            isOrdered: true
        };
        commonEventManager.publish(event, options, (err) => {
        if (err) {
            this.addLog(`EditorAttributeChangedTest publish ${event} failed, err = ${JSON.stringify(err)}`);
        } else {
            this.addLog(`EditorAttributeChangedTest publish ${event} success`);
        }
        })
  }
}

