# AGENTS.md - 输入法框架 (IMF)

## 基本信息

| 属性 | 值 |
|----------|-------|
| **仓库名** | inputmethod_imf |
| **子系统** | inputmethod |
| **主要语言** | C++, TypeScript/ArkTS |
| **许可证** | Apache License 2.0 |
| **构建系统** | GN (Generate Ninja) |
| **组件** | imf (输入法框架) |

## 核心功能

OpenHarmony 输入法框架 (IMF) 是一个系统服务，用于管理操作系统上的文本输入能力。它为应用程序与输入法引擎 (IME) 交互提供统一的接口。框架处理多用户场景、安全输入、配置管理，并支持原生 C++ 和 ArkTS 开发。

框架作为系统能力运行，协调请求文本输入服务的客户端应用程序与提供这些服务的输入法应用程序。它管理输入会话的完整生命周期，从初始绑定到活跃文本输入再到解绑，并支持多显示器等高级功能。

### IMF 特定概念

#### 面板类型

- **SOFT_KEYBOARD** - 用于文本输入的标准软键盘面板
- **STATUS_BAR** - 用于显示输入法状态和配置信息的紧凑状态面板

#### 面板标志

- **FLG_FIXED** - 固定位置面板（通常在屏幕底部）
- **FLG_FLOATING** - 可由用户移动的浮动面板
- **FLG_CANDIDATE_COLUMN** - 候选词列表面板

#### 沉浸模式

面板显示模式以提供更好的用户体验：

- **NONE_IMMERSIVE** - 无沉浸效果的正常模式
- **IMMERSIVE** - 完全沉浸模式
- **LIGHT_IMMERSIVE** - 浅色沉浸模式
- **DARK_IMMERSIVE** - 深色沉浸模式

#### 输入法面板

管理面板生命周期的主要类：

- `CreatePanel()` - 使用指定配置创建面板
- `DestroyPanel()` - 销毁面板并释放资源
- `ShowPanel()` / `HidePanel()` - 控制面板可见性
- `Resize()` - 将面板调整为指定尺寸
- `MoveTo()` - 将面板移动到指定位置
- `SetImmersiveMode()` - 设置沉浸显示模式
- `GetSystemPanelCurrentInsets()` - 获取系统面板偏移信息

#### 输入法控制器

输入法框架的核心控制器：

- `Attach()` - 将输入法绑定到文本编辑器
- `Detach()` - 将输入法从文本编辑器解绑
- `DispatchKeyEvent()` - 将按键事件分发给输入法

#### 文本变化监听器

来自 IME 的文本变化回调接口：

- `InsertText()` - 在光标位置插入文本
- `DeleteForward()` - 从光标向前删除文本
- `DeleteBackward()` - 从光标向后删除文本
- `SendKeyEventFromInputMethod()` - 从 IME 发送按键事件
- `MoveCursor()` - 在指定方向移动光标
- `HandleSetSelection()` - 设置文本选择范围
- `GetLeftTextOfCursor()` - 获取光标左侧的文本
- `GetRightTextOfCursor()` - 获取光标右侧的文本
- `GetTextIndexAtCursor()` - 获取光标位置索引

#### 按键事件

物理键盘监听的按键事件结构：

- 包含按键码、按键动作和按键标志
- 由 IME 用于监听物理键盘事件
- 支持按键事件消费回调

#### 系统面板边距

系统面板调整信息：

- `left` - 系统面板左侧边距
- `right` - 系统面板右侧边距
- `bottom` - 系统面板底部边距
- 用于计算相对于系统面板的键盘面板位置

### 框架模块

1. **应用客户端** (`frameworks/native/inputmethod_controller`)
   - 应用程序的输入法显示/隐藏请求
   - 文本操作：InsertText, DeleteForward, DeleteBackward
   - 光标控制：MoveCursor, HandleSetSelection
   - 按键事件分发和监听
   - 通信：直接调用框架 API，通过 IPC/Binder 与服务通信
   - 关键组件：InputClientServiceImpl, KeyEventConsumer, InputDataChannel

2. **输入法客户端** (`frameworks/native/inputmethod_ability`)
   - 监控输入法当前状态
   - 面板生命周期管理（创建/销毁/显示/隐藏/调整/移动）
   - 沉浸模式支持（NONE_IMMERSIVE, IMMERSIVE, LIGHT_IMMERSIVE, DARK_IMMERSIVE）
   - 面板类型：SOFT_KEYBOARD, STATUS_BAR
   - 面板标志：FLG_FIXED, FLG_FLOATING, FLG_CANDIDATE_COLUMN
   - 通信：通过 IPC/Binder 与服务通信
   - 关键组件：InputMethodPanel, InputMethodAbility

3. **输入法服务** (`services`)
   - 输入法框架的核心
   - 输入法的主要处理逻辑
   - 状态管理、面板管理、输入分发
   - 子组件：
     * UserSessionManager - 每用户会话管理
     * ClientGroup - 客户端分组和管理
     * ImeInfoInquirer - IME 信息查询
     * ImeLifecycleManager - IME 生命周期管理
     * InputTypeManager - 输入类型管理
   - 通信：通过 IPC/Binder 与所有客户端通信

4. **输入法 JS 接口** (`interfaces/kits/js`)
   - 输入法操作的 JS/Node-API 接口
   - ExtraConfig 用于配置管理
   - InputController 用于文本输入控制
   - InputMethodList 用于 IME 列表和切换
   - 通信：JavaScript/Node-API 绑定到原生代码

5. **C 接口** (`interfaces/kits/c`)
   - 原生应用的 C API 绑定
   - InputController：绑定、解绑、显示/隐藏键盘
   - TextEditor：文本操作和光标控制
   - MessageHandler：消息处理回调
   - PrivateCommand：私有命令通信
   - 通信：C API 到原生实现

6. **ETS/ArkTS 接口** (`frameworks/ets`)
   - ArkUI 应用的 ArkTS/ETS 绑定
   - InputMethod 组件用于应用端输入
   - InputMethodEngine 组件用于 IME 应用端
   - 通信：ArkTS 绑定到原生代码

### 通信模式

**模块间通信：**

- 应用 → 输入法框架 API（直接调用）
- 应用 → 输入法服务（IPC/Binder）
- 输入法框架 API → 输入法服务（IPC/Binder）
- 输入法服务 → 输入法应用（IPC/Binder）
- 输入法应用 → 系统服务（IPC/Binder）

**系统服务集成：**

- 窗口管理器 - 面板显示管理
- 包管理器 - 查询包信息和扩展能力
- 公共事件管理器 - 事件处理和分发
- IPC 核心 - 进程间通信
- 能力管理器 - 能力生命周期管理
- 显示管理器 - 显示管理
- 输入管理器 - 按键事件监听

## 目录结构

```
inputmethod_imf/
├── common/              # 共享工具和头文件（global.h, 错误码）
├── services/            # 核心服务实现
│   ├── src/            # 主服务源文件
│   ├── include/         # 服务头文件
│   ├── adapter/         # 平台适配器（应用、显示、键盘等）
│   ├── hook/           # IMF hook 管理
│   ├── module/          # 模块管理器
│   ├── json/            # JSON 序列化工具
│   └── file/           # 文件操作
├── frameworks/          # 客户端框架
│   ├── native/          # 原生 C++ 客户端实现
│   ├── ndk/            # C API
│   ├── js/             # JavaScript/Node-API 绑定
│   ├── ets/            # ArkTS/ETS 绑定
│   └── kits/           # 扩展工具包
├── interfaces/          # API 定义
│   ├── inner_api/       # 内部 API（inputmethod_controller, inputmethod_ability）
│   └── kits/           # 公共 API
├── test/               # 测试套件
│   ├── unittest/        # 单元测试
│   ├── fuzztest/        # Fuzz 测试
│   └── common/          # 测试工具
├── tools/              # 开发工具
├── profile/            # 系统能力配置
└── BUILD.gn           # 根构建配置
```

## 构建系统

### 构建命令

```bash
./build.sh --product-name <product_name> --build-target imf
./build.sh --product-name rk3568 --build-target imf
```

### 测试命令

```bash
./build.sh --product-name <product_name> --build-target imf_test
```

## 错误处理

### 错误码（来自 `common/include/global.h`）

```cpp
return ErrorCode::NO_ERROR;
return ErrorCode::ERROR_NULL_ERROR;
return ErrorCode::ERROR_BAD_PARAMETERS;
return ErrorCode::ERROR_CLIENT_NOT_FOUND;
...
```

### 日志（IMSA_HILOG 宏来自 `common/include/global.h`）

```cpp
IMSA_HILOGD("Debug: %{public}s", str.c_str());
IMSA_HILOGI("Info message");
IMSA_HILOGW("Warning message");
IMSA_HILOGE("Error: %{public}d", errorCode);
IMSA_HILOGF("Fatal message");
```

## 主要依赖（来自 bundle.json）

| 依赖 | 用途 |
|------------|---------|
| `init` | 系统能力管理器代理，进程状态通知 |
| `napi` | JavaScript/ArkTS 绑定的 Node-API |
| `samgr` | 服务注册和检索的系统能力管理器 |
| `ipc` | 进程间通信（IRemoteObject, Binder, IPCSkeleton） |
| `eventhandler` | 任务发布和事件分发（EventHandler, EventQueue） |
| `bundle_framework` | 查询包信息和扩展能力（BundleMgrClient） |
| `ability_runtime` | 能力生命周期、ExtensionAbilityInfo、AppManager |
| `hilog` | 日志框架（IMSA_HILOG* 宏） |
| `access_token` | 权限检查（AccessTokenID, HasPermission） |
| `window_manager` | 面板显示管理（DisplayManager, WSUtils） |
| `input` | 按键事件监听（KeyEvent, KeyboardEvent, InputManager） |
| `os_account` | 多用户支持（QueryActiveOsAccountIds） |

## 参考资料

### ArkTS API 参考

- [@ohos.inputMethod（输入法框架）](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/js-apis-inputmethod.md) - 应用端输入法控制 API
- [@ohos.inputMethodEngine（输入法服务）](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/js-apis-inputmethodengine.md) - IME 应用端 API
- [@ohos.inputMethod（输入法框架）（系统接口）](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/js-apis-inputmethod-sys.md) - 输入法管理的系统 API
- [输入法框架错误码](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/errorcode-inputmethod-framework.md) - 错误码参考

### C API 参考

- [InputMethod_Controller](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/capi-inputmethod-controller-capi-h.md) - 输入法控制器 C API
- [InputMethod_TextConfig](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/capi-inputmethod-text-config-capi-h.md) - 文本配置 C API
- [InputMethod_TextEditorProxy](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/capi-inputmethod-text-editor-proxy-capi-h.md) - 文本编辑代理 C API
- [InputMethod_Types](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/capi-inputmethod-types-capi-h.md) - 类型定义 C API
- [InputMethod_AttachOptions](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/capi-inputmethod-attach-options-capi-h.md) - 绑定选项 C API

### 开发指南

- [IME Kit简介](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/ime-kit-intro.md) - 输入法开发服务介绍
- [实现一个输入法应用](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/inputmethod-application-guide.md) - 输入法应用开发指南
- [在自绘编辑框中使用输入法](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/use-inputmethod-in-custom-edit-box.md) - 自绘UI组件使用输入法
- [在自绘编辑框中使用输入法(C/C++)](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/use-inputmethod-in-custom-edit-box-ndk.md) - C方式使用输入法
- [切换输入法应用](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/switch-inputmethod-guide.md) - 输入法切换指南
- [输入法子类型开发指南](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/input-method-subtype-guide.md) - 子类型开发指导
- [输入法应用沉浸模式](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/inputmethod-immersive-mode-guide.md) - 沉浸模式开发
- [通过hdc命令管理输入法](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/inputmethod-hdc-commands-guide.md) - hdc命令管理IME
- [不可获焦窗口中输入框与输入法交互指南](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/use-inputmethod-in-not-focusable-window.md) - 特殊窗口场景
- [输入法开发服务术语](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/ime-kit-glossary.md) - 术语定义

## Notes for Agents

### 需要做的

- 实现新代码前检查现有模式
- 使用 `common/include/global.h` 中 `ErrorCode` 命名空间的错误码
- 使用 IMSA_HILOG* 宏记录日志，包含行号和函数名
- 业务逻辑前验证所有参数
- 使用智能指针（`std::shared_ptr`, `sptr<>`）和 RAII 模式
- 在 `test/unittest/cpp_test/` 中使用 gtest 框架编写测试
- 使用互斥锁（`std::lock_guard`, `std::unique_lock`）确保线程安全
- 遵循命名约定：类/方法使用 PascalCase，成员变量使用 camelCase 加 `_` 后缀
- 敏感操作前使用 `IdentityChecker` API 检查权限
- 使用 `std::atomic` 实现线程安全的标志和计数器
- 创建 IPC Stub 类时实现 `OnRemoteRequest()`
- 使用 `InputDeathRecipient` 监控远程对象死亡

### 不要做的

- **禁止** 删除失败的测试用例来使用例"通过"
- **禁止** 未明确用户请求时提交代码
- **禁止** 对已有接口做不兼容变更：
  - 禁止删除已有接口或修改接口签名（参数类型、返回值类型、参数顺序）
  - 禁止修改已有接口实现时抛出新的错误码
  - 禁止修改已有接口的语义或默认行为
  - 禁止在已有接口中新增必填参数
  - 如需扩展功能，应新增接口而非修改已有接口
- **禁止** 未检查 `global.h` 就创建新错误码
- **禁止** 敏感操作跳过权限检查
- **禁止** 使用无明确所有权语义的原始指针
- **禁止** 使用 `new` 时不加 `std::nothrow` 和空指针检查
- **禁止** 发明新的命名约定 - 遵循现有模式