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
| **适用范围** | 本文件为仓库根级指引，覆盖整个 inputmethod_imf 仓库 |

## 任务到路径映射

执行任何任务前，先根据任务类型定位关键路径：

| 任务类型 | 先看这里 | 原因 |
|----------|----------|------|
| **公共 API 变更**（ArkTS/JS） | `interfaces/kits/js/`, `interfaces/kits/c/`, `frameworks/ets/` | 公共 API 定义在此，任何签名/语义变更需要兼容性审查 |
| **服务端核心逻辑** | `services/src/`, `services/include/` | IMF 主处理逻辑、状态管理、面板管理、输入分发 |
| **应用客户端功能** | `frameworks/native/inputmethod_controller/` | 应用侧输入法绑定、文本操作、按键分发 |
| **IME 客户端功能** | `frameworks/native/inputmethod_ability/` | 输入法应用侧面板生命周期、沉浸模式 |
| **权限与安全检查** | `services/identity_checker/` | IdentityChecker 定义权限校验、焦点校验、系统应用校验 |
| **IPC 通信层** | `.idl` 文件（`frameworks/native/` 下各 IDL 定义），`services/src/input_method_system_ability.cpp` | IPC 接口由 IDL 文件自动生成 Stub/Proxy，服务端 OnRemoteRequest 覆写在 input_method_system_ability.cpp |
| **面板窗口管理** | `services/adapter/window_adapter/`, `services/adapter/display_adapter/` | 面板显示依赖窗口和显示管理器适配 |
| **IME 生命周期** | `services/src/ime_lifecycle_manager.cpp` | IME 启停、切换、重连逻辑 |
| **多用户会话** | `services/src/peruser_session.cpp`, `services/src/user_session_manager.cpp` | 每用户会话和用户级 IME 状态 |
| **测试用例** | `test/unittest/cpp_test/`, `test/fuzztest/` | 单元测试和 fuzz 测试 |
| **配置与参数** | `etc/para/`, `profile/`, `inputmethod.gni` | 系统参数、SA profile、GN 构建变量 |
| **DFX（可观测性）** | `common/include/inputmethod_sysevent.h`, `hisysevent.yaml` | HiSysEvent 事件定义和配置 |
| **错误码** | `common/include/global.h` (ErrorCode namespace) | 所有内部错误码定义 |
| **CAPI** | `frameworks/ndk/`（实现）, `interfaces/kits/c/`（头文件） | C 语言 API 实现和公共头文件 |
| **CJ 语言绑定** | `frameworks/cj/` | CJ 语言 FFI 绑定 |
| **输入法 Extension** | `frameworks/kits/extension/`, `frameworks/ets/extension/` | 输入法 ExtensionAbility 框架 |
| **CLI 工具** | `tools/ime/` | hdc 命令行输入法管理工具 |

## 知识路由

### 编辑前必读声明

修改任何代码前，agent 必须先声明以下三项：
1. **任务类别**：本次任务属于哪类（公共 API 变更、服务逻辑、IPC 通信、权限安全、面板管理、DFX 等）
2. **已阅读文档**：根据下方路由表，声明已阅读了哪些必读文档和文件
3. **已知约束**：根据「约束和边界」章节，声明本次变更涉及哪些约束规则

### 任务触发路由

执行以下任务类型时，**必须先阅读对应文档**再动手：

| 触发条件 | 必读文档/文件 | 原因 |
|----------|-------------|------|
| 修改公共 API 签名或语义 | [js-apis-inputmethod.md](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/js-apis-inputmethod.md), [js-apis-inputmethodengine.md](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/js-apis-inputmethodengine.md), [js-apis-inputmethod-sys.md](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/js-apis-inputmethod-sys.md), `interfaces/kits/c/` 下对应头文件 | 公共 API 不可做不兼容变更，需对照官方文档确认现有语义 |
| 修改 C API | [capi-inputmethod-controller-capi-h.md](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/capi-inputmethod-controller-capi-h.md), [capi-inputmethod-types-capi-h.md](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-ime-kit/capi-inputmethod-types-capi-h.md) | C API 是公共接口，同样受兼容性约束 |
| 新增或修改权限/安全检查 | `services/identity_checker/include/identity_checker.h`, `common/include/global.h` (ErrorCode::ERROR_STATUS_PERMISSION_DENIED, ERROR_STATUS_SYSTEM_PERMISSION) | 权限变更影响所有调用方，需理解现有校验逻辑 |
| 修改 IPC 接口或新增 IPC 方法 | 对应 `.idl` 文件（`frameworks/native/` 下），`common/include/message.h` | IPC Stub/Proxy 由 IDL 自动生成，修改接口需先改 IDL 文件再重新生成；消息码是跨进程协议 |
| 修改面板类型/标志/沉浸模式 | [inputmethod-immersive-mode-guide.md](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/inputmethod-immersive-mode-guide.md), `frameworks/native/inputmethod_ability/include/input_method_panel.h` | 面板行为是公共语义，需对照开发指南 |
| 添加新错误码 | `common/include/global.h` (ErrorCode namespace) | 已有错误码枚举值不可变更 |
| 修改 IME 生命周期/启停逻辑 | `services/src/ime_lifecycle_manager.cpp`, `services/src/ime_state_manager.cpp` | IME 生命周期涉及多进程协同，理解状态机再改 |
| 修改多用户/会话逻辑 | `services/src/peruser_session.cpp`, `services/src/user_session_manager.cpp`, `services/adapter/os_account_adapter/` | 多用户场景有跨用户隔离要求 |
| 修改 DFX/日志/事件 | `common/include/global.h` (IMSA_HILOG* 宏), `hisysevent.yaml`, `common/include/inputmethod_sysevent.h` | 日志和事件有命名规范和配置约束 |
| 修改 seccomp 策略 | `seccomp_policy/imf_ext_secure_mode.seccomp.policy` | seccomp 策略影响 Extension 安全沙箱 |

### 词汇触发路由

遇到以下术语时，阅读对应知识源：

| 术语/缩写 | 含义 | 指向 |
|-----------|------|------|
| **IME** | 输入法引擎应用 | `frameworks/native/inputmethod_ability/`, [inputmethod-application-guide.md](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/inputmethod-application-guide.md) |
| **IMF** | 输入法框架服务 | `services/` |
| **IMC** | 应用端控制器 | `frameworks/native/inputmethod_controller/` |
| **IMA** | 输入法端能力 | `frameworks/native/inputmethod_ability/` |
| **SA** | 系统能力（IMF 注册为 SA 3703） | `profile/3703.json`, `services/src/input_method_system_ability.cpp` |
| **IPC Stub/Proxy** | 跨进程通信的服务端 Stub 和客户端 Proxy | IDL 文件（`frameworks/native/` 下各 `.idl`）为源码，Stub/Proxy 由构建系统自动生成 |
| **Panel** | 输入法面板（SOFT_KEYBOARD / STATUS_BAR） | `frameworks/native/inputmethod_ability/include/panel_info.h`（枚举定义）, `input_method_panel.h`（面板类） |
| **Panel Flag** | 面板标志（FLG_FIXED / FLG_FLOATING / FLG_CANDIDATE_COLUMN） | `frameworks/native/inputmethod_ability/include/panel_info.h` |
| **Immersive Mode** | 沉浸显示模式 | `frameworks/native/inputmethod_ability/include/panel_info.h`（枚举定义）, [inputmethod-immersive-mode-guide.md](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/inputmethod/inputmethod-immersive-mode-guide.md) |
| **DeathRecipient** | 远程对象死亡监听 | `common/include/input_death_recipient.h` |
| **IdentityChecker** | 权限/焦点/身份校验器 | `services/identity_checker/include/identity_checker.h` |
| **PerUserSession** | 每用户会话管理 | `services/include/peruser_session.h` |
| **ClientGroup** | 客户端分组管理 | `services/include/client_group.h` |
| **NAPI** | JS/ArkTS 到 C++ 的绑定层 | `frameworks/js/napi/` |
| **CAPI** | C 语言公共 API | `frameworks/ndk/`（实现）, `interfaces/kits/c/`（头文件） |
| **CJ** | CJ 语言 FFI 绑定 | `frameworks/cj/` |
| **ExtensionAbility** | 输入法 Extension 能力 | `frameworks/kits/extension/`, `frameworks/ets/extension/` |
| **Seccomp** | 安全计算模式策略 | `seccomp_policy/` |
| **HiSysEvent** | 系统事件打点 | `hisysevent.yaml`, `common/include/inputmethod_sysevent.h` |
| **IMSA** | IMF 服务端代号 | `services/src/input_method_system_ability.cpp` |
| **IDL** | 接口定义语言 — IPC 接口的源文件 | `frameworks/native/` 下各 `.idl` 文件，构建时自动生成 Stub/Proxy |

### 路径触发路由

修改以下目录中的文件时，额外必读：

| 修改路径 | 额外必读 | 原因 |
|----------|---------|------|
| `services/adapter/` | 对应系统服务的 API 文档 | 适配层代理了外部系统服务接口，需理解原始 API |
| `services/hook/` | `interfaces/inner_api/imf_hook/` | Hook 是框架行为注入点，有独立 inner_api |
| `frameworks/js/napi/` | NAPI 官方文档 | NAPI 绑定有内存管理和生命周期规范 |
| `frameworks/ets/` | ArkTS/ETS API 文档 | ETS 绑定需遵循 ArkUI 框架规范 |
| `seccomp_policy/` | OpenHarmony seccomp 策略规范 | 安全策略变更影响 Extension 运行沙箱 |
| `etc/` | 对应系统参数规范 | init cfg 和 para 文件有格式和 DAC 约束 |
| `services/identity_checker/` | `services/identity_checker/include/identity_checker.h` | 权限/安全逻辑变更需理解 IdentityChecker 接口 |

## 核心功能

OpenHarmony 输入法框架 (IMF) 是一个系统服务（SA 3703），用于管理操作系统上的文本输入能力。它为应用程序与输入法引擎 (IME) 交互提供统一的接口。框架处理多用户场景、安全输入、配置管理，并支持原生 C++ 和 ArkTS 开发。

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

管理面板生命周期的主要类（定义于 `frameworks/native/inputmethod_ability/include/input_method_panel.h`）：

- `CreatePanel()` - 使用指定配置创建面板
- `DestroyPanel()` - 销毁面板并释放资源
- `ShowPanel()` / `HidePanel()` - 控制面板可见性
- `Resize()` - 将面板调整为指定尺寸
- `MoveTo()` - 将面板移动到指定位置
- `SetImmersiveMode()` - 设置沉浸显示模式
- `GetSystemPanelCurrentInsets()` - 获取系统面板偏移信息

#### 输入法控制器

输入法框架的核心控制器（定义于 `frameworks/native/inputmethod_controller/`）：

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
   - 文本操作和光标控制，参见「文本变化监听器」和「输入法控制器」
   - 按键事件分发和监听
   - 通信：直接调用框架 API，通过 IPC/Binder 与服务通信
   - 关键组件：InputClientServiceImpl, KeyEventConsumerServiceImpl, InputDataChannelServiceImpl

2. **输入法客户端** (`frameworks/native/inputmethod_ability`)
   - 监控输入法当前状态
   - 面板生命周期管理（创建/销毁/显示/隐藏/调整/移动），参见「输入法面板」
   - 沉浸模式和面板类型/标志支持，参见「IMF 特定概念」
   - 通信：通过 IPC/Binder 与服务通信
   - 关键组件：InputMethodPanel, InputMethodAbility

3. **输入法服务** (`services`)
   - 输入法框架的核心（SA 3703）
   - 输入法的主要处理逻辑
   - 状态管理、面板管理、输入分发
   - 子组件：
     * InputMethodSystemAbility - SA 主入口
     * UserSessionManager - 每用户会话管理
     * PerUserSession - 单用户会话实例
     * ClientGroup - 客户端分组和管理
     * ImeInfoInquirer - IME 信息查询
     * ImeLifecycleManager - IME 生命周期管理
     * ImeStateManager / ImeStateManagerFactory - IME 状态机
     * InputTypeManager - 输入类型管理
     * IdentityChecker / IdentityCheckerImpl - 权限/焦点/身份校验（独立子目录）
     * FreezeManager - 冻结管理
     * FullImeInfoManager - IME 全量信息管理
   - 通信：通过 IPC/Binder 与所有客户端通信

4. **输入法 JS 接口** (`frameworks/js/napi/`)
   - inputmethodclient: 输入法控制 NAPI 模块
   - inputmethodability: 输入法引擎 NAPI 模块
   - inputmethodlist: 输入法列表/切换 NAPI 模块
   - keyboardpanelmanager: 面板管理 NAPI 模块
   - ExtraConfig: 配置管理（定义于 `interfaces/kits/js/`）
   - 通信：JavaScript/Node-API 绑定到原生代码

5. **CAPI** (`frameworks/ndk/`（实现）, `interfaces/kits/c/`（公共头文件）)
   - 原生应用的 C API 实现和头文件
   - InputMethod_Controller：绑定、解绑、显示/隐藏键盘
   - InputMethod_TextEditorProxy：文本操作和光标控制
   - InputMethod_MessageHandlerProxy：消息处理回调
   - InputMethod_PrivateCommand：私有命令通信
   - InputMethod_Types：类型定义
   - InputMethod_AttachOptions：绑定选项
   - 通信：C API 到原生实现

6. **ETS/ArkTS 接口** (`frameworks/ets/`)
   - `taihe/inputMethod/` - 应用端 InputMethod ArkTS 绑定
   - `taihe/inputMethodEngine/` - IME 应用端 InputMethodEngine ArkTS 绑定
   - `taihe/keyboardPanelManager/` - 面板管理 ArkTS 绑定
   - `extension/` - 输入法 ExtensionAbility（ani + ets）
   - `inputmethodlist/` - 输入法列表对话框
   - 通信：ArkTS 绑定到原生代码

7. **CJ 语言绑定** (`frameworks/cj/`)
   - CJ 语言 FFI 绑定到 IMF 原生实现
   - 通信：CJ FFI 到原生代码

8. **输入法 Extension** (`frameworks/kits/extension/`, `frameworks/kits/extension_cj/`)
   - 输入法 ExtensionAbility 框架实现
   - Extension 模块和 Extension Context
   - CJ Extension FFI 绑定

### 通信模式

**模块间通信：**

- 应用 → 输入法框架 API（直接调用）
- 应用 → 输入法服务（IPC/Binder）
- 输入法框架 API → 输入法服务（IPC/Binder）
- 输入法服务 → 输入法应用（IPC/Binder）
- 输入法应用 → 系统服务（IPC/Binder）

**系统服务集成：**

- 窗口管理器 (`window_adapter`) - 面板显示管理
- 包管理器 (`app_mgr_adapter`) - 查询包信息和扩展能力
- 公共事件管理器 - 事件处理和分发
- IPC 核心 - 进程间通信
- 能力管理器 (`samgr`) - 能力生命周期管理
- 显示管理器 (`display_adapter`) - 显示管理
- 输入管理器 (`keyboard`) - 按键事件监听
- 系统参数适配 (`system_param_adapter`) - 系统参数读写
- 设置数据提供 (`settings_data_provider`) - 设置数据访问
- OS 账号适配 (`os_account_adapter`) - 多用户账号
- 资源调度适配 (`res_sched_adapter`) - 资源调度
- 焦点监控 (`focus_monitor`) - 焦点变化监听

## 目录结构

```
inputmethod_imf/
├── common/                  # 共享工具和头文件
│   └── include/            # global.h(错误码/日志宏), input_death_recipient.h,
│                            # itypes_util.h, block_queue.h, message.h 等
├── services/                # 核心服务实现（SA 3703）
│   ├── src/                # 主服务源文件（核心业务逻辑）
│   ├── include/             # 服务头文件
│   ├── adapter/             # 平台适配器（12个子模块）
│   │   ├── app_mgr_adapter/      # 包管理适配
│   │   ├── display_adapter/      # 显示管理适配
│   │   ├── window_adapter/       # 窗口管理适配
│   │   ├── keyboard/             # 输入管理适配
│   │   ├── focus_monitor/        # 焦点监控适配
│   │   ├── ime_connection_manager/ # IME 连接管理
│   │   ├── os_account_adapter/   # 多用户账号适配
│   │   ├── samgr/                # 系统能力管理适配
│   │   ├── settings_data_provider/ # 设置数据提供
│   │   ├── system_param_adapter/ # 系统参数适配
│   │   ├── res_sched_adapter/    # 资源调度适配
│   │   └── wms_connection_monitor/ # WMS 连接监控
│   ├── identity_checker/    # 权限/焦点/身份校验器
│   ├── dialog/              # 输入法选择对话框
│   ├── hook/                # IMF 行为注入 Hook 管理
│   ├── module/              # 模块管理器
│   ├── json/                # JSON 序列化工具
│   └── file/                # 文件操作
├── frameworks/              # 客户端框架
│   ├── native/              # 原生 C++ 客户端实现
│   │   ├── inputmethod_controller/  # 应用端控制器（IMC）
│   │   └── inputmethod_ability/     # 输入法端能力（IMA）
│   ├── js/napi/             # JavaScript/Node-API 绑定模块
│   │   ├── inputmethodclient/       # 输入法控制 NAPI
│   │   ├── inputmethodability/      # 输入法引擎 NAPI
│   │   ├── inputmethodlist/         # 列表/切换 NAPI
│   │   └── keyboardpanelmanager/    # 面板管理 NAPI
│   ├── ndk/                 # CAPI 实现
│   ├── cj/                  # CJ 语言 FFI 绑定
│   ├── ets/                 # ArkTS/ETS 绑定
│   │   ├── taihe/           # Taihe 绑定（inputMethod, inputMethodEngine, keyboardPanelManager）
│   │   ├── extension/       # ExtensionAbility（ani + ets）
│   │   └── inputmethodlist/ # 输入法列表对话框
│   └── kits/                # 扩展工具包
│       ├── extension/       # 输入法 Extension 框架
│       ├── extension_cj/    # CJ Extension FFI 绑定
│       └── extra_config/    # Extra 配置工具
├── interfaces/              # API 定义
│   ├── inner_api/           # 内部 API
│   │   ├── inputmethod_controller/  # 应用端内部 API 头文件
│   │   ├── inputmethod_ability/     # IME 端内部 API 头文件
│   │   └── imf_hook/               # IMF Hook 内部 API
│   └── kits/                # 公共 API
│       ├── js/              # ExtraConfig NAPI/ANI 头文件
│       └── c/               # C API 头文件（公共接口）
├── test/                    # 测试套件
│   ├── unittest/            # 单元测试
│   │   ├── cpp_test/        # C++ gtest 单元测试
│   │   ├── napi_test/       # NAPI 测试
│   │   └── queue_test/      # 队列测试
│   ├── fuzztest/            # Fuzz 测试（35+ fuzz 目标）
│   └── common/              # 测试工具和 mock
├── etc/                     # 系统配置
│   ├── init/                # SA init cfg 文件
│   └── para/                # 系统参数和 DAC 配置
├── seccomp_policy/          # Seccomp 安全策略（Extension 沙箱）
├── profile/                 # SA profile（3703.json, 3703_ondemand.json）
├── tools/                   # 开发工具
│   └── ime/                 # 输入法 CLI 管理工具
├── hisysevent.yaml          # HiSysEvent 事件配置
├── hisysevent_ue.yaml       # HiSysEvent UE 事件配置
├── inputmethod.gni          # GN 构建变量定义
├── BUILD.gn                 # 根构建配置
└── bundle.json              # 组件依赖和构建定义
```

## 构建系统

### 环境检测

编译前必须先确认当前编译环境：

1. 查看 `.repo` 的父目录中所有目录名称
2. 如果存在以下目录名称中 70% 及以上则认为是**全量源码环境**：`applications, arkcompiler, base, build, commonlibrary, developtools, device, docs, domains, drivers, foundation, ide, interface, kernel, napi_generator, prebuilts, productdefine, test, third_party, vendor`
3. 否则是**独立编译环境**
4. 有 `build.sh` 不一定是全量源码环境，判断编译环境必须按上述方法严格执行

### 全量源码编译

所有命令必须从源码根目录（包含 `.repo` 的目录）执行。product 默认是 rk3568。

```bash
# 编译 IMF 业务代码
./build.sh --product-name rk3568 --build-target imf

# 编译 IMF 测试用例（TDD, FUZZ）
./build.sh --product-name rk3568 --build-target imf_test
```

- **编译产物位置**：`out/rk3568/inputmethod/imf/`
- **测试产物位置**：`out/rk3568/tests/unittest/imf/imf/cpp/<test_name>`
- **编译成功标志**：打印 `=====build  successful=====`

### 独立编译

所有命令必须从源码根目录（包含 `.repo` 的目录）执行。product 默认是 rk3568。

先检查 hb 工具是否可用：`hb help`（输出无异常则 hb 编译环境 OK）。

```bash
# 编译 IMF 业务代码
hb build imf -i                              # 首次编译或改动过 BUILD.gn
hb build imf -i --fast-rebuild               # 非首次且未改动 BUILD.gn

# 编译 IMF 测试用例（TDD, FUZZ）
hb build imf -t                              # 首次编译或改动过 BUILD.gn
hb build imf -t --fast-rebuild               # 非首次且未改动 BUILD.gn
```

- **编译产物位置**：`out/standard/src/inputmethod/imf/`
- **测试产物位置**：`out/standard/test/tests/unittest/imf/imf/cpp/<test_name>`
- **业务编译成功标志**：打印 `imf build src success`
- **测试编译成功标志**：打印 `imf build test success`

### 测试执行

编译测试用例后，执行方式取决于测试框架：

- **TDD 单元测试**：使用 `testfwk_developer_test` 框架执行编译产物

### 代码格式化

**仅对新增或本次修改的代码做格式化，不要对历史代码做格式化。**

```bash
# 格式化修改的 C/C++ 代码（使用仓库根 .clang-format 配置，基于 WebKit 风格）
clang-format -i --style=file <修改的文件>
```

关键格式化规则（来自 `.clang-format`）：基于 WebKit 风格、指针靠右（`int *ptr`）、列宽限制 120、命名空间不缩进。

### 关键构建产物

| 构建目标 | 产出 | 说明 |
|----------|------|------|
| `inputmethod_client` | `libinputmethod_client.z.so` | 应用端客户端共享库 |
| `inputmethod_ability` | `libinputmethod_ability.z.so` | IME 端能力共享库 |
| `inputmethod_service` | `libinputmethod_service.z.so` | 服务端核心共享库 |
| `inputmethod` | `libinputmethod.z.so` (NAPI 模块) | JS 公共 API 模块 |
| `inputmethodengine` | `libinputmethodengine.z.so` (NAPI 模块) | JS IME API 模块 |
| `ohinputmethod` | CAPI 库 | C API 公共库 |

## 错误处理

### 错误码（来自 `common/include/global.h` ErrorCode namespace）

已有错误码枚举值不可变更：

```cpp
// 通用段
ErrorCode::NO_ERROR              // 无错误
ErrorCode::ERROR_NULL_POINTER    // 空指针
ErrorCode::ERROR_BAD_PARAMETERS  // 参数错误
ErrorCode::ERROR_CLIENT_NOT_FOUND // 客户端未找到
ErrorCode::ERROR_STATUS_PERMISSION_DENIED  // 权限被拒
ErrorCode::ERROR_STATUS_SYSTEM_PERMISSION  // 非系统应用
ErrorCode::ERROR_NOT_CURRENT_IME  // 非当前输入法
ErrorCode::ERROR_NOT_IME         // 非输入法应用

// IMA 段（ERROR_IMA_BEGIN ~ ERROR_IMA_END）
ErrorCode::ERROR_IME
ErrorCode::ERROR_OPERATE_PANEL
ErrorCode::ERROR_IMA_CHANNEL_NULLPTR
ErrorCode::ERROR_IMA_INVALID_IMMERSIVE_EFFECT

// IMC 段（ERROR_IMC_BEGIN ~ ERROR_IMC_END）
ErrorCode::ERROR_CLIENT_NOT_EDITABLE
ErrorCode::ERROR_CLIENT_NOT_BOUND
ErrorCode::ERROR_IMC_NULLPTR

// IMSA 段（ERROR_IMSA_BEGIN ~ ERROR_IMSA_END）
ErrorCode::ERROR_IME_NOT_STARTED
ErrorCode::ERROR_CLIENT_NOT_FOCUSED
ErrorCode::ERROR_IMSA_NULLPTR
ErrorCode::ERROR_IMSA_USER_SESSION_NOT_FOUND
```

### 日志（IMSA_HILOG 宏来自 `common/include/global.h`）

```cpp
// 所有日志宏自动包含行号和函数名，无需手动添加
IMSA_HILOGD("Debug: %{public}s", str.c_str());    // LOG_DEBUG
IMSA_HILOGI("Info: %{public}d", count);           // LOG_INFO
IMSA_HILOGW("Warning: %{public}s", msg.c_str());  // LOG_WARN
IMSA_HILOGE("Error: %{public}d", errorCode);      // LOG_ERROR
IMSA_HILOGF("Fatal: %{public}s", reason.c_str()); // LOG_FATAL
```

**日志规范**：
- 隐私数据使用 `%{private}` 标记，公开数据使用 `%{public}` 标记
- Log domain: `0xD001C10`，Log tag: `ImsaKit`
- 不要使用 `printf` 或 `cout`，必须使用 IMSA_HILOG* 宏

## 主要依赖（来自 bundle.json）

| 依赖 | 用途 |
|------------|---------|
| `init` | 进程状态通知和系统参数读写（begetutil, beget_proxy） |
| `napi` | JavaScript/ArkTS 绑定的 Node-API |
| `samgr` | 服务注册和检索的系统能力管理器 |
| `ipc` | 进程间通信（IRemoteObject, Binder, IPCSkeleton） |
| `eventhandler` | 任务发布和事件分发（EventHandler, EventQueue） |
| `bundle_framework` | 查询包信息和扩展能力（BundleMgrClient） |
| `ability_runtime` | 能力生命周期、ExtensionAbilityInfo、AppManager |
| `hilog` | 日志框架（IMSA_HILOG* 宏） |
| `access_token` | 权限检查（AccessTokenID, HasPermission） |
| `window_manager` | 面板显示管理（DisplayManagerLite, libwsutils, libwm） |
| `input` | 按键事件监听（KeyEvent, KeyboardEvent, InputManager） |
| `os_account` | 多用户支持（QueryActiveOsAccountIds） |
| `c_utils` | 基础工具库 |
| `hisysevent` | 系统事件打点 |
| `hitrace` | 跟踪框架 |
| `ffrt` | 并发调度框架 |
| `graphic_2d` | 图形渲染 |
| `data_share` | 数据共享 |
| `screenlock_mgr` | 锁屏管理 |
| `hicollie` | 看门狗/超时检测 |
| `ace_engine` | ArkUI 引擎 |

## 约束和边界

### 禁止事项

- **禁止** 删除失败的测试用例来使用例"通过"
- **禁止** 未明确用户请求时提交代码
- **禁止** 对已有公共接口做不兼容变更：
  - 禁止删除已有接口或修改接口签名（参数类型、返回值类型、参数顺序）
  - 禁止修改已有接口实现时抛出新的错误码
  - 禁止修改已有接口的语义或默认行为
  - 禁止在已有接口中新增必填参数
  - 如需扩展功能，应新增接口而非修改已有接口
  - 此规则适用于 ArkTS API、JS NAPI、CAPI、inner_api 所有层
- **禁止** 变更已有错误码枚举值
- **禁止** 敏感操作跳过权限检查 — 所有涉及 IME 切换、安全模式、系统级操作的 IPC 方法必须调用 IdentityChecker 校验。
- **禁止** 使用无明确所有权语义的原始指针 — `sptr<>` 用于 Binder/IPC 对象（IRemoteObject 派生类），`std::shared_ptr` 用于普通 C++ 对象，`std::unique_ptr` 用于独占所有权对象
- **禁止** 使用 `new` 时不加 `std::nothrow` 和空指针检查
- **禁止** 发明新的命名约定 — 遵循现有模式（类/方法 PascalCase，成员变量 camelCase_ 后缀，互斥锁 camelCase_ 后缀以 Lock_/Mutex_/Mtx_ 结尾）
- **禁止** 修改 IPC 消息码编号或重新排序 — IPC 消息码是跨进程协议，新增消息码只能在现有列表末尾追加
- **禁止** 跨模块反向依赖 — 服务层 (`services/`) 不应导入客户端头文件 (`frameworks/native/inputmethod_controller/` 或 `inputmethod_ability/`)
- **禁止** 直接修改 `seccomp_policy/` 文件 — Seccomp 策略变更需安全团队审批
- **禁止** 在日志中泄露隐私数据 — 使用 `%{private}` 标记，不要打印用户输入内容、TokenID 等敏感信息
- **禁止** 跳过 DeathRecipient 设置 — 与远程对象交互时必须使用 `InputDeathRecipient`：`new (std::nothrow) InputDeathRecipient()` + `SetDeathRecipient(lambda)` + `remote->AddDeathRecipient(deathRecipient)`，存储为 `sptr<InputDeathRecipient>` 成员
- **禁止** 在 NAPI 模块中使用非 `napi_ok` 返回值时跳过错误处理 — 使用 `IMF_CALL` / `IMF_CALL_RETURN_VOID` 宏检查
- **禁止** 手动编写 IPC Stub/Proxy 代码 — Stub/Proxy 由 IDL 文件通过构建系统自动生成（`idl_gen_interface`），修改 IPC 接口时改 `.idl` 文件而非生成的代码
- **禁止** 修改面板类型/标志枚举值 — 枚举值是公共 API 的一部分，新增只能在末尾追加

### 修改前需确认

- **修改公共 API**（任何 `interfaces/kits/` 或 `frameworks/ets/taihe/` 下的接口） → 需确认兼容性审查已通过
- **修改 IPC 消息码或序列化格式** → 需确认跨版本兼容方案
- **修改权限/安全检查逻辑** (`services/identity_checker/`) → 需确认安全团队审批
- **修改 SA 启停行为** (`etc/init/`, `profile/`) → 需确认系统稳定性影响
- **修改多用户会话逻辑** → 需确认跨用户隔离不受影响
- **新增外部依赖** → 需确认许可证兼容（仅接受 Apache-2.0、MIT、BSD 等宽松许可证，不接受 GPL/AGPL 等强限制性许可证）和 bundle.json 审批
- **修改 seccomp 策略** → 需确认安全团队审批
- **新增或修改 IDL 文件** → 需确认 IPC 接口兼容性和 Stub/Proxy 重新生成流程

### 架构不变量

- **三层分离**：应用端 (IMC) → 服务端 (IMSA) → 输入法端 (IMA)，依赖方向为 IMC/IMA → IMSA，服务端不反向依赖客户端
- **IPC 是唯一跨进程通道**：IMC/IMA 与 IMSA 之间所有通信必须通过 Binder IPC，不得使用共享内存、文件等其他方式绕过
- **每用户隔离**：PerUserSession 管理每个用户的 IME 状态，跨用户操作必须通过 UserSessionManager 并校验权限
- **面板窗口由系统管理**：IME 应用不直接创建窗口，通过 IMF 服务协调 WindowManager 创建和显示面板
- **Adapter 层隔离系统服务**：所有对外部系统服务的调用必须通过 `services/adapter/` 下的适配器，不得直接使用系统服务 API
- **DeathRecipient 必须设置**：持有远程对象引用时必须注册 InputDeathRecipient，否则无法感知对端进程死亡
- **IDL 是 IPC 接口的源文件**：Stub/Proxy 代码由构建系统从 `.idl` 文件自动生成，不要手动修改生成的代码
- **智能指针规则**：`sptr<>` 用于 IPC/Binder 对象，`std::shared_ptr` 用于普通 C++ 对象，不混用

### 常见 Agent 失败模式

- **在服务层代码中直接使用客户端类**：服务不应知道客户端的具体实现类，应通过 IPC 接口交互
- **新增 IPC 方法时手动编写 Stub/Proxy**：应修改 `.idl` 文件并让构建系统重新生成，而非手动编写 Stub/Proxy 代码
- **修改错误码时导致已有枚举值变更**：新增或调整错误码必须确保已有枚举值不变
- **忽略多用户场景**：IMF 是系统服务，多用户并发操作是常态，修改逻辑时必须考虑多用户隔离
- **在 NAPI 层泄露 C++ 异常**：NAPI 绑定必须将 C++ 异常转换为 JS 错误码，不得让异常穿透到 JS 层
- **修改面板类型/标志枚举值**：枚举值是公共 API 的一部分，新增只能在末尾追加，不能修改已有值
- **权限检查遗漏**：涉及 IME 切换、安全模式、系统级操作的 IPC 方法必须使用 IdentityChecker 校验权限和焦点

## 验证循环

### 最小验证（每次变更必须执行）

1. **编译检查**（参见「构建系统」章节的构建命令）
2. **LSP 诊断**：对修改的文件运行 LSP 检查，确认无新增 error
3. **代码格式化**（参见「构建系统」章节的格式化命令）

### 任务特定验证

| 变更类型 | 验证步骤 |
|----------|---------|
| **C++ 业务逻辑变更** | 编译 + 对应单元测试 (`test/unittest/cpp_test/`) |
| **NAPI 绑定变更** | 编译 + NAPI 测试 (`test/unittest/napi_test/`) |
| **公共 API 变更** | 编译 + 对比官方 API 文档确认无不兼容变更 |
| **IPC 变更**（修改 IDL） | 编译 + 确认 Stub/Proxy 重新生成 + fuzz 测试 (`test/fuzztest/` 中对应 stub fuzzer) |
| **服务端逻辑变更** | 编译 + `inputmethodsystemability_fuzzer` + 相关 cpp_test |
| **安全/权限变更** | 编译 + 权限场景测试 + IdentityChecker 相关测试 |

### Done 定义

任务完成必须满足：

1. ✅ 所有修改的文件 LSP 诊断无新增 error
2. ✅ 编译成功（参见「构建系统」章节，根据环境选择全量源码或独立编译命令）
3. ✅ 代码格式化已执行（参见「构建系统」章节的格式化命令）
4. ✅ 相关测试用例通过（如有对应测试）
5. ✅ 未引入公共 API 不兼容变更（如涉及公共 API）
6. ✅ 未违反任何约束和边界中列出的禁止事项

### 最终响应要求

完成任务后，报告必须包含：

- **修改的文件列表**及每个文件的变更摘要
- **执行的验证步骤**及结果（编译结果、测试结果、格式化状态）
- **是否涉及公共 API**：如是，列出具体接口和兼容性说明
- **是否涉及 IPC/权限/安全**：如是，列出具体变更点和风险评估

### 验证无法执行时的回退

如果构建环境不可用（无法执行构建命令）：

1. 确保所有修改的文件无语法错误（通过 LSP 诊断）
2. 确保所有修改遵循现有代码模式（通过阅读同类文件对比）
3. 明确标注"编译验证未执行"，列出预计影响
4. 不要假设编译会通过 — 必须标注验证缺口

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