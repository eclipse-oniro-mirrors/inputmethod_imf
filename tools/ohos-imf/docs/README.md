# ohos-imf

## 概述

输入法框架命令行工具，用于文本交互，仅可在 PC 端使用。

## 功能列表

- **文本输入**：向绑定输入法的焦点编辑框插入文本

## 基本用法

```bash
ohos-imf <command> [options]
ohos-imf --help
ohos-imf <command> --help
```

## 命令列表

| 命令 | 说明 | 参数 | 权限 | 前置依赖 |
|---------|-------------|------------|-------------|--------------|
| insert | 向绑定输入法的焦点编辑框插入文本 | `--text <string>`（必填），文本大小限制最大 512 字节 | ohos.permission.CONTROL_DEVICE | 编辑框与输入法应用已绑定 |


## 输出格式

所有命令将 JSON 输出到 stdout，结构如下：

### 成功响应
```json
{
  "type": "result",
  "status": "success",
  "data": {
    // 命令特定数据
  }
}
```

### 失败响应
```json
{
  "type": "result",
  "status": "failed",
  "errCode": "ERR_XXX",
  "errMsg": "错误描述",
  "suggestion": "建议的下一步操作"
}
```

### 错误码

| 错误码 | 说明 |
|------------|-------------|
| `ERR_CMD_INVALID` | 未知命令 |
| `ERR_ARG_COUNT_MISMATCH` | 参数数量不匹配 |
| `ERR_ARG_MISSING` | 缺少必须参数 |
| `ERR_ARG_OUT_OF_RANGE` | 参数值超出范围 |
| `ERR_INTERNAL_ERROR` | 内部错误 |
| `ERR_PERMISSION_DENIED` | 权限不足 |
| `ERR_EDIT_BOX_NOT_BOUND_WITH_IME_APP` | 不存在与输入法应用绑定的编辑框 |

## 示例

### insert

```bash
# 向编辑框中插入文本"hello world"
ohos-imf insert --text "hello world"

# 输出示例：
{
  "type": "result",
  "status": "success",
  "data": {}
}
```

## 安装

CLI 工具安装于 OpenHarmony 设备的 `/system/bin/cli_tool/executable/ohos-imf`。

## 构建配置

- **构建目标**：`ohos-imf`
- **子系统**：`inputmethod`
- **部件**：`imf`