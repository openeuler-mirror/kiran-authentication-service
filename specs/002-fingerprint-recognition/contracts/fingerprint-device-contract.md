# 接口契约: 本地指纹设备

**Date**: 2026-09-01  
**范围**: kiran-control-panel ↔ kiran-authentication-daemon ↔ 设备管理服务 ↔ libfprint 指纹驱动插件

## 1. 链路总览

```
控制面板                      daemon                         设备管理服务                   驱动插件
FingerPage                  User/Session/DeviceAdaptor       FingerprintDevice             LibfprintDriver
  │ EnrollStart(fingerprint,     │                                │                              │
  │   name, extraInfo)           │ 注入当前用户 feature_ids        │                              │
  ├─────────────────────────────>│ EnrollStart(extraInfo)        │                              │
  │                              ├───────────────────────────────>│ 查重 identify → enroll        │
  │                              │                                ├─────────────────────────────>│
  │<─ EnrollStatus(...)          │<─ 转发                         │<─ progress / COMPLETE data   │
  │                              │ COMPLETE → FeatureDB           │                              │
  │                              │                                │                              │
  │                              │ Session.startGeneralAuth       │                              │
  │                              │ feature_ids + user_name        │ IdentifyStart(extraInfo)     │
  │                              ├───────────────────────────────>│ 组装 gallery → identify      │
  │                              │                                ├─────────────────────────────>│
  │<─ AuthMessage / 结果         │<─ IdentifyStatus / Auth*       │<─ MATCH/NOT_MATCH/RETRY      │
```

## 2. 录入契约

### 2.1 请求

| 参数 | 值 |
|---|---|
| authType | `KAD_AUTH_TYPE_FINGERPRINT` |
| featureName | 面板自动生成 |
| extraInfo | 至少含当前用户 `feature_ids`（daemon 注入）；可无图像字段 |

**时序**: 面板切入录入页即 `EnrollStart`（与人脸「先预览再拍照建会话」不同）；用户按提示在指纹仪上按压。

### 2.2 设备内部两阶段

1. **DUPLICATE_CHECK**（已有特征时）：identify 当前用户模板；命中 → `ENROLL_STATUS_REPEATED`（「该指纹已录入」）
2. **FORMAL**：`enroll` 多阶段；PASS/RETRY/NORMAL 中间态；成功 → COMPLETE + FeatureData

### 2.3 EnrollStatus

| result | 场景 | progress | data | message 示例 |
|---|---|---|---|---|
| NORMAL | 提示按压/查重 | 0~n | — | 「请按压手指进行重复检测」「请再次按压手指录入」 |
| PASS | 某一阶段通过 | 递增 | — | 阶段通过提示 |
| RETRY | 质量不佳 | 当前 | — | 「指纹质量不佳，请重试」 |
| REPEATED | 与已有特征重复 | 0 | — | 「该指纹已录入」 |
| FAIL | 打开失败/取消/驱动错误 | 0 | — | 驱动错误文案 / 「fingerprint operation canceled」 |
| COMPLETE | 成功 | 100 | FeatureData JSON | 「enroll success」等 |

COMPLETE 的 data 含：feature、featureID(MD5)、idVendor、idProduct、deviceType。

### 2.4 停止

面板取消 → `EnrollStop` → 设备置位 + `cancel(handle)` → finished 若 stop 则丢弃。

## 3. 识别契约

### 3.1 请求 extraInfo

```json
{
  "feature_ids": ["..."],
  "user_name": "<认证目标用户>"
}
```

| 场景 | feature_ids | 设备 gallery |
|---|---|---|
| 不可切换 | 非空（该用户） | 仅白名单 |
| 可切换 | 空数组 | user_name 优先 + 全库 |

无可用特征 → 直接 `IDENTIFY_STATUS_NOT_MATCH`（如「identify fail!」）。

### 3.2 IdentifyStatus

| result | 场景 | featureID | 是否结束 |
|---|---|---|---|
| RETRY | 扫描质量问题 | — | 否（同一次扫描过程中） |
| MATCH | 命中模板 | 命中 ID | 是 |
| NOT_MATCH | 明确不匹配或错误映射为不匹配 | — | 是 |

**语义要点**: MATCH 路径驱动可 early-cancel；daemon 对 MATCH 调 `matchUser`；可切换时允许特征所属用户 ≠ 发起用户。

### 3.3 停止

`IdentifyStop` → stop 标志 + `cancel` → finished 丢弃结果（FR-008）。

## 4. 特征管理契约

| 操作 | 链路 | 说明 |
|---|---|---|
| 列表 | `GetIdentifications(fingerprint)` | 既有 |
| 重命名 | `RenameIdentification` | 既有 |
| 删除 | `DeleteIdentification` + 设备 Remove | 既有 |

## 5. 驱动错误码

避开状态码 0~5 值域：

| 码 | 含义 |
|---|---|
| 100 | 打开失败 |
| 101 | 录入失败 |
| 102 | 识别失败 |
| 103 | 已取消 |
| 104 | 无已录入特征 |

文案经 `getErrorMsg` / 设备 tr() 映射后进 message。

## 6. 兼容性

- daemon：`authType2DeviceType(FINGERPRINT)`、COMPLETE 落库、`startGeneralAuth` 注入、`matchUser` 均已存在；可切换全库语义由**设备侧** consumie 空 feature_ids 实现。
- 面板：finger-page 既有进度 UI，消费 EnrollStatus，无需 faceImage。
- 构建：无 libfprint 时可跳过插件（FR-015）。
