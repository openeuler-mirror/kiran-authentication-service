# 接口契约: 基于 fprintd 的本地指纹设备

**Date**: 2026-09-04  
**范围**: kiran-control-panel ↔ kiran-authentication-daemon ↔ 设备管理服务 ↔ fprintd 指纹驱动插件 ↔ fprintd（`net.reactivated.Fprint`）

## 1. 链路总览

```
控制面板                 daemon                    设备管理服务                fprintd 插件              fprintd
FingerPage             User/Session                FingerprintDevice          FprintdDriver            system bus
  │ EnrollStart(fp,…)       │                           │                           │                        │
  ├────────────────────────>│ 注入 user_name            │                           │                        │
  │                         ├──────────────────────────>│ Claim → EnrollStart      │                        │
  │                         │                           ├──────────────────────────>│ Claim/Enroll            │
  │                         │                           │                           ├───────────────────────>│
  │<─ EnrollStatus          │<─ 转发                    │<─ 进度/COMPLETE 元数据     │<─ EnrollStatus         │
  │                         │ COMPLETE → FeatureDB 映射 │                           │                        │
  │                         │                           │                           │                        │
  │                         │ startGeneralAuth          │ IdentifyStart             │ Claim → Verify(…)      │
  │                         ├──────────────────────────>├──────────────────────────>├───────────────────────>│
  │<─ Auth 结果             │<─ IdentifyStatus          │<─ MATCH/NOT_MATCH         │<─ VerifyStatus         │
```

排障旁路（非生产热路径）：

```
运维 ── fprintd-enroll / fprintd-verify / fprintd-list / fprintd-delete ──> 同一 fprintd
```

## 2. fprintd D-Bus 面（插件必须使用）

| 接口 | 方法/信号 | 用途 |
|---|---|---|
| `net.reactivated.Fprint.Manager` | `GetDevices` / `GetDefaultDevice` | 枚举 |
| `net.reactivated.Fprint.Device` | `Claim(username)` / `Release` | 占用 |
| | `EnrollStart(finger)` / `EnrollStop` | 录入 |
| | `EnrollStatus(s result, b done)` | 录入进度 |
| | `VerifyStart(finger\|"any")` / `VerifyStop` | 校验 |
| | `VerifyStatus(s result, b done)` | 校验进度 |
| | `ListEnrolledFingers(username)` | 列表/同步 |
| | `DeleteEnrolledFinger(finger)` 等 | 删除 |

## 3. 录入契约

### 3.1 请求

| 参数 | 值 |
|---|---|
| authType | `KAD_AUTH_TYPE_FINGERPRINT` |
| featureName | 面板自动生成（展示名） |
| extraInfo | `user_name`（daemon 注入；指纹录入不注入 `feature_ids`） |

### 3.2 设备录入流程

1. Claim(user_name) → 选择空闲 finger_name → EnrollStart
2. 映射阶段信号 → PASS/RETRY/NORMAL；`enroll-duplicate` → REPEATED；成功 → COMPLETE + FeatureData 元数据

### 3.3 EnrollStatus（对上面板）

| result | 场景 | progress | data | message 示例 |
|---|---|---|---|---|
| NORMAL | 提示按压 | 0~n | — | 「请按压手指进行录入」 |
| PASS | 某一阶段通过 | 递增 | — | 阶段通过提示 |
| RETRY | 质量不佳 | 当前 | — | 「指纹质量不佳，请重试」 |
| REPEATED | fprintd enroll-duplicate（含跨用户） | 0 | — | 「该指纹可能已由当前用户或其他用户录入」 |
| FAIL | 取消/Polkit/无设备/驱动错误 | 0 | — | 可读错误 |
| COMPLETE | 成功 | 100 | FeatureData JSON（无 blob） | 「enroll success」 |

### 3.4 停止

`EnrollStop` → 插件 `EnrollStop` + `Release` → 丢弃结果（FR-008）。

## 4. 识别契约

### 4.1 请求 extraInfo

与既有 daemon/面板相同 JSON 形状；**设备侧解释为 fprintd Verify 策略**（见 data-model）。

### 4.2 IdentifyStatus

| result | 场景 | featureID | 是否结束 |
|---|---|---|---|
| RETRY | verify-retry-* | — | 否 |
| MATCH | verify-match | 映射 ID | 是 |
| NOT_MATCH | verify-no-match 等 | — | 是 |

### 4.3 停止

`IdentifyStop` → `VerifyStop` + `Release` → 丢弃结果。

## 5. 特征管理契约

| 操作 | 链路 | 说明 |
|---|---|---|
| 列表 | `GetIdentifications(fingerprint)` | FeatureDB；可与 ListEnrolledFingers 收敛 |
| 重命名 | `RenameIdentification` | 只改展示名 |
| 删除 | `DeleteIdentification` + 设备 Remove | 双删：DB + fprintd finger |

## 6. 驱动错误码

沿用既有设备错误码值域（避开状态码 0~5），并扩展 fprintd 相关码：

| 码 | 含义 |
|---|---|
| 100 | 打开/无设备失败 |
| 101 | 录入失败 |
| 102 | 识别失败 |
| 103 | 已取消 |
| 104 | 无已录入特征 |
| 105 | Polkit/权限拒绝（新增） |
| 106 | fprintd 服务不可用（新增） |
| 107 | Claim/AlreadyInUse（可映射为忙）（新增） |

## 7. 兼容性

- daemon：authType、COMPLETE 落库、`startGeneralAuth`、`matchUser` 复用；COMPLETE 须容忍空 feature blob
- 面板：finger-page 复用
- 构建：可跳过插件（FR-015）；**移除**进程内 libfprint 指纹插件（FR-018）
- CLI：仅文档与验收对照，不进入生产调用链（FR-019）
