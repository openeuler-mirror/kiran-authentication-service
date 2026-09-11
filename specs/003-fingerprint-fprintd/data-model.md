# Phase 1 Data Model: 基于 fprintd 的本地指纹识别认证

**Date**: 2026-09-04

## 实体

### 1. 指纹特征映射 (FeatureData) — 复用结构，语义变更

来源：`lib/feature-data.h`；落库：`FeatureDB`。

| 字段 | 类型 | 说明 |
|---|---|---|
| feature | QByteArray | **可空**；不再存 libfprint serialize 字节 |
| featureID | QString | = MD5(`fprintd:` + userName + `:` + finger_name) |
| featureName | QString | 面板生成或用户重命名（仅展示） |
| iid | QString | daemon 生成 |
| userName | QString | 所属操作系统账户 |
| deviceType / authType | int | DEVICE_TYPE_FINGERPRINT / KAD_AUTH_TYPE_FINGERPRINT |
| idVendor / idProduct | QString | 若 fprintd 设备属性可提供则写入，否则可空 |
| （扩展/约定）finger_name | — | 首期可用 featureName 旁路字段或写入 feature 占位 JSON；**推荐在 FeatureData 扩展或 extra 中显式存 finger_name**（实现时定） |

**写入方**: daemon `User::onEnrollStatus`（COMPLETE → addFeature 元数据）。  
**删除方**: 面板 → daemon 删库 + 设备 Remove → 驱动 `DeleteEnrolledFinger(finger_name)`。  
**读取方**: 识别时按 user_name / feature_ids 决定 Claim 目标；真正比对在 fprintd。

### 2. fprintd 模板

由 fprintd 管理，不入 FeatureDB。

| 键 | 说明 |
|---|---|
| username | 系统账户 |
| finger_name | 如 `left-thumb`、`right-index-finger` … |
| 存储位置 | 发行版约定（常见 `/var/lib/fprint/`） |

### 3. 指纹设备 (FingerprintDevice)

类：复用或特化 `src/device/adaptor/fingerprint-device.*`。

| 属性 | 值/说明 |
|---|---|
| deviceType | DEVICE_TYPE_FINGERPRINT |
| 绑定 | fprintd Device object path（如 `/net/reactivated/Fprint/Device/0`） |
| 状态机 | IDLE ⇄ DOING_ENROLL / DOING_IDENTIFY |
| 录入阶段 | 无独立查重阶段；直接 Enroll（fprintd enroll-duplicate → REPEATED） |
| claimedUser | 当前 Claim 的用户名；空表示未 Claim |

状态转换：

- `EnrollStart` 且 IDLE → Claim → DOING_ENROLL；结束/Stop → Release → IDLE
- `IdentifyStart` 且 IDLE → Claim → DOING_IDENTIFY；结束/Stop → Release → IDLE
- 非 IDLE 或 fprintd AlreadyInUse → 拒绝「设备忙」

### 4. 指纹驱动 (FprintdFingerprintDriver)

类：`plugins/driver/fingerprint-fprintd/fprintd-fingerprint-driver.*`，实现 `FingerprintDriver` 抽象（或并行抽象，若需区分 open 语义）。

能力：

- 枚举设备 object paths
- Claim / Release
- EnrollStart/Stop + EnrollStatus 映射
- VerifyStart/Stop + VerifyStatus 映射
- ListEnrolledFingers / DeleteEnrolledFinger
- 错误码映射（PermissionDenied、NoSuchDevice、…）

## 请求/响应契约对象

### 录入请求 extraInfo（daemon → 设备）

```json
{
  "user_name": "<当前用户>"
}
```

（指纹录入不携带 `feature_ids`；查重由 fprintd `enroll-duplicate` 完成。）
### 识别请求 extraInfo（daemon → 设备）

不可切换：

```json
{ "feature_ids": ["<md5...>"], "user_name": "<指定用户>" }
```

可切换：

```json
{ "feature_ids": [], "user_name": "<当前输入用户>" }
```

设备行为：

| 场景 | 行为 |
|---|---|
| 不可切换 | Claim(user_name) → VerifyStart("any") |
| 可切换 | 优先 Claim(user_name) Verify；失败则扩展其他有映射用户 |

### 状态回报

与既有面板 EnrollStatus / IdentifyStatus 语义对齐：

- 录入：`EnrollStatus(data, progress, result, message)` — NORMAL/PASS/RETRY/REPEATED/FAIL/COMPLETE
- 识别：`IdentifyStatus(featureID, result, message)` — RETRY/MATCH/NOT_MATCH

COMPLETE 的 data：FeatureData JSON（含 featureID、finger_name 约定字段、deviceType；feature 可空）。

### fprintd EnrollStatus → KAS 映射（示意）

| fprintd result | done | KAS |
|---|---|---|
| enroll-completed | true | COMPLETE |
| enroll-stage-passed | false | PASS（进度递增） |
| enroll-retry-scan / swipe / remove | false | RETRY |
| enroll-failed-* / enroll-disconnected | true | FAIL |
| enroll-data-full | true | FAIL（槽位满） |

### fprintd VerifyStatus → KAS 映射（示意）

| fprintd result | done | KAS |
|---|---|---|
| verify-match | true | MATCH |
| verify-no-match | true | NOT_MATCH |
| verify-retry-* | false | RETRY |
| verify-disconnected / verify-unknown-error | true | FAIL→NOT_MATCH 或 FAIL |

## 校验规则（源自 spec FR）

| 规则 | 来源 |
|---|---|
| fprintd enroll-duplicate 查重（一指一用户） | FR-010 |
| 不可切换仅目标用户 | FR-011 |
| 可切换优先当前用户再扩展 | FR-012 |
| 设备忙拒绝 | FR-007 |
| 停止丢弃结果 + Release | FR-008 |
| 每账户 ≤10 | FR-014 |
| featureID=稳定映射键 | FR-016 |
| 移除旧 libfprint 插件 / 不迁移 blob | FR-018 |
| 双源收敛 | FR-021 |
