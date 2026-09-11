# Phase 1 Data Model: 本地指纹识别认证

**Date**: 2026-09-01

## 实体

### 1. 指纹特征 (FeatureData) — 复用既有结构

来源：`lib/feature-data.h`；落库：`FeatureDB`（SQLite，`KAS_INSTALL_DATADIR`）。

| 字段 | 类型 | 说明 |
|---|---|---|
| feature | QByteArray | libfprint 序列化打印字节 |
| featureID | QString | = MD5(feature) |
| featureName | QString | 面板生成或用户重命名 |
| iid | QString | daemon 生成 |
| userName | QString | 所属操作系统账户 |
| deviceType / authType | int | DEVICE_TYPE_FINGERPRINT / KAD_AUTH_TYPE_FINGERPRINT |
| idVendor / idProduct | QString | 录入时设备的 VID/PID |

**写入方**: daemon `User::onEnrollStatus`（COMPLETE 解析 FeatureData → addFeature）。  
**删除方**: 面板 → daemon 删库 + 设备管理器 Remove → 设备侧 FeatureDB。  
**读取方**: 设备识别时按 feature_ids / user_name / 全库加载 blob。

### 2. 指纹设备 (FingerprintDevice)

类：`src/device/adaptor/fingerprint-device.{h,cpp}`，继承 `Device`。

| 属性 | 值/说明 |
|---|---|
| deviceType | DEVICE_TYPE_FINGERPRINT |
| 绑定 | 构造时 open(vid,pid)；失败则 manager 可不注册 |
| 状态机 | IDLE ⇄ DOING_ENROLL / DOING_IDENTIFY |
| 录入阶段 | NONE / DUPLICATE_CHECK / FORMAL |

状态转换：

- `EnrollStart` 且 IDLE → DOING_ENROLL；REPEATED/FAIL/COMPLETE/Stop → IDLE
- `IdentifyStart` 且 IDLE → DOING_IDENTIFY；MATCH/NOT_MATCH/错误/Stop → IDLE
- 非 IDLE → 拒绝「设备忙」
- Stop：置位 + `driver->cancel(handle)`，finished 时若 stop 则丢弃结果

### 3. 指纹驱动 (LibfprintDriver)

类：`plugins/driver/fingerprint/libfprint-fingerprint-driver.{h,cpp}`，继承 `FingerprintDriver`。

句柄内含：`FpContext`、`FpDevice`、`GCancellable`（每次操作可换新，避免沿用已 cancel 对象）。

抽象接口见 `include/driver-i.h`：`open/close/enroll/identify/cancel`。

## 请求/响应契约对象

### 录入请求 extraInfo（daemon → 设备）

```json
{ "feature_ids": ["<当前用户已有 md5...>", ...] }
```

- 非空：用于重复检测 gallery  
- 空：无已有特征，跳过查重直接正式录入

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

| feature_ids | 行为 |
|---|---|
| 非空 | 仅加载白名单 |
| 空 | 先 user_name 特征，再全库其余 |

### 状态回报

- 录入：`EnrollStatus(data, progress, result, message)`  
  - NORMAL/PASS/RETRY：过程提示  
  - REPEATED：重复  
  - FAIL：失败  
  - COMPLETE：100% + FeatureData JSON
- 识别：`IdentifyStatus(featureID, result, message)`  
  - RETRY：质量问题（过程中）  
  - MATCH：带 featureID  
  - NOT_MATCH：结束

## 校验规则（源自 spec FR）

| 规则 | 来源 |
|---|---|
| 录入前当前用户查重 | FR-010 |
| 不可切换仅白名单 | FR-011 |
| 可切换优先当前用户再全库 | FR-012 |
| 设备忙拒绝 | FR-007 |
| 停止丢弃结果 | FR-008 |
| 每账户 ≤10 | FR-014 |
| featureID=MD5(blob) | FR-016 |
