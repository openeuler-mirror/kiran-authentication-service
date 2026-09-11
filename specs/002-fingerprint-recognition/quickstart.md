# Quickstart: 本地指纹识别认证端到端验证

**Date**: 2026-09-01  
**前置阅读**: [contracts/fingerprint-device-contract.md](./contracts/fingerprint-device-contract.md)、[data-model.md](./data-model.md)

## 0. 前置条件

- 已安装 libfprint（或 libfprint-2）与受支持 USB 指纹仪
- 构建安装本仓库（含 `libkiran-fingerprint-libfprint.so`）
- 服务运行：`kiran-authentication-devices`、`kiran-authentication-daemon`
- 确认设备：`GetDevicesByType(DEVICE_TYPE_FINGERPRINT)` 能返回对象；或看 devices 日志中 FingerprintDevice open 成功

```bash
# 缺依赖时应跳过插件而非整仓失败
cmake -DBUILD_FINGERPRINT_DRIVER=ON ..   # 无 libfprint 时 WARNING skip
```

## 1. D-Bus / 服务侧抽查

### 1.1 录入

1. 控制面板或经 daemon `User.EnrollStart(KAD_AUTH_TYPE_FINGERPRINT, name, extraInfo)`
2. `dbus-monitor` 观察 `EnrollStatus`：查重提示 → 正式录入进度 → COMPLETE 或 REPEATED/FAIL
3. `GetIdentifications(fingerprint)` 可见新特征；重启 daemon 后仍在

### 1.2 识别（保持 D-Bus 连接）

```python
# 示意：对设备路径 IdentifyStart，监听 IdentifyStatus
# feature_ids 非空 = 仅该用户；空 + 由会话注入 user_name = 可切换语义
```

期望：本人 MATCH；错误手指 NOT_MATCH；IdentifyStop 后无迟到的成功。

## 2. 面板端到端（推荐主路径）

| # | 步骤 | 期望 |
|---|---|---|
| 1 | 插入支持的指纹仪，打开控制面板 → 身份认证 → 指纹 | 列表正常 |
| 2 | 点击录入 → 密码验证 | 进入录入页，提示按压 |
| 3 | 按提示完成多阶段按压 | 进度到 100%，特征入列表 |
| 4 | 同一手指再录一次 | 「该指纹已录入」 |
| 5 | 已有 10 个特征后再录 | 上限拒绝 |
| 6 | 重命名 / 删除 / 重启服务 | 名称保持；删除后不参与认证 |
| 7 | 录入中取消 | 无残留特征，可再录 |
| 8 | 锁屏选指纹，本人手指 | 解锁成功 |
| 9 | 锁屏选指纹，未登记手指 | 失败提示，可切密码 |
| 10 | 识别中切密码 | 无阻塞、无误报成功 |
| 11 | 可切换用户：输入用户 A，按仅属于 B 的手指 | 以 B 登录（SC-007） |
| 12 | 可切换：A/B 均有同一手指模板，输入 A 后按该手指 | 优先按 A 通过 |
| 13 | 断网重复关键步骤 | 仍可用 |

## 3. 成功标准对照

| SC | 验证方式 |
|---|---|
| SC-001 | 步骤 10 |
| SC-002 | 步骤 8 重复 20 次 |
| SC-003 | 步骤 9 交叉测试 |
| SC-004 | 步骤 2–3 重复 20 次 |
| SC-005 | 步骤 6 |
| SC-006 | 步骤 13 |
| SC-007 | 步骤 11–12 |

## 4. 已知限制

- 仅 libfprint 支持列表内设备
- 无独立活体/防伪层
- 匹配失败路径可能仍需等待抬指后设备收尾（成功路径已 early-cancel）
- PAM fail delay 可能导致「失败文案」与「重新认证按钮」之间体感空隙（属锁屏/PAM 层，非指纹算法本身）
