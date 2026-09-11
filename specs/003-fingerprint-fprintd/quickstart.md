# Quickstart: 基于 fprintd 的指纹认证端到端验证

**Date**: 2026-09-04  
**前置阅读**: [contracts/fingerprint-fprintd-contract.md](./contracts/fingerprint-fprintd-contract.md)、[data-model.md](./data-model.md)

## 0. 前置条件

- 已安装并启用 **fprintd**（及发行版匹配的 libfprint）
- USB 指纹仪可被 fprintd 枚举
- 构建安装本仓库（含 `libkiran-fingerprint-fprintd.so`）；**不应再存在** `libkiran-fingerprint-libfprint.so`
- 若从旧版本升级：旧 FeatureDB 指纹 blob **需重新录入**（见步骤 0.1）
- 服务运行：`kiran-authentication-devices`、`kiran-authentication-daemon`

```bash
systemctl status fprintd
fprintd-list "$USER"
cmake -DBUILD_FINGERPRINT_DRIVER=ON ..   # 指向 fprintd 插件；无 QtDBus 时 WARNING skip
```

### 0.1 升级清理（FR-018）

- 面板指纹列表若出现无法认证的旧条目：删除后重新录入
- 或按实现提供的启动清理逻辑，确认仅保留 fprintd 映射类特征

## 1. 开源工具基线（先于 KAS）

| # | 命令 | 期望 |
|---|---|---|
| 1 | `fprintd-enroll` | 多阶段按压后录入成功 |
| 2 | `fprintd-verify` | 本人 match，他人 no-match |
| 3 | `fprintd-list <user>` | 列出已录 finger |
| 4 | `fprintd-delete`（按发行版用法） | 删除后 list 为空 |

若本步失败：先修 fprintd/Polkit/硬件，再查 KAS。

## 2. D-Bus / 服务侧抽查

### 2.1 录入

1. 控制面板或经 daemon `User.EnrollStart(KAD_AUTH_TYPE_FINGERPRINT, name, extraInfo)`
2. `dbus-monitor --system` 观察 `net.reactivated.Fprint.Device` 的 EnrollStatus
3. 同时观察 KAS `EnrollStatus`：按压提示 → 进度 → COMPLETE 或 REPEATED/FAIL
4. `GetIdentifications(fingerprint)` 可见新特征；`fprintd-list` 可见对应 finger

### 2.2 识别

对设备路径 `IdentifyStart`，监听 `IdentifyStatus`：本人 MATCH；错误手指 NOT_MATCH；`IdentifyStop` 后无迟到成功；异常后仍可再次 Claim（SC-009）。

## 3. 面板端到端（推荐主路径）

| # | 步骤 | 期望 |
|---|---|---|
| 1 | 插入支持的指纹仪，打开控制面板 → 身份认证 → 指纹 | 列表正常 |
| 2 | 点击录入 → 密码验证 | 进入录入页，提示按压 |
| 3 | 按提示完成多阶段按压 | 进度到 100%，特征入列表；CLI list 一致 |
| 4 | 同一手指再录一次 | 「该指纹已录入」 |
| 5 | 已有 10 个特征后再录 | 上限拒绝 |
| 6 | 重命名 / 删除 / 重启服务 | 名称保持；删除后 DB 与 fprintd 均无 |
| 7 | 录入中取消 | 无残留映射，可再录 |
| 8 | 锁屏选指纹，本人手指 | 解锁成功 |
| 9 | 锁屏选指纹，未登记手指 | 失败提示，可切密码 |
| 10 | 识别中切密码 | 无阻塞、无误报成功 |
| 11 | 可切换用户：输入用户 A，按仅属于 B 的手指 | 以 B 登录（SC-007） |
| 12 | 可切换：A/B 均有同一手指模板，输入 A 后按该手指 | 优先按 A 通过 |
| 13 | 断网重复关键步骤 | 仍可用 |
| 14 | 用 CLI 删除某 finger 后打开面板 | 收敛孤儿映射（FR-021） |

## 4. 成功标准对照

| SC | 验证方式 |
|---|---|
| SC-001 | 步骤 10 |
| SC-002 | 步骤 8 重复 20 次 |
| SC-003 | 步骤 9 交叉测试 |
| SC-004 | 步骤 2–3 重复 20 次 |
| SC-005 | 步骤 6 |
| SC-006 | 步骤 13 |
| SC-007 | 步骤 11–12 |
| SC-008 | 第 1 节 CLI vs 步骤 8 |
| SC-009 | 录入/识别中杀 devices 进程后恢复再测 |

## 5. 已知限制

- 仅 fprintd/libfprint 支持列表内设备
- 无独立活体/防伪层
- 可切换用户若走逐用户 Verify，用户多时延迟可能升高
- 旧 libfprint blob 特征不迁移，须重录
- Polkit 未配置时可能 PermissionDenied
- 生产路径禁止 shell 调用 fprintd CLI
