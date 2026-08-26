# Phase 0 Research: 基于 fprintd 的本地指纹识别认证

**Date**: 2026-09-04（规划）

## D1 算法/采集引擎：fprintd（替换进程内 libfprint）

- **Decision**: 不链接 `libfprint.so`；通过系统总线访问 `net.reactivated.Fprint`（Manager + Device）。底层仍由 fprintd 进程加载 libfprint。原进程内 libfprint **插件代码**删除；`specs/002-fingerprint-recognition/` 保留作 as-built 对照。
- **Rationale**: 与发行版指纹栈统一；隔离 GObject/GMainContext 与传感器 ABI；可用官方工具排障；单一实现降低维护成本。
- **Alternatives considered**:
  - 继续维护进程内 libfprint —— 否决（本需求明确用 fprintd 替换实现代码）。
  - 生产路径 `QProcess` 调 `fprintd-enroll` —— 解析脆弱、权限与生命周期难控，仅允许作排障文档。

## D2 命名与类型

- **Decision**: 仍使用 `FingerprintDriver` / `DEVICE_TYPE_FINGERPRINT` / `KAD_AUTH_TYPE_FINGERPRINT`。插件名 `kiran-fingerprint-fprintd`。CMake 选项沿用或收敛为 `BUILD_FINGERPRINT_DRIVER`（指向本插件）。
- **Rationale**: 面板与 PAM 少改；对外类型不变。

## D3 设备装载：fprintd 枚举 + 热插拔协同

- **Decision**: 启动与设备变化时调用 `Manager.GetDevices` / `GetDefaultDevice`；对象路径变化时创建/销毁 `FingerprintDevice`。USB udev 事件可作为触发器，**以 fprintd 枚举结果为准**。
- **Rationale**: 硬件所有权在 fprintd；KAS 不再对设备 `fp_device_open`。
- **Note**: 无设备时不暴露可用指纹设备。

## D4 录入契约：Claim → EnrollStart → 映射落库

- **Decision**:
  1. daemon/面板既有 `EnrollStart`；daemon 注入 `user_name`（指纹不再注入 `feature_ids`；人脸等仍可注入）。
  2. 设备：`Claim(user_name)` → 选择空闲 `finger_name` → `EnrollStart(finger)`；监听 `EnrollStatus`。
  3. `enroll-duplicate` → `ENROLL_STATUS_REPEATED`（一指一用户，含跨用户）；其余阶段映射 PASS/RETRY/COMPLETE。
  4. COMPLETE：FeatureDB 写入元数据（featureID=稳定键，finger_name）；**不**写入 libfprint serialize blob。
- **Rationale**: 查重交给 fprintd；模板权威源在 fprintd。

## D5 识别契约：白名单用户 Verify vs 可切换扩展

- **Decision**:
  - 不可切换：`Claim(user_name)` + `VerifyStart("any")`。
  - 可切换：先对输入 `user_name` Verify；失败则对其余「FeatureDB 中有指纹映射的用户」依次尝试（短超时/可取消），命中即停止；由 daemon `matchUser` 定登录用户。
- **Rationale**: 现代 fprintd 以 per-user Verify 为主；逐用户 Verify 可落地。
- **Risk**: 用户很多时延迟上升——限制为「本机有指纹映射的用户」集合，并优先当前输入用户。
- **Open point**: 若目标发行版 fprintd 提供稳定 Identify API，优先改用 Identify。

## D6 停止与 Claim 生命周期

- **Decision**: Stop → `EnrollStop`/`VerifyStop` → `Release`；析构/异常路径同样保证 Release。`AlreadyInUse` → 「设备忙」。
- **Rationale**: 未 Release 会导致后续 CLI 与 KAS 全部失败（SC-009）。

## D7 特征存储与 featureID

- **Decision**: featureID = `MD5("fprintd:" + userName + ":" + finger_name)`；FeatureData.feature 可空；列表/删除以 finger_name 为 fprintd 句柄。
- **Sync**: `ListEnrolledFingers(user)` 与 FeatureDB 比对并收敛（FR-021）。
- **Migration**: 旧 serialize-blob 指纹记录不自动迁移；启动或升级路径清理无效记录并提示重录（FR-018）。

## D8 线程与主循环

- **Decision**: QDBus 异步调用 + 信号槽；fprintd 在 **系统总线**。
- **Rationale**: 无需引入 GObject 主循环纠缠。

## D9 构建

- **Decision**: 仅构建 fprintd 指纹插件；删除对 libfprint-2 pkg-config 的指纹插件探测与子目录。缺 QtDBus 则 WARNING 跳过。
- **Rationale**: 单一后端，无运行时后端选择项。

## D10 面板范围

- **Decision**: 复用 `finger-page`；fprintd EnrollStatus 字符串映射到既有 NORMAL/PASS/RETRY/COMPLETE。
- **Rationale**: UX 不变。

## D11 每用户上限与 finger 槽位

- **Decision**: daemon 上限 10；分配 finger_name 时跳过已占用槽；无空闲槽则失败提示。

## D12 Polkit

- **Decision**: 文档化 `device.enroll` / `device.verify` / `device.setusername`；必要时提供 rules 草案。

## D13 相对旧实现的变更摘要（对照 specs/002，实现已移除）

| 项 | 旧 libfprint 直连（代码删除，规格保留） | 本方案 fprintd |
|---|---|---|
| 链接 libfprint.so | 是 | 否 |
| 模板存储 | FeatureDB blob | fprintd + FeatureDB 映射 |
| featureID | MD5(blob) | MD5(user+finger) |
| 打开设备 | 驱动 open(vid,pid) | Claim(username) |
| 排障工具 | 无 | fprintd-* |
| 主循环 | GObject + Qt | QtDBus |
| 交付状态 | 规格 as-built 归档 | 唯一运行时路径 |
