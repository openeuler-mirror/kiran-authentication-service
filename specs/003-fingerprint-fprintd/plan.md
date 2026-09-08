# Implementation Plan: 基于 fprintd 的本地指纹识别认证

**Branch**: `003-fingerprint-fprintd` | **Date**: 2026-09-04 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/003-fingerprint-fprintd/spec.md`

## Summary

用 **fprintd** 路径**替换**原进程内 libfprint 指纹**实现**：删除 `plugins/driver/fingerprint/`；新增 `FprintdFingerprintDriver`（D-Bus 客户端插件）并适配 `FingerprintDevice`；通过 `net.reactivated.Fprint.Manager/Device` 完成枚举、Claim/Release、Enroll/Verify、List/Delete；生物模板存 fprintd，FeatureDB 存映射元数据；daemon 与控制面板复用既有指纹页与 PAM 链路。缺依赖时 CMake 跳过插件。运行时仅保留 fprintd 指纹后端；`specs/002-fingerprint-recognition/` 规格文档保留不删。

## Technical Context

**Language/Version**: C++11，Qt5（QDBus / QtConcurrent / QFutureWatcher）

**Primary Dependencies**: fprintd（系统 D-Bus 服务）、Qt5 DBus；**不**链接 libfprint.so；开发验证用 `fprintd-*` CLI

**Storage**:
- 生物模板：fprintd（由守护进程管理）
- 元数据：复用 FeatureDB；featureID = 稳定映射键（user + finger_name）；feature blob 为空或占位
- 旧 libfprint blob 记录：不迁移，清理或提示重录（FR-018）

**Testing**: D-Bus / 控制面板 + `fprintd-*` CLI 对照 + 锁屏 PAM 联调（见 quickstart.md）

**Target Platform**: 国产化桌面 Linux（x86_64/ARM64），USB 指纹仪 + 发行版 fprintd

**Project Type**: 设备管理服务 + 唯一指纹驱动插件(.so) + 既有面板指纹页

**Performance Goals**: 不阻塞 PAM；停止/取消时尽快 EnrollStop/VerifyStop + Release

**Constraints**: 仅 fprintd 支持设备；离线可用；每账户 ≤10 特征；需处理 Polkit；无第二指纹后端

**Scale/Scope**: 本机按 fprintd 设备对象实例化；单设备串行（忙拒绝）

## Constitution Check

对照既有原则：契约优先（contracts/）✓、本地优先（fprintd 本机采集）✓、安全边界文档化（Polkit/Claim）✓、单一指纹插件✓、可观测（日志 + CLI quickstart）✓ → **GATE 通过**（规划态）。

## Project Structure

### Documentation (this feature)

```text
specs/003-fingerprint-fprintd/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── fingerprint-fprintd-contract.md
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code (拟议)

```text
kiran-authentication-service/
├── include/driver-i.h                 # 复用 FingerprintDriver 抽象；必要时扩展错误码
├── lib/                               # FeatureDB / FeatureData（复用，blob 可空）
├── plugins/driver/
│   ├── CMakeLists.txt                 # BUILD_FINGERPRINT_DRIVER → fingerprint-fprintd；移除 libfprint 子目录
│   └── fingerprint-fprintd/           # libkiran-fingerprint-fprintd.so（拟）
│       ├── fprintd-fingerprint-driver.{h,cpp}
│       ├── CMakeLists.txt
│       └── README.md
├── src/device/
│   ├── adaptor/fingerprint-device.{h,cpp}  # fprintd Enroll/Verify/映射
│   ├── manager.cpp
│   └── loader/driver-loader.cpp
└── src/daemon/session.cpp                  # feature_ids / user_name；matchUser（既有）

移除（实现代码，规格 002 目录保留）:
└── plugins/driver/fingerprint/             # 原 libfprint 直连插件

kiran-control-panel/（既有）
└── plugins/authentication/pages/finger-page.{h,cpp}
```

**Structure Decision**: 面板 → daemon → 设备管理服务 → **唯一** fprintd 指纹插件。

## Complexity Tracking

| 风险 | 缓解 |
|---|---|
| fprintd 无跨用户 Identify 或发行版 API 不一致 | research 锁定 Verify 优先 + 受限多用户策略 |
| FeatureDB 与 fprintd 双源 | FR-021 同步/自愈；删除双写 |
| Polkit 阻断系统服务 | 配套 rules 草案；失败可观测 |
| 旧 blob 特征残留 | FR-018 清理/重录，不做跨引擎迁移 |

无 Constitution 违规。
