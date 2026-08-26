# Implementation Plan: 本地指纹识别认证

**Branch**: `002-fingerprint-recognition` | **Date**: 2026-09-01 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-fingerprint-recognition/spec.md`（as-built）

## Summary

为 kiran-authentication-service 增加基于 libfprint 的本地指纹认证：在设备管理服务侧实现 `FingerprintDriver`（libfprint 插件）与 `FingerprintDevice`；USB 热插拔装载；录入含当前用户重复检测 + 多阶段按压；识别按不可切换白名单 / 可切换「当前用户优先 + 全库兜底」组装模板列表；daemon 复用既有 FeatureDB 落库与 `matchUser`；控制面板复用既有指纹页。缺 libfprint 时 CMake 跳过插件。

## Technical Context

**Language/Version**: C++11，Qt5（QDBus / QtConcurrent / QFutureWatcher）

**Primary Dependencies**: libfprint-2（或 libfprint）、libgusb（链接 g_usb_device_get_vid/pid）、GLib/GObject（libfprint 异步 API）；Qt5 SQLite（FeatureDB）

**Storage**: 复用 FeatureDB；特征 blob = `fp_print_serialize` 字节；featureID = MD5(blob)

**Testing**: D-Bus / 控制面板手工验证 + 锁屏 PAM 联调（见 quickstart.md）

**Target Platform**: 国产化桌面 Linux（x86_64/ARM64），USB 指纹仪

**Project Type**: 设备管理服务 + 驱动插件(.so) + 既有面板指纹页

**Performance Goals**: 不阻塞 PAM；匹配成功 early-cancel；取消经 GCancellable 尽快返回

**Constraints**: 仅 libfprint 支持设备；离线可用；每账户 ≤10 特征；可切换匹配语义见 FR-011/FR-012

**Scale/Scope**: 本机按 VID/PID 实例化设备；单设备串行（忙拒绝）

## Constitution Check

对照既有原则：契约优先（contracts/）✓、本地优先（libfprint 本机采集）✓、安全边界文档化✓、驱动独立插件不破坏既有驱动✓、可观测（日志 + quickstart）✓ → **GATE 通过**。

## Project Structure

### Documentation (this feature)

```text
specs/002-fingerprint-recognition/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── fingerprint-device-contract.md
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
kiran-authentication-service/
├── include/driver-i.h                 # FingerprintDriver 抽象 + 状态/错误码
├── lib/                               # FeatureDB / FeatureData（复用）
├── plugins/driver/
│   ├── CMakeLists.txt                 # BUILD_FINGERPRINT_DRIVER + libfprint 探测后 add_subdirectory
│   └── fingerprint/                   # libkiran-fingerprint-libfprint.so
│       ├── libfprint-fingerprint-driver.{h,cpp}
│       ├── CMakeLists.txt
│       └── README.md
├── src/device/
│   ├── adaptor/fingerprint-device.{h,cpp}
│   ├── manager.cpp                    # DRIVER_TYPE_FINGERPRINT → FingerprintDevice
│   └── loader/driver-loader.cpp       # 加载指纹驱动类型
└── src/daemon/session.cpp             # feature_ids / user_name 注入；matchUser（既有）

kiran-control-panel/（既有，非本分支新建）
└── plugins/authentication/pages/finger-page.{h,cpp}
```

**Structure Decision**: 沿用 面板 → daemon → 设备管理服务 → 驱动插件。新增主要在设备侧与指纹插件；daemon 识别注入与落库逻辑复用，可切换语义依赖设备侧组装 gallery。

## Complexity Tracking

无 Constitution 违规。
