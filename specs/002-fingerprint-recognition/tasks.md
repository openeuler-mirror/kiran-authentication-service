# Tasks: 本地指纹识别认证

**Input**: Design documents from `/specs/002-fingerprint-recognition/`

**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, data-model.md ✅, contracts/ ✅, quickstart.md ✅

**Tests**: 规格未要求 TDD；按 quickstart.md 做功能验证。

**Organization**: as-built 任务清单——反映已落地实现，供 spec-kit 追溯与后续增量勾选。

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 驱动插件目录与 CMake：`plugins/driver/fingerprint/`，链接 libfprint-2/libfprint + libgusb，安装到 `KAS_AUTH_DRIVERSDIR`
- [X] T002 [P] 父级 `plugins/driver/CMakeLists.txt`：`BUILD_FINGERPRINT_DRIVER`，缺 libfprint 时 WARNING 跳过（对齐人脸）
- [X] T003 [P] 确认 daemon 路由：`KAD_AUTH_TYPE_FINGERPRINT` → `DEVICE_TYPE_FINGERPRINT`，FeatureDB 落库与 `FEATURE_COUNT_MAXIMUN=10` 可复用

---

## Phase 2: Foundational

- [X] T004 `include/driver-i.h`：`FingerprintDriver` 抽象、`FingerprintEnrollStatus` / `FingerprintIdentifyStatus` / `FingerprintDriverError`
- [X] T005 实现 `LibfprintDriver`：hwdb/枚举 VID/PID、`open/close`、异步 enroll/identify + GCancellable、`cancel`、serialize/deserialize、匹配 early-cancel（仅登录识别）
- [X] T006 `driver-loader` 识别 `DRIVER_TYPE_FINGERPRINT`；`Manager::genDevice` 创建 `FingerprintDevice`

**Checkpoint**: 插入支持设备后 devices 进程可 open 并暴露 D-Bus 设备对象

---

## Phase 3: User Story 1 - 控制面板指纹录入 (P1)

- [X] T007 [US1] `FingerprintDevice::doEnrollStart`：忙/未打开拒绝；当前用户 feature_ids 查重 identify；命中 REPEATED
- [X] T008 [US1] 正式 enroll 工作线程 + 中间态 Queued 回报；COMPLETE 组装 FeatureData（MD5 + vid/pid）
- [X] T009 [US1] `EnrollStop`：cancel + 丢弃结果
- [X] T010 [US1] 面板 `finger-page` 联调：进度图与 EnrollStatus 文案（既有页面）

**Checkpoint**: 面板可完成录入 / 重复拒绝 / 取消

---

## Phase 4: User Story 2 - 登录/锁屏识别 (P1)

- [X] T011 [US2] `doIdentifyStart`：解析 feature_ids / user_name；非空仅白名单；空则优先 user + 全库
- [X] T012 [US2] identify 工作线程；RETRY 中间态；MATCH/NOT_MATCH 结束；Stop 丢弃
- [X] T013 [US2] PAM/锁屏联调：本人通过、错误拒绝、切换认证无阻塞
- [X] T014 [US2] 可切换用户：输入 A 按 B 的手指登录 B；A/B 同指优先 A（修复「空 feature_ids 只加载当前用户」回归）

**Checkpoint**: 锁屏指纹认证与切换用户语义达标

---

## Phase 5: User Story 3 - 特征管理 (P2)

- [X] T015 [US3] 复用 GetIdentifications / Rename / Delete 双写删除链路验证

---

## Phase 6: Polish

- [X] T016 插件 README（支持设备、编译、实现说明）
- [X] T017 翻译资源：录入/识别提示中英文（devices 翻译）
- [X] T018 本 spec 目录 as-built 文档齐套（spec/plan/research/data-model/contracts/quickstart/tasks）

## Dependencies

```text
T001–T003 → T004–T006 → T007–T010 (US1)
                    ↘→ T011–T014 (US2)
T015 可与 US1 后并行验证
```

## Implementation Strategy

已实现主线：驱动插件 → 设备适配器 → 面板/锁屏联调。后续增量以本 tasks 为基线开子任务（例如更多传感器适配、fail-delay 与 UI 时序优化属 session-guard/PAM，不单列为本功能阻塞项）。
