# Tasks: 基于 fprintd 的本地指纹识别认证

**Input**: Design documents from `/specs/003-fingerprint-fprintd/`

**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, data-model.md ✅, contracts/ ✅, quickstart.md ✅

**Tests**: 规格未要求 TDD；按 quickstart.md 做功能验证（含 fprintd CLI 对照）。

**Organization**: 规划态任务清单——实现时按 Phase 勾选。本功能**替换**旧 libfprint 直连，不保留双后端。

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup / 移除旧实现

- [X] T001 删除 `plugins/driver/fingerprint/`（libfprint 直连**代码**）及父级 CMake 对其的 `pkg_search_module(libfprint…)` / `add_subdirectory`；**保留** `specs/002-fingerprint-recognition/`
- [X] T002 新建 `plugins/driver/fingerprint-fprintd/`：链接 Qt5DBus，安装到 `KAS_AUTH_DRIVERSDIR`；`BUILD_FINGERPRINT_DRIVER` 指向本目录
- [X] T003 [P] 确认 daemon：映射串可落库；`FEATURE_COUNT_MAXIMUN=10`；`matchUser` 可复用；录入 extraInfo 注入 `user_name`
- [X] T004 [P] 升级/启动路径：`cleanupLegacyFingerprintFeatures` 清理旧 serialize-blob（FR-018）

---

## Phase 2: Foundational

- [X] T005 `FprintdFingerprintDriver`：Manager 枚举、Claim/Release、错误码映射（含 Polkit/服务不可用）
- [X] T006 实现 EnrollStart/Stop + EnrollStatus → 驱动进度/结果回调
- [X] T007 实现 VerifyStart/Stop + VerifyStatus → MATCH/NOT_MATCH/RETRY
- [X] T008 ListEnrolledFingers / DeleteEnrolledFinger；finger_name 分配与 featureID 稳定映射
- [X] T009 适配 `FingerprintDevice` / `driver-loader` / `Manager::genLocalDevices`：fprintd 本地驱动装载；去掉 libfprint open(vid,pid) 热路径

**Checkpoint**: `fprintd` 运行且有设备时，devices 进程可暴露指纹设备；Claim/Release 无泄漏；旧插件已不在构建产物中

---

## Phase 3: User Story 1 - 控制面板指纹录入 (P1)

- [X] T010 [US1] `doEnrollStart`：忙/无设备/未授权拒绝；正式 Enroll；fprintd enroll-duplicate → REPEATED
- [X] T011 [US1] 正式 Enroll；进度映射；COMPLETE 写 FeatureData 元数据（fprintd 映射串）
- [X] T012 [US1] `EnrollStop`：Stop + Release + 丢弃结果；无半成品映射
- [ ] T013 [US1] 面板 `finger-page` 联调（需真机/手工）

**Checkpoint**: 面板可完成录入 / 重复拒绝 / 取消；`fprintd-list` 可见对应 finger

---

## Phase 4: User Story 2 - 登录/锁屏识别 (P1)

- [X] T014 [US2] `doIdentifyStart`：不可切换 → Claim(user) + Verify("any")；映射 featureID
- [X] T015 [US2] 可切换：优先当前用户，再扩展有映射用户；命中后 matchUser
- [X] T016 [US2] IdentifyStop 丢弃 + Release
- [ ] T017 [US2] PAM/锁屏联调：本人通过、错误拒绝、切换认证无阻塞、可切换登录（需真机/手工）

**Checkpoint**: 锁屏指纹认证达标；与 `fprintd-verify` 结论一致（SC-008）

---

## Phase 5: User Story 3 - 特征管理 (P2)

- [X] T018 [US3] 列表/重命名/删除双写（FeatureDB + fprintd DeleteEnrolledFinger）
- [X] T019 [US3] FeatureDB ↔ fprintd 不一致时的收敛（`syncWithFprintd`）

---

## Phase 6: User Story 4 - CLI 排障文档 (P3)

- [X] T020 [US4] quickstart：发行版安装、polkit、fprintd-* 对照、升级后重录说明（已有）
- [X] T021 [US4] 插件 README：架构、支持前提、与旧直连差异

---

## Phase 7: Polish

- [X] T022 Polkit rules 草案（`data/polkit/50-kiran-authentication-fprintd.rules`）
- [X] T023 翻译资源：服务不可用/权限不足等文案
- [ ] T024 关闭 research D5 Identify open point（按目标发行版实测）
- [ ] T025 全套 spec 对照实现回写（as-built）；确认仓库无 libfprint 指纹插件残留引用

## Dependencies

```text
T001–T004 → T005–T009 → T010–T013 (US1)
                     ↘→ T014–T017 (US2)
T018–T019 可与 US1 后并行
T020–T025 收尾
```

## Implementation Strategy

先删旧插件并接通 fprintd D-Bus，再面板录入，最后锁屏与可切换用户。全程用 `fprintd-*` 对照硬件基线。
