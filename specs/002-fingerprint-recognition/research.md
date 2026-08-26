# Phase 0 Research: 本地指纹识别认证

**Date**: 2026-09-01（as-built）

## D1 算法/采集引擎：libfprint

- **Decision**: 使用系统 libfprint（优先 `libfprint-2.pc`），经 GObject 异步 API `fp_device_enroll` / `fp_device_identify` 完成采集与比对；完成回调投递到全局默认 GMainContext，由设备管理进程 Qt 主循环（QEventDispatcherGlib）驱动。
- **Rationale**: 覆盖 Goodix/Elan/Synaptics 等常见 USB 指纹仪；避免自研传感器协议。
- **Alternatives considered**: 厂商私有 SDK（如 ZKTeco）——不在 libfprint 支持列表，需独立插件，不在本期范围。

## D2 命名与类型

- **Decision**: `FingerprintDriver`（`DRIVER_TYPE_FINGERPRINT`）+ `FingerprintDevice`（`DEVICE_TYPE_FINGERPRINT`），对应 `KAD_AUTH_TYPE_FINGERPRINT`。插件名 `kiran-fingerprint-libfprint`。
- **Rationale**: 与既有枚举及面板指纹页一致。

## D3 设备装载：USB VID/PID + 热插拔

- **Decision**: `getSupportVidPid()` 优先解析 libfprint 安装的 `60-autosuspend-libfprint*.hwdb`；缺失则枚举当前已连接设备。`Manager::genDevice` 在 udev 匹配到指纹驱动类型时创建 `FingerprintDevice` 并 `open(vid,pid)`；打开失败则跳过注册。
- **Rationale**: 指纹仪是真实 USB 设备，与本地人脸「无 vid/pid 启动装载」路径不同。
- **Note**: 热插时 libusb/libfprint 枚举可能滞后于 udev；`open` 内短重试（约数秒内）降低失败率。

## D4 录入契约：设备侧多阶段按压 + 当前用户查重

- **Decision**:
  1. daemon/面板既有 `EnrollStart`；daemon 将当前用户 `feature_ids` 写入 extraInfo。
  2. `FingerprintDevice::doEnrollStart`：若已有特征非空 → 先 `identify` 查重（无 statusCb，避免 early-cancel 干扰）；命中 → `ENROLL_STATUS_REPEATED`；否则进入正式 `enroll`。
  3. 正式录入通过 progressCb 上报 PASS/RETRY/NORMAL；成功后特征 blob + featureID=MD5 → `EnrollStatus(COMPLETE, FeatureData JSON)`；daemon 既有逻辑落库。
- **Rationale**: 对齐 fprintd「录入前查重」习惯；查重限当前用户，避免全库误判「已录入」。
- **Alternatives considered**: 仅靠 featureID 碰撞查重——无法覆盖「同一手指不同次采集特征字节不同」的情况，必须现场再扫一次比对。

## D5 识别契约：白名单 vs 优先+全库

- **Decision**:
  - 不可切换：`Session::startGeneralAuth` 注入该用户 `feature_ids`；设备只加载这些模板。
  - 可切换：`feature_ids` 为空 + `user_name`；设备先加载该用户特征，再 `GetFeatureIDList()` 追加全库；命中 ID 经 `matchUser` 决定登录用户。
- **Rationale**: 不可切换必须防误命中他人；可切换需支持「输入 A、按 B 的手指登录 B」。
- **Bug fixed (as-built)**: 曾把「空 feature_ids + user_name」误做成只加载该用户、不再全库；已改为优先+兜底。

## D6 匹配成功 early-cancel

- **Decision**: 登录识别（有 identifyCb）在 match_cb 命中后 `g_cancellable_cancel`，尽快结束，避免图像类设备卡在 AWAIT_FINGER_OFF。录入前查重（identifyCb 为空）不 early-cancel，以免设备未 idle 导致后续 enroll 异常。
- **Rationale**: 实测抬指等待会明显拖慢成功路径；查重与正式录入衔接对 idle 更敏感。

## D7 特征存储

- **Decision**: blob = libfprint `fp_print_serialize`；featureID = MD5(blob)；复用 FeatureDB，不改表结构。
- **Rationale**: 与人脸/其它生物特征落库路径一致。

## D8 线程与主循环

- **Decision**: enroll/identify 在 `QtConcurrent` 工作线程阻塞等待；异步完成回调在 Qt 主线程；中间状态经 `QMetaObject::invokeMethod(..., QueuedConnection)` 回设备对象发 D-Bus 信号。析构时限时等待 worker，避免与主循环互相死锁。
- **Rationale**: 不可在工作线程迭代与 Qt 共享的 GMainContext。

## D9 构建可选依赖

- **Decision**: `plugins/driver/CMakeLists.txt` 中 `option(BUILD_FINGERPRINT_DRIVER ON)`；`pkg_search_module` 查找 libfprint-2/libfprint，找不到则 WARNING 并跳过。
- **Rationale**: 与人脸驱动缺 ncnn/opencv 时跳过同一策略，保证无指纹开发环境仍能编过核心组件。

## D10 面板范围

- **Decision**: 复用 `kiran-control-panel` `finger-page`：进度 SVG（0/25/50/75/100）+ EnrollStatus 文案；不引入摄像头预览。
- **Rationale**: 指纹交互在采集器上完成，与人脸「面板采图」不同。

## D11 每用户上限

- **Decision**: daemon `FEATURE_COUNT_MAXIMUN = 10`，零改动。
- **Rationale**: 与人脸等一致。
