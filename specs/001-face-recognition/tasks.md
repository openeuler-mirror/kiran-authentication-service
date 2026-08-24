# Tasks: 本地人脸识别认证

**Input**: Design documents from `/specs/001-face-recognition/`

**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, data-model.md ✅, contracts/ ✅, quickstart.md ✅

**Tests**: 规格未要求 TDD;按 quickstart.md 的验证场景做功能验证(算法基准工具除外)。

**Organization**: 任务按用户故事分组,可独立实现与验证。⚠️ 含跨仓库任务(kiran-control-panel),已标注。

## Format: `[ID] [P?] [Story] Description`

- **[P]**: 可并行(不同文件,无依赖)
- **[Story]**: 所属用户故事(US1/US2/US3)
- 描述含精确文件路径

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: 模型落位、依赖接入、驱动插件骨架

- [X] T001 将 ncnn 模型接入构建:/mnt/1t/y/opencv/backport_452/ncnn_models/{yunet.param,yunet.bin,sface.param,sface.bin} 复制到本仓库 data/models/face/,并在 /mnt/1t/y/kiran-authentication-service/CMakeLists.txt 与 src/device/CMakeLists.txt 增加安装规则(安装至 KAS_INSTALL_DATADIR/models/face/)
- [X] T002 [P] 创建驱动插件目录骨架:/mnt/1t/y/kiran-authentication-service/plugins/driver/face/CMakeLists.txt,链接 ncnn(pkg-config)与 OpenCV(core/imgproc/imgcodecs/dnn),输出 face-driver.so 插件并安装
- [X] T003 [P] 确认 daemon 路由可用性:核对 /mnt/1t/y/kiran-authentication-service/lib/utils.cpp `authType2DeviceType(KAD_AUTH_TYPE_FACE)→DEVICE_TYPE_FACE` 与 daemon FeatureDB 落库逻辑(user.cpp),记录零改动结论到交付说明

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: 驱动接口抽象与 ncnn 算法封装——所有用户故事的地基

**⚠️ CRITICAL**: 本阶段完成前,任何用户故事不能开始

- [X] T004 在 /mnt/1t/y/kiran-authentication-service/include/driver-i.h 新增 FaceDriver 抽象基类(DRIVER_TYPE_FACE):`int identify(const std::string &extraInfo)`、`int enroll(const std::string &extraInfo)`、`void identifyResultPostProcess(const std::string &extraInfo)`,并定义人脸错误码段(摄像头 1xx/算法 2xx/录入 3xx)
- [X] T005 [P] 实现 ncnn YuNet 封装 /mnt/1t/y/kiran-authentication-service/plugins/driver/face/yunet-ncnn.{h,cpp}:从 /mnt/1t/y/opencv/backport_452/ncnn_test.cpp 提取 YunetNcnn 类(setInputSize/detect,输出 N×15 CV_32F,含 NMS),模型路径参数化
- [X] T006 [P] 实现 ncnn SFace 封装 /mnt/1t/y/kiran-authentication-service/plugins/driver/face/sface-ncnn.{h,cpp}:提取 SfaceNcnn 类(alignCrop 5 点对齐 112×112、feature 128 维、match 余弦相似度),模型路径参数化
- [X] T007 实现 FaceDriver 骨架 /mnt/1t/y/kiran-authentication-service/plugins/driver/face/face-driver.{h,cpp}:Driver 接口(getDriverName/getErrorMsg/getType=DRIVER_TYPE_FACE/getSupportedAuthTypes)、导出 `extern "C" Driver* createDriver()`、错误码→文案映射(中英文);以 include/driver-i.h 接口与 src/device/loader/driver-loader.cpp 的 createDriver 约定为准,结构参考旧仓库 /mnt/1t/y/kiran-authentication-devices/src/driver/ 的驱动实现
- [X] T008 [P] 实现算法基准验证工具 /mnt/1t/y/kiran-authentication-service/plugins/driver/face/face-algo-benchmark.cpp(独立可执行):加载 yunet/sface 模型跑参考图集,校验 135 张脸、同人 ≈0.885、异人 ≈0.179(quickstart 1.1)

**Checkpoint**: 地基就绪——ncnn 检测/特征/比对可用且基准达标,用户故事可以开始

---

## Phase 3: User Story 1 - 控制面板人脸录入 (Priority: P1) 🎯 MVP

**Goal**: 面板预览 → 拍照传图 → 服务端检测/提取/保存 → 进度反馈 → 特征入列表

**Independent Test**: 控制面板人脸页点录入 → 预览出现 → 拍照 → 进度到 100% → 特征出现在列表;失败/取消场景按 spec US1 验收场景 1-6 验证

### Implementation for User Story 1

- [X] T009 [US1] 实现 FaceDriver::enroll 在 /mnt/1t/y/kiran-authentication-service/plugins/driver/face/face-driver.cpp:解析 extraInfo JSON 的 faceImage(base64)→JPEG 解码→YuNet 检测(无脸或质量不达标→错误"未检测到人脸",多脸取面积最大的一张)→对齐+特征提取→featureID=MD5(特征字节)→查重(FeatureDB 已存在→"该特征已录入")→返回特征数据。质量门限:检测置信度阈值沿用参考实现 0.6,人脸框最小尺寸按图像短边比例定义(实现阶段标定,不达标视为无合格人脸)
- [X] T010 [US1] 创建 FaceDevice 在 /mnt/1t/y/kiran-authentication-service/src/device/adaptor/face-device.{h,cpp}:继承 Device,deviceType()=DEVICE_TYPE_FACE;doEnrollStart 解析 extraInfo→QtConcurrent 线程执行 driver enroll→按 contracts/face-device-contract.md 2.2 表回报 EnrollStatus(处理中 progress 递增/FAIL 带原因/COMPLETE 100%+data=FeatureData JSON);EnrollStop 标记停止并丢弃结果;设备忙拒绝语义(FR-007)
- [X] T011 [US1] 在 /mnt/1t/y/kiran-authentication-service/src/device/manager.cpp 增加本地人脸设备启动装载:扫描插件中 DRIVER_TYPE_FACE 且 getSupportVidPid() 为空的驱动,启动期创建 FaceDevice 并加入 m_devices(参照 genSoftDevices 模式,research D3)
- [X] T012 [US1] 验证设备管理器 D-Bus 暴露:确认 GetDevicesByType(DEVICE_TYPE_FACE) 能返回新设备(检查 /mnt/1t/y/kiran-authentication-service/src/device 的 D-Bus 注册与 manager 查询逻辑,必要时补注册);用 dbus-send 模拟面板 EnrollStart 带 base64 图像,验证 EnrollStatus 信号与 daemon FeatureDB 落库(quickstart 1.2)
- [X] T013 [P] [US1] 面板录入页预览(跨仓库 /mnt/1t/y/kiran-control-panel):face-page.cpp 录入页用 QCamera/QCameraViewfinder 替换原 272×272 静态进度图区域,切入录入页即开预览,新增"拍照/录入"按钮;取消/关页关闭摄像头
- [X] T014 [US1] 面板拍照传图与结果处理(跨仓库 /mnt/1t/y/kiran-control-panel):face-page.cpp 拍照按钮捕获当前帧→JPEG→base64→组装 extraInfo {"faceImage":...}→调用 kiran-auth-dbus-proxy.cpp startEnroll(KAD_AUTH_TYPE_FACE, featureName, extraInfo)(时序改为:进页只预览,拍照时才建会话);EnrollStatus 驱动进度与弹窗(finishEnroll 现有逻辑);2 分钟无操作自动关预览回管理页(FR-016/FR-017)

**Checkpoint**: US1 可独立演示——面板录入闭环打通(quickstart 步骤 1-9)

---

## Phase 4: User Story 2 - 登录/锁屏人脸识别认证 (Priority: P1)

**Goal**: PAM 场景摄像头自采识别,仅与目标用户特征比对;匹配通过、不匹配结束、10 秒超时

**Independent Test**: 锁屏选人脸认证:本人通过、他人拒绝并提示、切换密码无阻塞(quickstart 步骤 10-12)

### Implementation for User Story 2

- [X] T015 [US2] 实现 FaceDriver::identify 在 /mnt/1t/y/kiran-authentication-service/plugins/driver/face/face-driver.cpp:cv::VideoCapture(0) 打开默认摄像头(V4L2);采集循环:YuNet 检测→无脸/质量不达标→RETRY 提示继续(质量门限与 T009 一致,实现阶段标定)→多脸取面积最大的一张(FR-014 修正)→提取特征→按 extraInfo.feature_ids 从 FeatureDB 读特征 blob(为空则全库兜底)→逐一余弦比对→≥阈值→返回命中 featureID;不匹配→结束;默认 10 秒超时→"识别超时";支持停止标记(QRunnable/QAtomicInt 或复用现有 QtConcurrent+停止标志模式);摄像头打开失败→明确错误
- [X] T016 [US2] 实现 FaceDevice 识别侧在 /mnt/1t/y/kiran-authentication-service/src/device/adaptor/face-device.cpp:doIdentifyStart 解析 feature_ids→工作线程执行→按 contracts 3.2 表映射 IdentifyStatus(RETRY 不结束/MATCH 带 featureID/NOT_MATCH 结束/超时结束);IdentifyStop 标记停止并丢弃结果(FR-008);feature_ids 为空→提示"未录入人脸特征"
- [X] T017 [US2] 补齐错误码文案在 /mnt/1t/y/kiran-authentication-service/plugins/driver/face/face-driver.cpp:getErrorMsg 全错误码中英文映射(摄像头/算法/录入段),消息随状态回报透传到界面
- [X] T018 [US2] PAM 链路联调:启动服务后经 PAM/锁屏走通人脸认证;确认 daemon session.cpp 注入的 feature_ids 被正确消费、daemon User/Session 对 IdentifyStatus 的既有处理无需改动;验证切换密码/停止无阻塞(SC-001)

**Checkpoint**: US2 可独立演示——登录/锁屏人脸识别闭环打通

---

## Phase 5: User Story 3 - 人脸特征管理 (Priority: P2)

**Goal**: 列表/重命名/删除,即时生效且重启后保持

**Independent Test**: 面板人脸页:列表显示 → 重命名生效 → 删除后不再参与认证,重启服务后状态保持(quickstart 步骤 5-7)

### Implementation for User Story 3

- [X] T019 [US3] 实现 FaceDevice::GetFeatureIDList 在 /mnt/1t/y/kiran-authentication-service/src/device/adaptor/face-device.cpp:按 DEVICE_TYPE_FACE 从 FeatureDB 查询 featureID 列表返回;确认设备管理器 Remove(featureID) 链路可用(manager.cpp:350 已有 FeatureDB 删除逻辑)
- [X] T020 [US3] 删除链路验证(不改 daemon 代码):核对 /mnt/1t/y/kiran-authentication-service/src/daemon/user.cpp onDeleteIdentification 的既有双写删除(daemon 删库 + 调设备管理器 Remove);确认该处 TODO 注释(同步删除认证设备管理中的 fid)已过时并记录结论;在 face 场景验证双写删除一致
- [ ] T021 [US3] 面板管理联调(跨仓库 /mnt/1t/y/kiran-control-panel):general-bio-page.cpp/face-page.cpp 的列表(GetIdentifications)、重命名(RenameIdentification)、删除(DeleteIdentification)在人脸上全链路验证;重命名/删除后 FeatureDB 与界面一致,重启保持

**Checkpoint**: 全部用户故事独立可用

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: 配置化、日志、i18n、全量验证与交付文档

- [X] T022 [P] 阈值配置化:人脸驱动相似度阈值做成配置项(读 face 驱动配置文件,默认值实现阶段标定:参考同人 0.885/异人 0.179,初值取 0.55~0.65 区间,research D9)
- [X] T023 [P] 日志补齐:KLOG 记录录入/识别关键事件(请求来源、图像大小、检测结果、比对分数、耗时、错误码),参照现有设备日志风格(soft-face-device.cpp 为范本)
- [X] T024 [P] 文案与翻译:驱动/设备错误文案中英文,更新 /mnt/1t/y/kiran-authentication-service/translations/ 下的 .ts 文件(lupdate/lrelease 流程)
- [ ] T025 全量验证:按 /mnt/1t/y/kiran-authentication-service/specs/001-face-recognition/quickstart.md 执行 13 步端到端 + SC-001~SC-006 对照(含离线、重启持久化、多脸、超时、重复录入)
- [X] T026 [P] 交付文档:说明安全边界(无活体检测,照片/屏幕可通过)、模型来源与许可(ncnn 模型,OpenCV Zoo 衍生)、部署与升级说明;更新 README

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: 无依赖,立即开始
- **Foundational (Phase 2)**: 依赖 Setup——阻塞所有用户故事
- **User Stories (Phase 3-5)**: 依赖 Foundational;US3 可与 US1/US2 并行(主要动 daemon 既有链路)
- **Polish (Phase 6)**: 依赖目标故事完成

### User Story Dependencies

- **US1 (P1)**: Foundational 后即可开始,无其他故事依赖 —— **MVP**
- **US2 (P1)**: 依赖 Foundational(T004-T007)+ US1 的 T010/T011(设备类与装载是共享的);识别逻辑本身独立
- **US3 (P2)**: 依赖 US1 的 T010/T011(设备注册后才有删除链路),其余为既有 daemon 代码的验证/补齐

### Within Each User Story

- 驱动实现(enroll/identify)→ 设备类接线 → 装载/注册 → D-Bus 验证 → 面板联调
- 每个故事完成即过 Checkpoint,可独立演示

### Parallel Opportunities

- T002/T003、T005/T006/T008 可并行(不同文件)
- US2 的 T015(驱动识别)可与 US1 的 T013/T014(面板)并行
- US3 的 T019-T021 与 US2 联调并行
- Polish 的 T022/T023/T024/T026 可并行

---

## Implementation Strategy

### MVP First (User Story 1)

1. Phase 1 Setup → Phase 2 Foundational(T004-T008,基准达标)
2. Phase 3 US1(T009-T014)完成 → 面板录入闭环
3. **STOP and VALIDATE**: quickstart 步骤 1-9 独立验证
4. 可先行交付/演示录入能力

### Incremental Delivery

1. Setup + Foundational → 算法引擎可用
2. +US1 → 录入闭环(MVP)
3. +US2 → 登录/锁屏识别闭环(P1 全量)
4. +US3 → 特征管理完整
5. +Polish → 配置化/日志/i18n/全量验证/文档

### Parallel Team Strategy

- 开发者 A:US1 服务侧(T009-T012)
- 开发者 B:US1 面板侧(T013-T014,跨仓库)
- 开发者 C:US2 驱动识别(T015 可在 Foundational 后先行)
- US3 由任一完成者接手(改动量小)

---

## Notes

- 跨仓库任务(T013/T014/T021)在 /mnt/1t/y/kiran-control-panel 提交,建议与本仓库分支同名提交并联动合并
- T003/T012/T018/T020 为"验证/核对"型任务:先读代码确认零改动结论,不符合才动手改
- daemon 侧设计结论为零改动,若实现中发现契约偏差,先回看 contracts/face-device-contract.md 与 research.md,再决定是否改 daemon
- 每完成一个任务或逻辑组提交一次(commit-code 技能)
- 模型文件体积较大(param+bin 共 ~2MB 级),提交前确认 .gitignore 不影响 data/models/face/
