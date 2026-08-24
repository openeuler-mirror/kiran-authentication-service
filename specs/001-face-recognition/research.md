# Phase 0 Research: 本地人脸识别认证

**Date**: 2026-08-19

## D1 算法引擎:ncnn(用户已选型)

- **Decision**: 使用 ncnn 方案,严格参考 `/mnt/1t/y/opencv/backport_452/ncnn_test.cpp`;模型用 `ncnn_models/yunet.param|bin` + `sface.param|bin`。
- **Rationale**: 用户明确选择(需求原文即指向 ncnn_test.cpp);ncnn 1.0.20260624 已装;参考程序已验证基准(135 张脸 / 同人 0.885 / 异人 0.179)。
- **Alternatives considered**: OpenCV DNN 移植版(backport_452 的 yunet_detector.hpp/sface_recognizer.hpp,ONNX 模型)——依赖更薄但用户选 ncnn。

## D2 命名与类型:新类,不复用 soft 命名

- **Decision**: 新建 `FaceDriver`(继承 Driver,`DRIVER_TYPE_FACE`)与 `FaceDevice`(继承 Device,`DEVICE_TYPE_FACE`),对应 `KAD_AUTH_TYPE_FACE`。绝不沿用 `SoftFaceDriver`/`SOFT_DEVICE_TYPE_FACE`(那是 ks-authhub 远端比对方案的命名)。
- **Rationale**: 用户明确要求;枚举中 KAD_AUTH_TYPE_FACE 与 KAD_AUTH_TYPE_SOFT_FACE 本就并存,语义独立。

## D3 设备装载路径:无 vid/pid 的本地设备在启动时装载

- **Decision**: `Manager` 增加启动期装载路径:扫描驱动插件中 `DRIVER_TYPE_FACE` 且 `getSupportVidPid()` 为空(无硬件绑定)的驱动,在 `genSoftDevices()` 旁新增 `genLocalDevices()`(或等价逻辑)创建 `FaceDevice`,设备状态初始化为在线。
- **Rationale**: 本地人脸识别没有 USB 设备(vid/pid),不会触发 udev 事件;而 daemon 的 `authType2DeviceType(KAD_AUTH_TYPE_FACE)=DEVICE_TYPE_FACE` 路由要求设备管理器能通过 `GetDevicesByType(DEVICE_TYPE_FACE)` 返回该设备。现有 `genDevice()`(udev 路径)的 FACE case 是 TODO,不能依赖。

## D4 录入契约:图像经 extraInfo JSON(base64)提交,特征由 daemon 落库

- **Decision**: 面板拍照后调用 `EnrollStart(authType=face, featureName, extraInfo={"faceImage": "<base64 JPEG>"})`;daemon 原样透传给设备 `EnrollStart(extraInfo)`;`FaceDevice::doEnrollStart` 解析 extraInfo,取 base64 图像交给 `FaceDriver::enroll()`:解码 → YuNet 检测(多脸取最大脸,无脸拒绝)→ SFace 对齐+提特征 → 计算 featureID(MD5)→ 查重 → 通过 `EnrollStatus(data=FeatureData JSON, 100, COMPLETE, msg)` 回报;daemon `User::onEnrollStatus` 已有逻辑解析 FeatureData 并写入 FeatureDB(零改动)。
- **Rationale**: 复用既有 D-Bus 通道不新增方法(旧架构无面板传图先例,此为新增环节);daemon 侧 COMPLETE→FeatureDB 落库逻辑已存在(user.cpp:211-232)。
- **Alternatives considered**: 新增 D-Bus 方法传字节数组 —— 接口改动大,收益小。

## D5 识别契约:feature_ids 注入 + 设备侧查库比对 + 摄像头自采

- **Decision**: 识别链路不改:daemon `Session::startGeneralAuth` 已把目标用户特征 ID 注入 `extraInfo.feature_ids`(session.cpp:600-603);设备侧 `FaceDevice::doIdentifyStart` 从本进程 FeatureDB 按 feature_ids 读取特征 blob;`FaceDriver::identify()` 用 OpenCV VideoCapture 打开默认摄像头连续采集:YuNet 检测 → 多脸取最大脸 → 对齐提特征 → 与目标特征逐一余弦比对 → 超过阈值 → `IdentifyStatus(featureID, MATCH)`;窗口内持续比对,窗口结束区分结果:比对过且均不匹配 → `NOT_MATCH`"人脸不匹配";未检测到可比对人脸 → "识别超时";停止请求 → 丢弃结果。
- **Rationale**: 设备管理服务与 daemon 同用 lib 里的 FeatureDB(同一 SQLite 路径),manager.cpp:350 已有设备侧删特征先例,证明两侧共享存储是既有设计。

## D6 状态映射(对齐 spec 与旧 multi-function 语义)

- **Decision**:
  - 录入:处理中 progress 0→100 递增(检测/提取/保存各阶段);无脸/质量不达标 → `ENROLL_STATUS_FAIL`(提示原因,预览保留可重试);多脸取面积最大的一张;重复录入 → `FAIL`("该特征已录入");成功 → `COMPLETE`(100%,data=FeatureData JSON)。
  - 识别:无脸/质量差 → `IDENTIFY_STATUS_RETRY`(提示调整,继续采集);多脸取最大脸;匹配 → `MATCH`(featureID);窗口结束区分:比对过且均不匹配 → `NOT_MATCH`"人脸不匹配";未检测到可比对人脸 → "识别超时"。
- **Rationale**: 语义与 spec FR-006/FR-014/FR-018/FR-019 及旧 multi-function 的 ENROLL_PROCESS/IDENTIFY_PROCESS 映射一致。

## D7 特征存储:复用 FeatureDB,featureID=特征字节 MD5

- **Decision**: 特征 blob = SFace 输出 128 维 float 原始字节;featureID = MD5(blob);录入查重即查 featureID 是否已存在。FeatureDB(SQLite,`KAS_INSTALL_DATADIR`)复用,不改表结构。
- **Rationale**: 与旧 multi-function `handleFaceEnrolled` 完全一致(QCryptographicHash::hash(feature, Md5));daemon 已按 featureID 生成 iid 并入库。

## D8 摄像头:识别阶段服务端自采,录入阶段不碰摄像头

- **Decision**: 驱动内用 `cv::VideoCapture(0)`(V4L2)采集识别帧;录入阶段服务端不打开摄像头(面板预览+传图)。摄像头打开失败 → 明确错误提示。
- **Rationale**: 契约要求(FR-013);识别时无面板参与。

## D9 阈值与标定

- **Decision**: 相似度阈值做成配置文件项(如 face 驱动配置),默认值在实现阶段用参考基准数据标定:参考同人 0.885/异人 0.179,初值取两者之间偏保守(约 0.55~0.65),标定后固化。满足 SC-003(他人误通过 ≤0.1%)。
- **Rationale**: 阈值是数值标定问题,不是需求问题;FR-010 要求可配置。

## D10 每用户特征上限(已裁决)

- **Decision**: 保留现有 daemon 的 `FEATURE_COUNT_MAXIMUN = 10`(user.cpp:37,超限返回 `ERROR_USER_FEATURE_LIMITS_EXCEEDED`);spec FR-015 已同步改为"每账户最多 10 个特征,达到上限拒绝录入并提示"。daemon 零改动。
- **Rationale**: 用户裁决(2026-08-19),与现有生物特征限制一致。

## D11 面板改造范围(kiran-control-panel,跨仓库)

- **Decision**: `face-page.cpp` 录入页:切入录入页即开 QCamera 预览(替换 272×272 静态进度图位置),新增"拍照/录入"按钮;点击时捕获当前帧 → JPEG → base64 → 组装 extraInfo `{"faceImage": ...}` → 调用 `startEnroll(KAD_AUTH_TYPE_FACE, featureName, extraInfo)`(注意:现流程是"先 startEnroll 再切页",需调整为"先切页预览、拍照时才 startEnroll");取消/关页关闭摄像头(处理中先 stopEnroll);2 分钟无操作自动关闭预览回管理页。面板仓库目前无任何摄像头代码,预览为新增能力。
- **Rationale**: spec US1/FR-013/FR-016/FR-017 的落地;会话在拍照时建立,预览阶段不占用设备忙状态。

## D12 模型与依赖打包

- **Decision**: 模型文件(yunet.param/bin、sface.param/bin)随软件包安装至数据目录(如 `KAS_INSTALL_DATADIR/models/face/`);CMake 增加 `ncnn` 与 OpenCV 模块链接;驱动插件在设备管理服务构建树内编译安装。
- **Rationale**: 离线可用要求;ncnn 与 OpenCV 4.5.2 均为系统已装依赖。
