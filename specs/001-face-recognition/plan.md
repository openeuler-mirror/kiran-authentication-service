# Implementation Plan: 本地人脸识别认证

**Branch**: `001-face-recognition` | **Date**: 2026-08-19 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-face-recognition/spec.md`

## Summary

为 kiran-authentication-service 增加本地人脸识别认证(与 ks-authhub 的远端比对方案无关):在设备管理服务侧实现基于 ncnn(YuNet 检测 + SFace 128 维特征 + 余弦相似度比对)的人脸驱动与设备适配器;控制面板在录入时实时预览、拍照后将图像经 extraInfo JSON(base64)提交给服务,由服务完成检测、特征提取、持久化(复用 FeatureDB);识别认证由 PAM 会话链路触发,服务自行控制摄像头采集,仅与目标用户特征比对。涉及本仓库(设备+驱动+daemon 适配)与 kiran-control-panel(录入预览页)两个仓库。

## Technical Context

**Language/Version**: C++11(CMakeLists.txt `CMAKE_CXX_STANDARD 11`),Qt5(QDBus/QtConcurrent/QLibrary)

**Primary Dependencies**: ncnn 1.0.20260624(系统已装,`pkg-config ncnn` 可用);OpenCV 4.5.2(系统已装,仅需 core/imgproc/imgcodecs/dnn[NMSBoxes]);Qt5 SQLite(FeatureDB 现有)

**Storage**: 复用现有 FeatureDB(SQLite,`KAS_INSTALL_DATADIR`),daemon 与设备管理服务两侧进程均通过共享 lib 访问;特征 blob=128 维 float 字节,featureID=blob 的 MD5(与旧 multi-function 一致)

**Testing**: 单元验证用 backport_452 参考程序同款基准(135 张脸/同人 0.885/异人 0.179);端到端通过 D-Bus 调用 + 控制面板手工验证(quickstart.md)

**Target Platform**: 国产化桌面终端 Linux(x86_64/ARM64),CPU 推理,无 GPU 依赖;摄像头经 V4L2

**Project Type**: 系统服务(设备管理服务 + D-Bus 接口)+ 驱动插件(.so) + 跨仓库面板配套

**Performance Goals**: 不阻塞 PAM 认证链路;识别默认 10 秒超时窗口(FR-019);单帧检测+特征提取为百毫秒级(ncnn CPU,参考基准)

**Constraints**: 离线可用;模型随软件包分发(yunet.param/bin + sface.param/bin);识别阈值可配置,默认值待标定(参考同人 0.885/异人 0.179);多脸一律拒绝(FR-014)

**Scale/Scope**: 本机单设备;每操作系统账户最多 10 个人脸特征(沿用 daemon 现有 FEATURE_COUNT_MAXIMUN 检查,零改动);单用户并发请求由设备忙语义串行化

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

对照 constitution v1.0.0(2026-08-19 确立)校验:原则 I 契约优先(contracts/ 已产出,共享层零改动)✓、II 本地优先(ncnn 本地引擎+模型随包分发)✓、III 安全(安全边界文档化、阈值可配置)✓、IV 驱动稳定(新增独立抽象类,不破坏既有驱动)✓、V 可观测(日志/基准回归/quickstart 验证已排期)✓ → **GATE 通过**。

## Project Structure

### Documentation (this feature)

```text
specs/001-face-recognition/
├── plan.md              # 本文件
├── research.md          # Phase 0:决策记录
├── data-model.md        # Phase 1:数据模型与状态机
├── quickstart.md        # Phase 1:端到端验证指南
├── contracts/           # Phase 1:跨进程/跨仓库契约
│   └── face-device-contract.md
└── tasks.md             # Phase 2(/speckit-tasks,本命令不生成)
```

### Source Code (repository root)

```text
kiran-authentication-service/
├── include/
│   └── driver-i.h                      # 扩展:新增 FaceDriver 抽象基类(DRIVER_TYPE_FACE)
├── lib/                                # 共享库:FeatureDB / FeatureData(已有,复用)
├── plugins/driver/face/                # 新建:ncnn 人脸驱动插件(.so,导出 createDriver)
│   ├── face-driver.{h,cpp}             #   摄像头采集、检测/特征/比对、错误码
│   ├── yunet-ncnn.{h,cpp}              #   YuNet ncnn 封装(参考 ncnn_test.cpp)
│   ├── sface-ncnn.{h,cpp}              #   SFace ncnn 封装(5点对齐+128维特征)
│   └── CMakeLists.txt
├── src/device/adaptor/                 # 设备管理服务
│   ├── face-device.{h,cpp}             # 新建:本地人脸设备(DEVICE_TYPE_FACE,非 soft)
│   └── manager.cpp                     # 修改:增加本地人脸驱动的启动装载路径
├── src/device/CMakeLists.txt           # 修改:链接 ncnn/OpenCV、模型安装规则
├── data/                               # 模型文件安装(yunet/sface param+bin)
└── specs/001-face-recognition/         # 本文档目录

kiran-control-panel/(跨仓库配套)
└── plugins/authentication/
    ├── pages/face-page.{h,cpp}         # 修改:录入页开摄像头预览+拍照按钮+2min超时
    └── utils/                          # 修改:startEnroll 时携带 base64 图像 extraInfo
```

**Structure Decision**: 完全沿用现有分层——面板 → kiran-authentication-daemon(src/daemon)→ 设备管理服务(src/device)→ 驱动插件(plugins/driver)。新增代码只在设备管理服务侧(新 FaceDevice + 新 face 驱动插件)与面板录入页;daemon 侧零改动(契约兼容:EnrollStatus data=FeatureData JSON 已有消费逻辑,feature_ids 注入已有逻辑)。

## Complexity Tracking

无 constitution 违规,不需要本表。
