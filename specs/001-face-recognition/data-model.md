# Phase 1 Data Model: 本地人脸识别认证

**Date**: 2026-08-19

## 实体

### 1. 人脸特征 (FeatureData) — 已有结构,复用

来源:`lib/feature-data.h`;落库:`FeatureDB`(SQLite,`KAS_INSTALL_DATADIR`)。

| 字段 | 类型 | 说明 |
|---|---|---|
| feature | QByteArray | 128 维 float 原始字节(SFace 输出),比对依据 |
| featureID | QString | = MD5(feature),全局唯一,录入查重依据 |
| featureName | QString | 面板自动生成或用户重命名 |
| iid | QString | daemon 生成(Utils::GenerateIID(authType, featureID)),面板管理操作的句柄 |
| userName | QString | 所属操作系统账户 |
| deviceType / authType | int | DEVICE_TYPE_FACE / KAD_AUTH_TYPE_FACE |
| idVendor / idProduct / deviceSerialNumber | QString | 本地设备无 vid/pid,留空 |

**写入方**: daemon `User::onEnrollStatus`(COMPLETE 时解析设备上报的 FeatureData 并 addFeature)。
**删除方**: 面板 → daemon `onDeleteIdentification` → 双写删除(daemon FeatureDB + 设备管理器 `Remove(featureID)` → 设备侧 FeatureDB)。
**读取方**: 设备管理器侧按 `feature_ids` 查询特征 blob 供比对。

### 2. 人脸设备 (FaceDevice) — 新建

类:`src/device/adaptor/face-device.{h,cpp}`,继承 `Device`(device.h 已有骨架)。

| 属性 | 值/说明 |
|---|---|
| deviceType | DEVICE_TYPE_FACE |
| 状态机 | IDLE ⇄ DOING_ENROLL / DOING_IDENTIFY(设备忙语义,FR-007) |
| 装载 | 启动期无 vid/pid 装载(见 D3) |

状态转换:
- `EnrollStart(extraInfo)` 且 IDLE → DOING_ENROLL;COMPLETE/FAIL/Stop → IDLE
- `IdentifyStart(extraInfo)` 且 IDLE → DOING_IDENTIFY;MATCH/NOT_MATCH/超时/Stop → IDLE
- 非 IDLE 时新请求 → 明确拒绝"设备忙"
- Stop 语义:标记停止,处理线程完成/超时后丢弃结果(参照现有 SoftFaceDevice 模式)

### 3. 人脸驱动 (FaceDriver) — 新建

类:`plugins/driver/face/face-driver.{h,cpp}`,继承 `Driver`(`DRIVER_TYPE_FACE`),插件导出 `createDriver()`。
`include/driver-i.h` 扩展 `FaceDriver` 抽象基类:

```cpp
class FaceDriver : public Driver {
public:
    virtual int identify(const std::string &extraInfo) = 0;  // 摄像头自采循环,0=匹配,非0=错误码
    virtual int enroll(const std::string &extraInfo) = 0;    // 解析 base64 图像→特征;0=成功
    virtual void identifyResultPostProcess(const std::string &extraInfo) = 0;
};
```

内部封装:ncnn YuNet 检测器 + SFace 特征器(参考 ncnn_test.cpp 的 YunetNcnn/SfaceNcnn 类)。

## 请求/响应契约对象

### 录入请求 extraInfo(面板 → daemon → 设备)

```json
{ "faceImage": "<JPEG base64>" }
```

- 图像:面板预览当前帧,JPEG 编码后 base64;单张
- 校验:解码失败 → FAIL("图像无效");无脸/质量不达标 → FAIL("未检测到人脸");多脸取面积最大的一张;重复 → FAIL("该特征已录入")

### 识别请求 extraInfo(daemon → 设备)

```json
{ "feature_ids": ["<md5-1>", "<md5-2>", ...], ...面板/会话透传字段 }
```

- feature_ids 为空 → 提示"未录入人脸特征",结束(或按现有语义 NOT_MATCH)
- 设备按 ID 从 FeatureDB 读 blob;读不到 → 跳过该 ID

### 状态回报

- 录入:`EnrollStatus(data, progress, result, message)`;COMPLETE 时 data=FeatureData JSON(`lib/feature-data.h` 的 structToJson 格式)
- 识别:`IdentifyStatus(featureID, result, message)`;MATCH 时 featureID=命中的特征 ID

## 校验规则(源自 spec FR)

| 规则 | 来源 |
|---|---|
| 多脸(检测框 N>1)取面积最大的一张 | FR-014 |
| 重复录入(featureID 已存在)拒绝 | FR-018 |
| 窗口内持续比对;结束区分不匹配/超时 | FR-006 |
| 识别采集超时默认 10 秒 | FR-019 |
| 设备忙拒绝新请求 | FR-007 |
| 停止后丢弃结果 | FR-008 |
| 每账户特征数 ≤ 10(现有 daemon 检查,零改动) | FR-015(已裁决) |
