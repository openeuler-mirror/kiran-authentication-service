# 接口契约:本地人脸设备

**Date**: 2026-08-19
**范围**: kiran-control-panel ↔ kiran-authentication-daemon ↔ 设备管理服务(kiran-authentication-devices)↔ 人脸驱动插件

## 1. 链路总览

```
控制面板                         daemon                          设备管理服务                      驱动插件
FacePage                       User/Session/DeviceAdaptor        FaceDevice                       FaceDriver
  │ EnrollStart(authType,name,      │                                 │                               │
  │   extraInfo{faceImage})         │ 透传 extraInfo                  │                               │
  ├────────────────────────────────>│ EnrollStart(extraInfo)         │                               │
  │                                 ├────────────────────────────────>│ doEnrollStart → enroll(image)  │
  │                                 │                                 ├──────────────────────────────>│
  │                                 │                                 │<─ EnrollStatus(data,progress, │
  │<─ EnrollStatus(iid,complete,     │<─ (result,message 转发)         │   result, message)            │
  │    progress, message)           │  COMPLETE: data=FeatureData     │                               │
  │                                 │  → FeatureDB.addFeature → iid   │                               │
  │                                 │                                 │                               │
  │                                 │ Session.startGeneralAuth        │                               │
  │                                 │ extraInfo.feature_ids=[...]     │ IdentifyStart(extraInfo)      │
  │                                 ├────────────────────────────────>│ doIdentifyStart → identify()  │
  │                                 │                                 ├──────────────────────────────>│
  │                                 │                                 │<─ IdentifyStatus(featureID,  │
  │<─ AuthMessage/AuthResult        │<─ result, message)              │    result, message)           │
```

## 2. 录入契约

### 2.1 请求

面板调用既有 `EnrollStart(authType, featureName, extraInfo)`:

| 参数 | 值 |
|---|---|
| authType | `KAD_AUTH_TYPE_FACE` |
| featureName | 面板自动生成(现有 autoGenerateFeatureName) |
| extraInfo | `{"faceImage":"<JPEG base64>"}` |

**时序(与现状差异)**:面板进入录入页只开摄像头预览,不建会话;用户点击"拍照/录入"时才调用 EnrollStart(携带图像)。

### 2.2 状态回报 EnrollStatus(data, progress, result, message)

| result | 场景 | progress | data | message 示例 |
|---|---|---|---|---|
| NORMAL | 处理中 | 0→100 递增 | — | "正在处理…" |
| FAIL | 解码失败/无脸/质量不达标/重复/保存失败 | 0 | — | "未检测到人脸"/"该特征已录入" |
| COMPLETE | 成功 | 100 | FeatureData JSON | "录入成功" |

COMPLETE 的 data 必须包含:feature(QByteArray 特征字节)、featureID(MD5)、deviceType、authType(daemon 会补 featureName/iid/userName 并写入 FeatureDB)。

### 2.3 停止/取消

- 面板取消或关页:若有处理中的会话 → `EnrollStop()`;无会话 → 仅关闭摄像头。
- 设备收到 EnrollStop → 标记停止,处理线程结束后丢弃结果并回 IDLE。

## 3. 识别契约

### 3.1 请求

daemon `Session::startGeneralAuth` 现有逻辑注入特征 ID(零改动):

```json
{ "feature_ids": ["<md5...>"], ...面板透传字段 }
```

### 3.2 状态回报 IdentifyStatus(featureID, result, message)

| result | 场景 | featureID | message 示例 |
|---|---|---|---|
| RETRY | 未采集到人脸/质量不足 | — | "请面对摄像头" |
| MATCH | 余弦相似度 ≥ 阈值 | 命中特征 ID | "识别成功" |
| NOT_MATCH | 窗口内检测到人脸并比对,但均不匹配(窗口结束后报告) | — | "人脸不匹配" |
| 结束性错误 | 窗口内一直未检测到可比对人脸 | — | "识别超时" |

**语义要点**:RETRY 不结束流程,驱动继续采集;MATCH/NOT_MATCH/超时/停止均结束本次识别(一次识别一个结果)。

## 4. 特征管理契约

| 操作 | 链路 | 说明 |
|---|---|---|
| 列表 | 面板 `GetIdentifications(face)` → daemon FeatureDB | 已有,零改动 |
| 重命名 | 面板 `RenameIdentification(iid, name)` → daemon FeatureDB | 已有,零改动 |
| 删除 | 面板 `DeleteIdentification(iid)` → daemon 删库 + 调设备管理器 `Remove(featureID)` → 设备侧删库 | 已有,零改动 |

## 5. 错误码(驱动层)

FaceDriver 实现 `getErrorMsg(int)` 映射错误码 → 可读文案(中文+英文,跟随现有 i18n 机制):

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1xx | 摄像头:打开失败 / 已关闭 / 采集失败 |
| 2xx | 算法:模型加载失败 / 无脸 / 多脸取最大脸(203 保留不使用)/ 提取失败 |
| 3xx | 录入:图像解码失败 / 特征重复 / 保存失败 |

(具体编码在实现阶段定稿;面板展示 message 字段,不解析错误码。)

## 6. 兼容性

- daemon 侧对 KAD_AUTH_TYPE_FACE 的路由(`authType2DeviceType` → DEVICE_TYPE_FACE)与 COMPLETE 落库逻辑均已存在,**无需修改 daemon 代码**。
- 面板旧行为(先 startEnroll 后切页)在 face 认证上将被新时序取代,不影响其他认证类型。
- extraInfo 为 JSON 扩展字段:`faceImage` 仅 face 设备解析;其他设备忽略未知字段。
