# Quickstart:本地人脸识别认证端到端验证

**Date**: 2026-08-19
**前置阅读**: [contracts/face-device-contract.md](./contracts/face-device-contract.md)、[data-model.md](./data-model.md)

## 0. 前置条件

- 构建安装本仓库(带新 face 驱动插件 + FaceDevice)+ 配套改动的 kiran-control-panel
- 摄像头可用:`ls /dev/video0`(或 `v4l2-ctl --list-devices` 确认)
- 模型已安装:`$KAS_INSTALL_DATADIR/models/face/{yunet.param,yunet.bin,sface.param,sface.bin}`
- 系统服务运行:`kiran-authentication-devices`、`kiran-authentication-daemon`

## 1. 单元/算法验证(服务侧,无 UI)

### 1.1 特征基准回归

用参考图集跑驱动内算法单元验证,期望与参考基准一致:

```bash
# 期望:检测 135 张脸;同一人余弦 ≈ 0.885;不同人 ≈ 0.179
./face-algo-benchmark /path/to/largest_selfie.jpg /path/to/lena.jpg
```

### 1.2 D-Bus 录入验证(跳过面板,直接模拟面板调用)

```bash
# 准备:任意人脸照片 base64
# 注意:dbus-send 单参数上限 128KB,压缩后图片的 base64 需小于该值,
# 更大图请用脚本或真实面板
IMG_B64=$(base64 -w0 face.jpg)
JSON="{\"faceImage\":\"$IMG_B64\"}"

# 先创建用户对象,再发起录入(daemon 有调用方用户校验)
dbus-send --system --print-reply --dest=com.kylinsec.Kiran.Authentication \
  /com/kylinsec/Kiran/Authentication \
  com.kylinsec.Kiran.Authentication.FindUserByID uint64:0
dbus-send --system --print-reply --dest=com.kylinsec.Kiran.Authentication \
  /com/kylinsec/Kiran/Authentication/User/0 \
  com.kylinsec.Kiran.Authentication.User.EnrollStart \
  int32:4 string:"face1" string:"$JSON"
```

期望:`dbus-monitor` 观察到 `EnrollStatus` 信号,progress 递增,最终 `(iid, true, 100, ...)`;查询 `GetIdentifications(face)` 返回新特征;重启 daemon 后特征仍在。

### 1.3 D-Bus 识别验证

```bash
# 注意:dbus-send 调用完即退出,设备检测到调用方断连会自动停止流程
# (面板断连保护语义);识别等长流程需用保持 D-Bus 连接的脚本,例如:
python3 - <<'EOF'
import dbus, dbus.mainloop.glib, json
from gi.repository import GLib
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()
# 设备路径用 GetDevicesByType(int32:1) 查询
obj = bus.get_object('com.kylinsec.Kiran.AuthDevice', '/com/kylinsec/Kiran/AuthDevice/Device_XXX')
iface = dbus.Interface(obj, 'com.kylinsec.Kiran.AuthDevice.Device')
iface.connect_to_signal('IdentifyStatus', lambda fid, result, msg: print('IdentifyStatus:', fid, result, msg))
iface.IdentifyStart(json.dumps({'feature_ids': ['<featureID>']}))
loop = GLib.MainLoop(); GLib.timeout_add_seconds(15, loop.quit); loop.run()
EOF
# 期望:镜头前无人 → RETRY"未检测到人脸"后 10 秒 → "识别超时";
# 本人面对摄像头 → MATCH(返回特征ID);他人 → NOT_MATCH"人脸不匹配"
```

## 2. 面板端到端验证(推荐主路径)

| # | 步骤 | 期望 |
|---|---|---|
| 1 | 打开控制面板 → 身份认证 → 人脸 | 特征列表页正常显示(空列表或已有特征) |
| 2 | 点击"录入" → 密码验证 | 切入录入页,**摄像头预览立即显示** |
| 3 | 面对摄像头,点击"拍照/录入" | 进度反馈;完成后弹"录入成功",特征出现在列表 |
| 4 | 照片中无脸/多脸时点拍照 | 无脸提示"未检测到人脸";多脸取面积最大的一张录入 |
| 5 | 对同一张脸再次录入 | 提示"该特征已录入" |
| 5a | 在已有 10 个特征时再次发起录入 | 拒绝并提示"特征数量已达上限"(FR-015) |
| 6 | 重命名特征 → 重启服务 → 查看 | 新名称保持 |
| 7 | 删除特征 → 查看列表 | 特征移除;锁屏后人脸认证提示未录入/不匹配 |
| 8 | 录入页停留 2 分钟不动 | 自动关闭预览并返回管理页 |
| 9 | 录入中点击取消/关闭页面 | 流程终止、摄像头关闭、无残留特征 |
| 10 | 锁屏 → 选择人脸认证,本人面对摄像头 | 认证通过进入桌面 |
| 11 | 锁屏 → 人脸认证,他人面对摄像头 | 提示不匹配,可切换密码 |
| 12 | 人脸认证时切换到密码 | 识别停止,切换流畅无阻塞 |
| 13 | 断网后重复 1-12 | 全部正常(全离线) |

## 3. 成功标准对照(spec SC)

| SC | 验证方式 |
|---|---|
| SC-001 不阻塞 PAM 链路 | 步骤 12;观察切换响应与停止语义 |
| SC-002 本人通过率 ≥95% | 步骤 10 重复 20 次,统计 |
| SC-003 他人误通过 ≤0.1% | 多人交叉测试(≥1000 次比对,可用批量图集代替真人) |
| SC-004 首次录入成功率 ≥90% | 步骤 2-3 重复 20 次 |
| SC-005 增删改查即时生效 | 步骤 5-7 |
| SC-006 离线可用 | 步骤 13 |

## 4. 已知限制

- 无活体检测:照片/屏幕可通过(交付文档需说明)
- 无硬件人脸设备(双目/红外):仅默认 V4L2 摄像头
- 无人走监测(后续迭代)
