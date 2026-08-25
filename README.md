
# 认证管理服务
对于系统账户进行认证，包括指纹，人脸和UKEY等认证方式

# 依赖
yum install glib-2.0-devel zlog-devel json-glib-1.0-devel kiran-cc-daemon-devel
# 本地人脸识别额外依赖:ncnn、opencv4
yum install ncnn opencv4

# 编译
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..

# 安装
cmake install

# pam模块
pam_kiran_authentication.so 等待认证结果信号，对认证结果进行处理

# 本地人脸识别
- 算法:本地执行(YuNet 人脸检测 + SFace 128 维特征 + 余弦相似度比对),基于 ncnn,
  不依赖网络或远端服务器;与"软人脸"(比对在远端执行的方案)相互独立。
- 模型:不随本仓库分发,由 kiran-authentication-devices-sdk 仓库提供,
  安装至 /usr/share/kiran-authentication-service/models/face/
  (yunet/sface 的 param+bin,来源为 OpenCV Zoo 衍生模型,许可见 NOTICE);
  开发调试可用 KAS_FACE_MODEL_DIR 指向本地模型目录。
- 录入:控制面板人脸页实时预览并拍照提交,服务端完成检测/提取/持久化。
- 配置:kad.ini [Face] Threshold 为相似度阈值(默认 0.6)、Camera 为识别
  摄像头(索引或设备路径,默认 0);环境变量 KAS_FACE_MODEL_DIR /
  KAS_FACE_THRESHOLD 可覆盖。
- 安全边界:本期不含活体检测,照片/屏幕画面可能通过人脸认证,请结合
  使用场景评估风险(参见 specs/001-face-recognition/spec.md)。

