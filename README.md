
# 认证管理服务
对于系统账户进行认证，包括指纹，人脸和UKEY等认证方式

# 依赖
yum install glib-2.0-devel zlog-devel json-glib-1.0-devel kiran-cc-daemon-devel

# 编译
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..

# 安装
cmake install

# pam模块
pam_kiran_authentication.so 等待认证结果信号，对认证结果进行处理
