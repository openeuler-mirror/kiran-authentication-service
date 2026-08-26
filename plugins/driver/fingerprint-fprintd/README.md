# kiran-fingerprint-fprintd

基于系统 [fprintd](https://fprint.freedesktop.org/) 的指纹驱动插件。  
**不**链接 `libfprint.so`；采集与模板存储由 fprintd 完成。

## 架构

```
面板 / PAM → daemon → FingerprintDevice → kiran-fingerprint-fprintd.so
                                              ↓ D-Bus (system)
                                         net.reactivated.Fprint
                                              ↓
                                         libfprint（fprintd 进程内）
```

- FeatureDB 仅存映射串：`fprintd:<user>:<finger_name>`，`featureID = MD5(映射串)`
- 生物模板权威源：fprintd（通常 `/var/lib/fprint/`）

## 依赖

- 运行：`fprintd` 服务、受支持的 USB 指纹仪
- 构建：Qt5 Core + DBus（不需要 libfprint-devel）
- CMake：`BUILD_FINGERPRINT_DRIVER=ON`（默认）

## 与旧 libfprint 直连的差异

| 项 | 旧直连（已移除代码） | 本插件 |
|---|---|---|
| 链接 libfprint | 是 | 否 |
| 模板位置 | FeatureDB blob | fprintd + FeatureDB 映射 |
| 排障 | 无 | `fprintd-enroll` / `verify` / `list` / `delete` |
| 装载 | USB VID/PID 热插 | 本地驱动启动装载（`isLocalDriver`） |

升级后旧 blob 特征会被清理，需在控制面板重新录入。

## Polkit

系统服务调用 enroll/verify 可能需要授权。可参考仓库内  
`data/polkit/50-kiran-authentication-fprintd.rules`（若已安装）。

## 验证

见 `specs/003-fingerprint-fprintd/quickstart.md`。
