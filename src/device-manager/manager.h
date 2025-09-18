/**
 * Copyright (c) 2025 ~ 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     yangfeng <yangfeng@kylinsec.com.cn>
 */

#pragma once

#include <QDBusContext>
#include <QMap>
#include <QObject>
#include <QSharedPointer>

#include "device/device.h"
#include "driver-loader.h"
#include "udev-monitor.h"

class AuthDeviceManagerAdaptor;

namespace Kiran
{
class Manager : public QObject, protected QDBusContext
{
    Q_OBJECT

public:
    explicit Manager(QObject *parent = nullptr);
    virtual ~Manager();

    static Manager *getInstance() { return m_instance; };
    static void globalInit();
    static void globalDeint() { delete m_instance; };

    void init();

    bool genDevice(const QString &driverName, const QString &vendorId, const QString &productId, const QString &devNode);

    QString getOnlineDevicesInfo();                                               // 获取当前已上线设备信息（含远程设备）（json：type、name）
    QMap<QString, QVector<QPair<QString, QString>>> getPhysicalSupportDevices();  // 获取物理设备支持信息
    bool loadRemoteDevices();                                                     // 加载远程设备
    void udevAdded(const QString &vendorId,
                   const QString &productId,
                   const QString &devNode);  // udev发现本地设备
    void udevDeleted();
    // QStringList getDeviceIdsByType(int type);  // 通过设备类型获取设备id
    // QString getDeviceInfo(QString deviceId);   // 通过设备id获取设备信息（json：type、name）

    QString GetDevices();
    QString GetDevicesByType(int device_type);
    QDBusObjectPath GetDevice(const QString &device_id);
    QStringList GetAllFeatureIDs();
    QString GetDriversByType(int device_type);
    void SetEnableDriver(const QString &driver_name, bool enable);
    void Remove(const QString &feature_id);

private:
    static Manager *m_instance;
    QSharedPointer<AuthDeviceManagerAdaptor> m_dbusAdaptor;

    QMap<QString, DevicePtr> m_devices;  // key: dev uuid
    QSharedPointer<UdevMonitor> m_udevMonitor;
    QSharedPointer<DriverLoader> m_driverLoader;
    QMap<QString, QVector<QPair<QString, QString>>> m_physicalSupportDevices;  // key-driverName value-vid/pid

    QMap<QString, QVector<QPair<QString, QString>>> m_onlinePhysicalDevices;
};
}  // namespace Kiran