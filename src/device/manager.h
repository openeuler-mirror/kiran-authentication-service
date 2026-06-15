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

#include "adaptor/device.h"
#include "loader/driver-loader.h"
#include "loader/udev-monitor.h"

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

    QString genDevice(const QString &driverName, const QString &vendorId, const QString &productId, const QString &devNode);
    bool genVirtualDevices();

    QString getOnlineDevicesInfo();                                               // 获取当前已上线设备信息（含远程设备）（json：type、name）
    QMap<QString, QVector<QPair<QString, QString>>> getPhysicalSupportDevices();  // 获取物理设备支持信息
    bool loadRemoteDevices();                                                     // 加载远程设备
    void onDeviceAdded(const QString &vendorId,
                       const QString &productId,
                       const QString &devNode);
    void onDeviceDeleted(const QString &devNode);

    QString GetDevices();
    QString GetDevicesByType(int deviceType);
    QDBusObjectPath GetDevice(const QString &deviceId);
    QStringList GetAllFeatureIDs();
    QString GetDriversByType(int deviceType);
    void SetEnableDriver(const QString &driverName, bool enable);
    void Remove(const QString &featureId);
    QString GetSupportedAuthTypes();

private:
    static Manager *m_instance;
    QSharedPointer<AuthDeviceManagerAdaptor> m_dbusAdaptor;

    QMap<QString, DevicePtr> m_devices;  // key: dev uuid
    QSharedPointer<UdevMonitor> m_udevMonitor;
    QSharedPointer<DriverLoader> m_driverLoader;

    QMap<QString, QString> m_onlineDevices;  // key=devNode(busPath), value=deviceID(UUID)
};
}  // namespace Kiran