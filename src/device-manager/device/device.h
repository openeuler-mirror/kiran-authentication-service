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
#include <QDBusObjectPath>
#include <QDBusServiceWatcher>
#include <QFutureWatcher>
#include <QObject>
#include <QSharedPointer>

#include "driver/driver.h"
#include "kas-authentication-i.h"
#include "lib/feature-data.h"  // for dbus xml

class AuthDeviceAdaptor;

namespace Kiran
{
typedef void *Handle;
class Device : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_PROPERTY(QString DeviceID READ deviceID CONSTANT)
    Q_PROPERTY(QString DeviceDriver READ driverName CONSTANT)
    Q_PROPERTY(int DeviceType READ deviceType)
    Q_PROPERTY(int DeviceStatus READ deviceStatus)
public:
    explicit Device(DriverPtr driver, QObject *parent = nullptr);
    virtual ~Device();

    virtual DeviceType deviceType() = 0;
    QString driverName() { return m_driver->getDriverName(); }
    QDBusObjectPath getObjectPath() { return m_objectPath; };

    QString deviceID() { return m_devId; };
    virtual void EnrollStart(const QString &extraInfo) = 0;
    virtual void EnrollStop() = 0;
    virtual void IdentifyStart(const QString &extraInfo) = 0;
    virtual void IdentifyStop() = 0;
    virtual QStringList GetFeatureIDList() = 0;
    int deviceStatus() { return m_status; };

    virtual void IdentifySuccessedPostProcess(const QString &extraInfo){};

    // signals:
    //     void identifyStatus(IdentifyStatus status, QString msg);
    //     void enrollStatus(EnrollStatus status, QString msg);

private:
    void registerDBusObject();
    void initServiceWatcher();
private Q_SLOTS:
    void onNameLost(const QString &serviceName);

public:
    QString m_devId;
    DriverPtr m_driver;
    int m_status;

    QSharedPointer<AuthDeviceAdaptor> m_dbusAdaptor;
    QDBusObjectPath m_objectPath;
    QSharedPointer<QDBusServiceWatcher> m_serviceWatcher;
};

typedef QSharedPointer<Device> DevicePtr;

}  // namespace Kiran