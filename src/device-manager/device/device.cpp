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

#include <qt5-log-i.h>
#include <QUuid>

#include "auth_device_adaptor.h"
#include "device.h"

#define GENERAL_AUTH_DEVICE_DBUS_OBJECT_PATH "/com/kylinsec/Kiran/AuthDevice/Device"
#define GENERAL_AUTH_DEVICE_DBUS_INTERFACE_NAME "com.kylinsec.Kiran.AuthDevice.Device"

namespace Kiran
{
Device::Device(DriverPtr driver, QObject* parent) : QObject(parent),
                                                    m_driver(driver)
{
    QUuid uuid = QUuid::createUuid();
    m_devId = uuid.toString().remove(QChar('{')).remove(QChar('}')).remove(QChar('-')).toLower();

    m_dbusAdaptor = QSharedPointer<AuthDeviceAdaptor>(new AuthDeviceAdaptor(this));

    m_status = DEVICE_STATUS_IDLE;

    registerDBusObject();
    initServiceWatcher();
}

Device::~Device()
{
}

void Device::registerDBusObject()
{
    m_objectPath = QDBusObjectPath(QString("%1_%2").arg(GENERAL_AUTH_DEVICE_DBUS_OBJECT_PATH).arg(m_devId));
    QDBusConnection dbusConnection = QDBusConnection::systemBus();
    if (dbusConnection.registerObject(m_objectPath.path(),
                                      GENERAL_AUTH_DEVICE_DBUS_INTERFACE_NAME,
                                      this))
    {
        KLOG_INFO() << "register Object :" << m_objectPath.path();
    }
    else
    {
        KLOG_WARNING() << "Can't register object:" << dbusConnection.lastError();
    }
}

void Device::initServiceWatcher()
{
    m_serviceWatcher = QSharedPointer<QDBusServiceWatcher>(new QDBusServiceWatcher(this));
    this->m_serviceWatcher->setConnection(QDBusConnection::systemBus());
    this->m_serviceWatcher->setWatchMode(QDBusServiceWatcher::WatchForUnregistration);
    connect(m_serviceWatcher.data(), &QDBusServiceWatcher::serviceUnregistered, this, &Device::onNameLost);
}

void Device::onNameLost(const QString& serviceName)
{
    KLOG_DEBUG() << "NameLost: " << serviceName;
    this->m_serviceWatcher->removeWatchedService(serviceName);
    switch (deviceStatus())
    {
    case DEVICE_STATUS_DOING_ENROLL:
        EnrollStop();
        break;
    case DEVICE_STATUS_DOING_IDENTIFY:
        IdentifyStop();
        break;
    default:
        break;
    }
}

}  // namespace Kiran