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

#include "auth_device_manager_adaptor.h"
#include "device/device.h"
#include "device/ukey-device.h"
#include "device/virtual-face-device.h"
#include "kas-authentication-i.h"
#include "lib/feature-db.h"
#include "manager.h"

namespace Kiran
{
Manager* Manager::m_instance = nullptr;

Manager::Manager(QObject* parent) : QObject(parent)
{
}

Manager::~Manager()
{
}

void Manager::globalInit()
{
    m_instance = new Manager();
    m_instance->init();
}

void Manager::init()
{
    // dbus 注册
    m_dbusAdaptor = QSharedPointer<AuthDeviceManagerAdaptor>(new AuthDeviceManagerAdaptor(this));
    QDBusConnection dbusConnection = QDBusConnection::systemBus();
    if (!dbusConnection.registerService(AUTH_DEVICE_DBUS_NAME))
    {
        KLOG_ERROR() << "register Service error:" << dbusConnection.lastError().message();
    }
    else
    {
        if (dbusConnection.registerObject(AUTH_DEVICE_DBUS_OBJECT_PATH,
                                          AUTH_DEVICE_DBUS_INTERFACE_NAME,
                                          this))
        {
            KLOG_DEBUG() << "register Object:" << AUTH_DEVICE_DBUS_OBJECT_PATH;
        }
        else
        {
            KLOG_ERROR() << "Can't register object:" << dbusConnection.lastError();
        }
    }

    // 驱动载入
    m_driverLoader = QSharedPointer<DriverLoader>(new DriverLoader());
    m_physicalSupportDevices = m_driverLoader->getPhysicalSupportDevices();

    // 程序启动时，udev已经检测到设备，需要手动触发一次
    auto usbInfoList = UdevMonitor::enumerateDevices();
    for (auto deviceInfo : usbInfoList)
    {
        udevAdded(deviceInfo.idVendor, deviceInfo.idProduct, deviceInfo.busPath);
    }

    // udev监控
    m_udevMonitor = QSharedPointer<UdevMonitor>(new UdevMonitor());
    connect(m_udevMonitor.data(), &UdevMonitor::deviceAdded, this, &Manager::udevAdded);
    connect(m_udevMonitor.data(), &UdevMonitor::deviceDeleted, this, &Manager::udevDeleted);

    // 虚拟驱动，在程序启动时载入
    genVirtualDevices();
}

bool Manager::genDevice(const QString& driverName, const QString& vendorId, const QString& productId, const QString& devNode)
{
    auto driver = m_driverLoader->loadDriver(driverName);
    if (driver)
    {
        // TODO: 创建设备
        switch (driver->getType())
        {
        case DRIVER_TYPE_UKey:  // ukey
        {
            auto device = UkeyDevicePtr(new UkeyDevice(vendorId,
                                                       productId,
                                                       driver));
            if (!device)
            {
                return false;
            }
            m_devices.insert(device->deviceID(), device);
            break;
        }

        case DRIVER_TYPE_FingerPrint:  // 指纹
        case DRIVER_TYPE_Face:         // 人脸
        case DRIVER_TYPE_FingerVein:   // 指静脉
        case DRIVER_TYPE_Iris:         // 虹膜
        case DRIVER_TYPE_VoicePrint:   // 声纹
        case DRIVER_TYPE_Virtual_Face: // 虚拟人脸
        default:
        {
            break;
        }
        }
    }

    return true;
}

bool Manager::genVirtualDevices()
{
    KLOG_INFO() << "genVirtualDevices";

    QStringList virtualDrivers = m_driverLoader->getVirualDrivers();
    for (QString driverName : virtualDrivers)
    {
        KLOG_INFO() << "gen Virtual Devices: " << driverName;
        DriverPtr driver = m_driverLoader->loadDriver(driverName);
        if (driver)
        {
            VirtualFaceDevicePtr device = VirtualFaceDevicePtr(new VirtualFaceDevice(driver));
            if (device)
            {
                m_devices.insert(device->deviceID(), device);
            }
        }
    }
    return true;
}

QString Manager::getOnlineDevicesInfo()
{
    return QString();
}

QMap<QString, QVector<QPair<QString, QString>>> Manager::getPhysicalSupportDevices()
{
    return m_physicalSupportDevices;
}

bool Manager::loadRemoteDevices()
{
    return false;
}

void Manager::udevAdded(const QString& vendorId, const QString& productId, const QString& devNode)
{
    // KLOG_INFO() << "device detected: " << vendorId << productId << devNode;

    auto iter = m_physicalSupportDevices.begin();
    for (; iter != m_physicalSupportDevices.end(); iter++)
    {
        auto& devices = iter.value();
        for (auto& device : devices)
        {
            if (device.first == vendorId && device.second == productId)
            {
                KLOG_INFO() << "device detected: " << vendorId << productId << iter.key();
                genDevice(iter.key(), vendorId, productId, devNode);

                return;
            }
        }
    }
}

void Manager::udevDeleted()
{
    QList<DeviceInfo> newUsbInfoList = UdevMonitor::enumerateDevices();
    QStringList newBusList;
    Q_FOREACH (auto newUsbInfo, newUsbInfoList)
    {
        newBusList << newUsbInfo.busPath;
    }

    QStringList oldBusList = m_onlinePhysicalDevices.keys();
    QString deviceID;
    int deviceType;
    Q_FOREACH (auto busPath, oldBusList)
    {
        if (newBusList.contains(busPath))
        {
            continue;
        }
        KLOG_INFO() << "device removed:" << busPath;

        // AuthDevicePtr oldAuthDevice = m_deviceMap.value(busPath);
        // deviceID = oldAuthDevice->deviceID();
        // deviceType = oldAuthDevice->deviceType();
        // int removeCount = m_deviceMap.remove(busPath);

        // Q_EMIT m_dbusAdaptor->DeviceDeleted(deviceType, deviceID);

        // QMapIterator<DeviceInfo, int> i(m_retreyCreateDeviceMap);
        // while (i.hasNext())
        // {
        //     i.next();
        //     if (i.key().busPath == busPath)
        //     {
        //         m_retreyCreateDeviceMap.remove(i.key());
        //     }
        // }
        // KLOG_DEBUG() << QString("device delete: bus:%1 deviceID:%2 deviceType:%3").arg(busPath).arg(deviceID).arg(deviceType);
        // break;
    }
}

// QStringList Manager::getDeviceIdsByType(int type)
// {
//     return QStringList();
// }

// QString Manager::getDeviceInfo(QString deviceId)
// {
//     return QString();
// }

QString Manager::GetDevices()
{
    auto devices = m_devices.values();
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;
    for (auto& device : devices)
    {
        QJsonObject jsonObj{
            {"deviceType", device->deviceType()},
            {"deviceName", device->driverName()},
            {"deviceID", device->deviceID()},
            {"objectPath", device->getObjectPath().path()}};
        jsonArray.append(jsonObj);
    }

    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

QString Manager::GetDevicesByType(int device_type)
{
    auto devices = m_devices.values();
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;
    for (auto& device : devices)
    {
        if (device->deviceType() == device_type)
        {
            QJsonObject jsonObj{
                {"deviceName", device->driverName()},
                {"deviceID", device->deviceID()},
                {"objectPath", device->getObjectPath().path()}};
            jsonArray.append(jsonObj);
        }
    }
    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

QDBusObjectPath Manager::GetDevice(const QString& device_id)
{
    QDBusObjectPath objectPath;
    if (m_devices.contains(device_id))
    {
        objectPath = m_devices.value(device_id)->getObjectPath();
    }
    return objectPath;
}

QStringList Manager::GetAllFeatureIDs()
{
    return QStringList();
}

QString Manager::GetDriversByType(int device_type)
{
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;

    auto driverInfos = m_driverLoader->getPhysicalDriverInfos();
    for (auto& driverInfo : driverInfos)
    {
        if (driverInfo.type == device_type)
        {
            QJsonObject jsonObj{
                {"driverName", driverInfo.name},
                {"enable", true}};
            jsonArray.append(jsonObj);
        }
    }
    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

void Manager::SetEnableDriver(const QString& driver_name, bool enable)
{
}

void Manager::Remove(const QString& feature_id)
{
    // FeatureData featureData = FeatureDB::getInstance()->getFeatureData(feature_id);
    bool result = FeatureDB::getInstance()->deleteFeature(feature_id);

    // NOTE: 是否需要重置ukey设备
}

}  // namespace Kiran
