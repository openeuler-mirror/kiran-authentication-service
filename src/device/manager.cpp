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

#include "adaptor/device.h"
#include "adaptor/soft-code-device.h"
#include "adaptor/soft-code-no-camera-device.h"
#include "adaptor/soft-face-device.h"
#include "adaptor/ukey-device.h"
#include "auth_device_manager_adaptor.h"
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

    // 程序启动时，udev已经检测到设备，手动枚举已连接的 USB 设备
    struct udev* udev = udev_new();
    struct udev_enumerate* enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, "usb");
    udev_enumerate_scan_devices(enumerate);
    struct udev_list_entry* devices = udev_enumerate_get_list_entry(enumerate);
    struct udev_list_entry* entry;
    udev_list_entry_foreach(entry, devices)
    {
        const char* syspath = udev_list_entry_get_name(entry);
        struct udev_device* dev = udev_device_new_from_syspath(udev, syspath);

        QString idVendor = udev_device_get_sysattr_value(dev, "idVendor");
        QString idProduct = udev_device_get_sysattr_value(dev, "idProduct");
        QString devNode = udev_device_get_devnode(dev);

        if (!devNode.isEmpty())
        {
            onDeviceAdded(idVendor, idProduct, devNode);
        }
        udev_device_unref(dev);
    }
    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    // udev监控
    m_udevMonitor = QSharedPointer<UdevMonitor>(new UdevMonitor());
    connect(m_udevMonitor.data(), &UdevMonitor::deviceAdded, this, &Manager::onDeviceAdded);
    connect(m_udevMonitor.data(), &UdevMonitor::deviceDeleted, this, &Manager::onDeviceDeleted);

    // 软驱动，在程序启动时载入
    genSoftDevices();
}

QString Manager::genDevice(const QString& driverName, const QString& vendorId, const QString& productId, const QString& devNode)
{
    auto driver = m_driverLoader->loadDriver(driverName);
    if (!driver)
    {
        return QString();
    }

    // TODO: 创建设备
    switch (driver->getType())
    {
    case DRIVER_TYPE_UKEY:
    {
        auto device = UkeyDevicePtr(new UkeyDevice(vendorId,
                                                   productId,
                                                   driver));
        if (!device)
        {
            return QString();
        }
        QString deviceID = device->deviceID();
        m_devices.insert(deviceID, device);
        return deviceID;
    }

    case DRIVER_TYPE_FINGERPRINT:
    case DRIVER_TYPE_FACE:
    case DRIVER_TYPE_FINGERVEIN:
    case DRIVER_TYPE_IRIS:
    case DRIVER_TYPE_VOICEPRINT:
    case DRIVER_TYPE_SOFT:
    default:
    {
        break;
    }
    }

    return QString();
}

bool Manager::genSoftDevices()
{
    QStringList softDrivers = m_driverLoader->getSoftDrivers();
    for (QString driverName : softDrivers)
    {
        DriverPtr driver = m_driverLoader->loadDriver(driverName);
        if (driver)
        {
            DevicePtr device;
            if (driver->getType() == DRIVER_TYPE_SOFT)
            {
                switch (driver->getSoftType())
                {
                case SOFT_DRIVER_TYPE_FACE:
                    device = SoftFaceDevicePtr(new SoftFaceDevice(driver));
                    break;
                case SOFT_DRIVER_TYPE_CODE:
                    device = SoftCodeDevicePtr(new SoftCodeDevice(driver));
                    break;
                case SOFT_DRIVER_TYPE_CODE_NO_CAMERA:
                    device = SoftCodeNoCameraDevicePtr(new SoftCodeNoCameraDevice(driver));
                    break;
                default:
                    break;
                }
            }
            if (device)
            {
                m_devices.insert(device->deviceID(), device);
            }
        }
    }
    KLOG_INFO() << "gen Soft Devices result: ";
    for (auto device : m_devices)
    {
        KLOG_INFO() << device->driverName() << device->deviceType() << device->deviceID();
    }

    return true;
}

QString Manager::getOnlineDevicesInfo()
{
    return QString();
}

QMap<QString, QVector<QPair<QString, QString>>> Manager::getPhysicalSupportDevices()
{
    return m_driverLoader->getPhysicalSupportDevices();
}

bool Manager::loadRemoteDevices()
{
    return false;
}

void Manager::onDeviceAdded(const QString& vendorId, const QString& productId, const QString& devNode)
{
    auto supportDevices = m_driverLoader->getPhysicalSupportDevices();
    auto iter = supportDevices.begin();
    for (; iter != supportDevices.end(); iter++)
    {
        auto& devices = iter.value();
        for (auto& device : devices)
        {
            if (device.first == vendorId && device.second == productId)
            {
                KLOG_INFO() << "device detected: " << vendorId << productId << iter.key();
                QString deviceID = genDevice(iter.key(), vendorId, productId, devNode);
                if (!deviceID.isEmpty())
                {
                    m_onlineDevices[devNode] = deviceID;
                }
                return;
            }
        }
    }
}

void Manager::onDeviceDeleted(const QString& devNode)
{
    auto it = m_onlineDevices.find(devNode);
    if (it == m_onlineDevices.end())
    {
        KLOG_WARNING() << "Unknown device removed:" << devNode;
        return;
    }

    QString deviceID = it.value();
    m_onlineDevices.erase(it);

    if (m_devices.contains(deviceID))
    {
        m_devices.remove(deviceID);
    }

    KLOG_INFO() << "device removed:" << devNode << "deviceID:" << deviceID;
}

QString Manager::GetDevices()
{
    auto devices = m_devices.values();
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;
    for (auto& device : devices)
    {
        QJsonObject jsonObj{
            {"deviceType", device->deviceType()},
            {"softDeviceType", (int)device->softDeviceType()},
            {"deviceName", device->driverName()},
            {"deviceID", device->deviceID()},
            {"objectPath", device->getObjectPath().path()}};
        jsonArray.append(jsonObj);
    }

    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

QString Manager::GetDevicesByType(int deviceType)
{
    auto devices = m_devices.values();
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;
    for (auto& device : devices)
    {
        if (device->deviceType() == deviceType)
        {
            QJsonObject jsonObj{
                {"deviceName", device->driverName()},
                {"deviceID", device->deviceID()},
                {"objectPath", device->getObjectPath().path()},
                {"softDeviceType", (int)device->softDeviceType()}};
            jsonArray.append(jsonObj);
        }
    }
    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

QDBusObjectPath Manager::GetDevice(const QString& deviceId)
{
    QDBusObjectPath objectPath;
    if (m_devices.contains(deviceId))
    {
        objectPath = m_devices.value(deviceId)->getObjectPath();
    }
    return objectPath;
}

QStringList Manager::GetAllFeatureIDs()
{
    return QStringList();
}

QString Manager::GetDriversByType(int deviceType)
{
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;

    auto driverInfos = m_driverLoader->getPhysicalDriverInfos();
    for (auto& driverInfo : driverInfos)
    {
        if (driverInfo.type == deviceType)
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

void Manager::SetEnableDriver(const QString& driverName, bool enable)
{
}

void Manager::Remove(const QString& featureId)
{
    // FeatureData featureData = FeatureDB::getInstance()->getFeatureData(featureId);
    bool result = FeatureDB::getInstance()->deleteFeature(featureId);

    // NOTE: 是否需要重置ukey设备
}

QString Manager::GetSupportedAuthTypes()
{
    QList<int> authTypes;
    for (auto device : m_devices)
    {
        if (device && device->m_driver)
        {
            std::vector<int> driverTypes = device->m_driver->getSupportedAuthTypes();
            for (int type : driverTypes)
            {
                if (!authTypes.contains(type))
                {
                    authTypes << type;
                }
            }
        }
    }

    QJsonArray jsonArray;
    for (int type : authTypes)
        jsonArray.append(type);
    QJsonDocument jsonDoc(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

}  // namespace Kiran
