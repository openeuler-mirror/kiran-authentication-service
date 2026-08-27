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

#include <algorithm>

#include <qt5-log-i.h>
#include <QSettings>

#include "adaptor/device.h"
#include "adaptor/face-device.h"
#include "adaptor/soft-code-device.h"
#include "adaptor/soft-code-no-camera-device.h"
#include "adaptor/soft-face-device.h"
#include "adaptor/ukey-device.h"
#include "auth_device_manager_adaptor.h"
#include "config.h"
#include "kas-authentication-i.h"
#include "lib/feature-db.h"
#include "manager.h"

namespace Kiran
{
namespace
{
/** KS 软认证类型按 KsWorkMode 位序排序：F → P → S → C */
int kiranWorkModeAuthTypeRank(int authType)
{
    switch (authType)
    {
    case KAD_AUTH_TYPE_SOFT_FACE:
        return 0;
    case KAD_AUTH_TYPE_PASSWORD:
        return 1;
    case KAD_AUTH_TYPE_SOFT_CODE_NO_CAMERA:
        return 2;
    case KAD_AUTH_TYPE_SOFT_CODE:
        return 3;
    default:
        return 100;
    }
}
}  // namespace

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

    // 驱动禁用状态（持久化）
    loadDisabledDrivers();

    // 软驱动，在程序启动时载入
    genSoftDevices();
    // 本地能力驱动（无 vid/pid 绑定，如本地人脸识别），在程序启动时载入
    genLocalDevices();
}

void Manager::loadDisabledDrivers()
{
    QSettings settings(QString(KAS_INSTALL_SYSCONFDIR) + "/kiran-authentication-devices.ini",
                       QSettings::IniFormat);
    const auto names = settings.value("DisabledDrivers/Names", QStringList()).toStringList();
    // Qt 5.6 无迭代器范围构造(需 Qt >= 5.14),改用 fromList
    m_disabledDrivers = QSet<QString>::fromList(names);
    KLOG_INFO() << "disabled drivers:" << m_disabledDrivers;
}

void Manager::saveDisabledDrivers()
{
    QSettings settings(QString(KAS_INSTALL_SYSCONFDIR) + "/kiran-authentication-devices.ini",
                       QSettings::IniFormat);
    settings.setValue("DisabledDrivers/Names", QStringList(m_disabledDrivers.values()));
    settings.sync();
}

QString Manager::genDevice(const QString& driverName, const QString& vendorId, const QString& productId, const QString& devNode)
{
    auto driver = m_driverLoader->loadDriver(driverName);
    if (!driver)
    {
        return QString();
    }
    // 驱动被禁用时不为热插拔设备创建设备对象
    if (m_disabledDrivers.contains(QString::fromStdString(driver->getDriverName())))
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
        if (driver &&
            !m_disabledDrivers.contains(QString::fromStdString(driver->getDriverName())))
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

bool Manager::genLocalDevices()
{
    QStringList localDrivers = m_driverLoader->getLocalDrivers();
    for (QString driverFile : localDrivers)
    {
        DriverPtr driver = m_driverLoader->loadDriver(driverFile);
        if (!driver ||
            m_disabledDrivers.contains(QString::fromStdString(driver->getDriverName())))
        {
            continue;
        }
        DevicePtr device;
        switch (driver->getType())
        {
        case DRIVER_TYPE_FACE:
            device = FaceDevicePtr(new FaceDevice(driver));
            break;
        default:
            KLOG_WARNING() << "unsupported local driver type:" << getDriverTypeStr(driver->getType())
                           << "file:" << driverFile;
            break;
        }
        if (device)
        {
            m_devices.insert(device->deviceID(), device);
        }
    }
    KLOG_INFO() << "gen Local Devices result:";
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

    // 物理驱动(udev 硬件)与本地驱动(无 vid/pid 绑定,如本地人脸识别)
    auto driverInfos = m_driverLoader->getPhysicalDriverInfos();
    auto localDriverInfos = m_driverLoader->getLocalDriverInfos();
    for (auto& driverInfo : driverInfos)
    {
        if (driverInfo.type == deviceType)
        {
            QJsonObject jsonObj{
                {"driverName", driverInfo.name},
                {"enable", !m_disabledDrivers.contains(driverInfo.name)}};
            jsonArray.append(jsonObj);
        }
    }
    for (auto& driverInfo : localDriverInfos)
    {
        if (driverInfo.type == deviceType)
        {
            QJsonObject jsonObj{
                {"driverName", driverInfo.name},
                {"enable", !m_disabledDrivers.contains(driverInfo.name)}};
            jsonArray.append(jsonObj);
        }
    }
    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

void Manager::SetEnableDriver(const QString& driverName, bool enable)
{
    KLOG_INFO() << "SetEnableDriver:" << driverName << "enable:" << enable;

    if (enable)
    {
        m_disabledDrivers.remove(driverName);
    }
    else
    {
        m_disabledDrivers.insert(driverName);
    }
    saveDisabledDrivers();

    // 即时生效:禁用时移除该驱动的在线设备并通知 daemon;
    // 启用时若为本地/软驱动则立即创建设备(daemon 在下次查询时感知)
    auto iter = m_devices.begin();
    while (iter != m_devices.end())
    {
        auto device = iter.value();
        if (device->driverName() == driverName)
        {
            if (enable)
            {
                ++iter;
                continue;
            }
            const QString deviceID = device->deviceID();
            const int deviceType = device->deviceType();
            KLOG_INFO() << "SetEnableDriver remove device:" << deviceID;
            // 先请求停止;驱动调用工作线程不捕获设备(this),结果经
            // QFuture 返回,可安全地立即注销 D-Bus 对象并释放设备
            device->EnrollStop();
            device->IdentifyStop();
            QDBusConnection::systemBus().unregisterObject(device->getObjectPath().path());
            iter = m_devices.erase(iter);
            Q_EMIT m_dbusAdaptor->DeviceDeleted(deviceType, deviceID);
            continue;
        }
        ++iter;
    }

    if (enable)
    {
        // 重新装载被启用的本地/软驱动
        auto createForFile = [this, driverName](const QString &driverFile)
        {
            DriverPtr driver = m_driverLoader->loadDriver(driverFile);
            if (!driver || QString::fromStdString(driver->getDriverName()) != driverName)
            {
                return;
            }
            DevicePtr device;
            if (DRIVER_TYPE_SOFT == driver->getType())
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
            else if (DRIVER_TYPE_FACE == driver->getType())
            {
                device = FaceDevicePtr(new FaceDevice(driver));
            }
            if (device)
            {
                const QString deviceID = device->deviceID();
                m_devices.insert(deviceID, device);
                KLOG_INFO() << "SetEnableDriver create device:" << deviceID;
                Q_EMIT m_dbusAdaptor->DeviceAdded(device->deviceType(), deviceID);
            }
        };
        for (const auto &driverFile : m_driverLoader->getLocalDrivers())
        {
            createForFile(driverFile);
        }
        for (const auto &driverFile : m_driverLoader->getSoftDrivers())
        {
            createForFile(driverFile);
        }
    }
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

    std::sort(authTypes.begin(), authTypes.end(), [](int a, int b)
              {
        const int rankA = kiranWorkModeAuthTypeRank(a);
        const int rankB = kiranWorkModeAuthTypeRank(b);
        if (rankA != rankB)
        {
            return rankA < rankB;
        }
        return a < b; });

    QJsonArray jsonArray;
    for (int type : authTypes)
        jsonArray.append(type);
    QJsonDocument jsonDoc(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

}  // namespace Kiran
