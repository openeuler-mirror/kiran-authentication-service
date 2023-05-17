/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-session-manager is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     tangjie02 <tangjie02@kylinos.com.cn>
 */

#include "src/daemon/device/device-adaptor-factory.h"
#include <auxiliary.h>
#include <kiran-authentication-devices/kiran-auth-device-i.h>
#include <QString>
#include "json/auth-device.h"
#include "src/daemon/auth-manager.h"
#include "src/daemon/auth_device_manager_proxy.h"
#include "src/daemon/auth_device_proxy.h"
#include "src/utils/utils.h"

namespace Kiran
{
DeviceAdaptorFactory::DeviceAdaptorFactory(AuthManager *authManager) : m_authManager(authManager)
{
    this->m_authDeviceManagerProxy = new AuthDeviceManagerProxy(AUTH_DEVICE_DBUS_NAME,
                                                                AUTH_DEVICE_DBUS_OBJECT_PATH,
                                                                QDBusConnection::systemBus(),
                                                                this);

    this->m_serviceWatcher = new QDBusServiceWatcher(this);
}

DeviceAdaptorFactory *DeviceAdaptorFactory::m_instance = nullptr;
void DeviceAdaptorFactory::globalInit(AuthManager *authManager)
{
    m_instance = new DeviceAdaptorFactory(authManager);
    m_instance->init();
}

QSharedPointer<DeviceAdaptor> DeviceAdaptorFactory::getDeviceAdaptor(int32_t authType)
{
    auto device = this->m_devices.value(authType);
    RETURN_VAL_IF_TRUE(device, device);
    device = this->createDeviceAdaptor(authType);
    RETURN_VAL_IF_FALSE(device, QSharedPointer<DeviceAdaptor>());
    KLOG_DEBUG() << "authtype:" << authType << "create device adaptor:" << device->getDeviceID();
    this->m_devices.insert(authType, device);
    return device;
}

QString DeviceAdaptorFactory::getDeivcesForType(int32_t authType)
{
    if (!this->m_authDeviceManagerProxy)
    {
        KLOG_WARNING() << "auth device manager proxy is null.";
        return "";
    }

    QString devicesInfo = m_authDeviceManagerProxy->GetDevicesByType(Utils::authType2DeviceType(authType));
    return devicesInfo;
}

QString DeviceAdaptorFactory::getDriversForType(int32_t authType)
{
    if(!this->m_authDeviceManagerProxy)
    {
        KLOG_WARNING() << "auth device manager proxy is null.";
        return "";
    }

    QString driverInfo = m_authDeviceManagerProxy->GetDriversByType(Utils::authType2DeviceType(authType));
    return driverInfo;    
}

bool DeviceAdaptorFactory::setDrivereEanbled(const QString& driverName,bool enabled)
{
    if(!this->m_authDeviceManagerProxy)
    {
        KLOG_WARNING() << "auth device manager proxy is null.";
        return false;
    }

    auto reply = m_authDeviceManagerProxy->SetEnableDriver(driverName,enabled);
    reply.waitForFinished();
    return reply.isError()?false:true;
}

void DeviceAdaptorFactory::init()
{
    this->m_serviceWatcher->setConnection(QDBusConnection::systemBus());
    this->m_serviceWatcher->setWatchMode(QDBusServiceWatcher::WatchForUnregistration);
    this->m_serviceWatcher->addWatchedService(AUTH_DEVICE_DBUS_NAME);

    connect(this->m_serviceWatcher, &QDBusServiceWatcher::serviceUnregistered, this, &DeviceAdaptorFactory::onAuthDeviceManagerLost);
    connect(this->m_authManager, &AuthManager::defaultDeviceChanged, this, &DeviceAdaptorFactory::onDefaultDeviceChanged);
    connect(this->m_authDeviceManagerProxy, &AuthDeviceManagerProxy::DeviceDeleted, this, &DeviceAdaptorFactory::onDeviceDeleted);
}

bool DeviceAdaptorFactory::deleteFeature(const QString& dataID)
{
    auto reply = m_authDeviceManagerProxy->Remove(dataID);
    reply.waitForFinished();

    if(reply.isError() )
    {
        KLOG_WARNING() << "delete feature" << dataID << "failed," << reply.error().message();
        return false;
    }

    return true;
}

QSharedPointer<DeviceAdaptor> DeviceAdaptorFactory::createDeviceAdaptor(int32_t authType)
{
    QSharedPointer<DeviceAdaptor> deviceAdaptor;

    if (!this->m_authDeviceManagerProxy)
    {
        KLOG_WARNING() << "The biometrics proxy is null.";
        return deviceAdaptor;
    }

    auto defaultDeviceID = this->m_authManager->GetDefaultDeviceID(authType);
    auto dbusDeviceProxy = this->getDBusDeviceProxy(authType, defaultDeviceID);
    if (dbusDeviceProxy)
    {
        deviceAdaptor = QSharedPointer<DeviceAdaptor>::create(dbusDeviceProxy);
    }
    return deviceAdaptor;
}

QSharedPointer<AuthDeviceProxy> DeviceAdaptorFactory::getDBusDeviceProxy(int authType,
                                                                         const QString &suggestDeviceID)
{
    QDBusObjectPath deviceObjectPath;
    QSharedPointer<AuthDeviceProxy> dbusDeviceProxy;

    // 尝试获取默认设备
    if (!suggestDeviceID.isEmpty())
    {
        deviceObjectPath = this->m_authDeviceManagerProxy->GetDevice(suggestDeviceID);
        if (deviceObjectPath.path().isEmpty())
        {
            KLOG_DEBUG() << "Not found suggest auth device: " << suggestDeviceID;
        }
    }

    // 如果未找到推荐设备，则随机选择一个
    if (deviceObjectPath.path().isEmpty())
    {
        KLOG_DEBUG() << "Prepare to randomly select a auth device." << Utils::authType2DeviceType(authType);
        QString devicesJson = this->m_authDeviceManagerProxy->GetDevicesByType(Utils::authType2DeviceType(authType));
        auto devices = authDevicesfromJson(devicesJson);
        if (!devices.isEmpty())
        {
            auto randomDevice = devices.at(0);
            KLOG_DEBUG() << "Found auth device:" << randomDevice.id() << randomDevice.name() << randomDevice.objectPath();
            deviceObjectPath.setPath(randomDevice.objectPath());
        }
        else
        {
            KLOG_DEBUG("Not found available %s device.",Utils::authTypeEnum2Str(authType).toStdString().c_str());
        }
    }

    if (!deviceObjectPath.path().isEmpty())
    {
        dbusDeviceProxy = QSharedPointer<AuthDeviceProxy>::create(AUTH_DEVICE_DBUS_NAME,
                                                                  deviceObjectPath.path(),
                                                                  QDBusConnection::systemBus());
        KLOG_DEBUG() << "Use device " << dbusDeviceProxy->deviceID() << " as active device.";
    }
    else
    {
        KLOG_DEBUG("Not found %s device.",Utils::authTypeEnum2Str(authType).toStdString().c_str());
    }

    return dbusDeviceProxy;
}

void DeviceAdaptorFactory::onDefaultDeviceChanged(int authType,
                                                  const QString &deviceID)
{
    auto deviceAdaptor = this->getDeviceAdaptor(authType);
    if (deviceAdaptor && deviceAdaptor->getDeviceID() != deviceID)
    {
        auto dbusDeviceProxy = this->getDBusDeviceProxy(authType, deviceID);
        deviceAdaptor->updateDBusDeviceProxy(dbusDeviceProxy);
    }
}

void DeviceAdaptorFactory::onAuthDeviceManagerLost(const QString &service)
{
    // 设备管理服务消失，认证设备无效，应清理所有无效的设备及其请求
    for (auto iter = m_devices.begin(); iter != m_devices.end();)
    {
        KLOG_DEBUG() << "auth device manager lost,remove device:" << iter->get()->getDeviceID();
        iter->get()->removeAllRequest();
        iter = m_devices.erase(iter);
    }
}

void DeviceAdaptorFactory::onDeviceDeleted(int deviceType, const QString &deviceID)
{
    // 认证设备拔出，认证设备变成无效，清理该设备下请求，从缓存中删除该设备
    for (auto iter = m_devices.begin(); iter != m_devices.end(); iter++)
    {
        if (iter->get()->getDeviceID() == deviceID)
        {
            KLOG_DEBUG() << "auth device deleted,remove device:" << iter->get()->getDeviceID();
            iter->get()->removeAllRequest();
            m_devices.erase(iter);
            break;
        }
    }
}
}  // namespace Kiran