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
#include <biometrics-i.h>
#include "src/daemon/auth-manager.h"
#include "src/daemon/biometrics_proxy.h"
#include "src/daemon/device_proxy.h"

namespace Kiran
{
DeviceAdaptorFactory::DeviceAdaptorFactory(AuthManager *authManager) : m_authManager(authManager)
{
    this->m_biometricsProxy = new BiometricsProxy(BIOMETRICS_DBUS_NAME,
                                                  BIOMETRICS_DBUS_OBJECT_PATH,
                                                  QDBusConnection::systemBus(),
                                                  this);
}

DeviceAdaptorFactory *DeviceAdaptorFactory::m_instance = nullptr;
void DeviceAdaptorFactory::globalInit(AuthManager *authManager)
{
    m_instance = new DeviceAdaptorFactory(authManager);
    m_instance->init();
}

QSharedPointer<DeviceAdaptor> DeviceAdaptorFactory::getDeviceAdaptor(int32_t deviceType)
{
    auto device = this->m_devices.value(deviceType);
    RETURN_VAL_IF_TRUE(device, device);
    device = this->createDeviceAdaptor(deviceType);
    RETURN_VAL_IF_FALSE(device, QSharedPointer<DeviceAdaptor>());
    this->m_devices.insert(deviceType, device);
    return device;
}

void DeviceAdaptorFactory::init()
{
    connect(this->m_authManager, &AuthManager::DefaultDeviceChanged, this, &DeviceAdaptorFactory::onDefaultDeviceChanged);
}

QSharedPointer<DeviceAdaptor> DeviceAdaptorFactory::createDeviceAdaptor(int32_t deviceType)
{
    QSharedPointer<DeviceAdaptor> deviceAdaptor;

    if (!this->m_biometricsProxy)
    {
        KLOG_WARNING() << "The biometrics proxy is null.";
        return deviceAdaptor;
    }

    auto defaultDeviceID = this->m_authManager->GetDefaultDeviceID(deviceType);
    auto dbusDeviceProxy = this->getDBusDeviceProxy(deviceType, defaultDeviceID);
    if (dbusDeviceProxy)
    {
        deviceAdaptor = QSharedPointer<DeviceAdaptor>::create(dbusDeviceProxy);
    }
    return deviceAdaptor;
}

QSharedPointer<DeviceProxy> DeviceAdaptorFactory::getDBusDeviceProxy(int deviceType,
                                                                     const QString &suggestDeviceID)
{
    QSharedPointer<DeviceProxy> dbusDeviceProxy;

    auto suggestDeviceReply = this->m_biometricsProxy->GetDevice(deviceType, suggestDeviceID);
    auto deviceObjectPath = suggestDeviceReply.value();

    if (suggestDeviceReply.isError())
    {
        KLOG_DEBUG() << "Not found suggest fingerprint device: " << suggestDeviceReply.error().message();
    }

    // 如果未找到推荐设备，则随机选择一个
    if (suggestDeviceReply.isError() || deviceObjectPath.path().isEmpty())
    {
        KLOG_DEBUG("Prepare to randomly select a fingerprint device.");

        auto devicesReply = this->m_biometricsProxy->GetDevicesByType(deviceType);
        auto devicesJson = devicesReply.value();
        auto jsonDoc = QJsonDocument::fromJson(devicesJson.toUtf8());
        auto jsonArr = jsonDoc.array();
        if (jsonArr.size() > 0)
        {
            auto deviceID = jsonArr[0].toObject().value(QStringLiteral(BIOMETRICS_DJK_KEY_ID)).toString();
            auto deviceReply = this->m_biometricsProxy->GetDevice(deviceType, deviceID);
            deviceObjectPath = deviceReply.value();
        }
        else
        {
            KLOG_DEBUG() << "Not found available fingerprint device.";
        }
    }

    if (!deviceObjectPath.path().isEmpty())
    {
        dbusDeviceProxy = QSharedPointer<DeviceProxy>::create(BIOMETRICS_DBUS_NAME,
                                                              suggestDeviceReply.value().path(),
                                                              QDBusConnection::systemBus());

        KLOG_DEBUG() << "Use device " << dbusDeviceProxy->deviceID() << " as active device.";
    }
    else
    {
        KLOG_WARNING("Not found fingerprint device.");
    }
    return dbusDeviceProxy;
}

void DeviceAdaptorFactory::onDefaultDeviceChanged(int deviceType,
                                                  const QString &deviceID)
{
    auto deviceAdaptor = this->getDeviceAdaptor(deviceType);
    if (deviceAdaptor && deviceAdaptor->getDeviceID() != deviceID)
    {
        auto dbusDeviceProxy = this->getDBusDeviceProxy(deviceType, deviceID);
        deviceAdaptor->updateDBusDeviceProxy(dbusDeviceProxy);
    }
}
}  // namespace Kiran