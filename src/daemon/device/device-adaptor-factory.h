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

#pragma once

#include "src/daemon/device/device-adaptor.h"

class AuthDeviceManagerProxy;

namespace Kiran
{
class AuthManager;

// 设备适配器工厂
class DeviceAdaptorFactory : public QObject
{
    Q_OBJECT
private:
    DeviceAdaptorFactory(AuthManager *authManager);

public:
    virtual ~DeviceAdaptorFactory(){};

    static DeviceAdaptorFactory *getInstance() { return m_instance; };
    static void globalInit(AuthManager *authManager);
    static void globalDeinit() { delete m_instance; };

    // 获取设备适配器，可通过设备适配器接口进行录入以及认证
    QSharedPointer<DeviceAdaptor> getDeviceAdaptor(int32_t authType);

    // 获取认证类型下当前的设备信息，从认证设备服务中获取,以JSON格式提供,转发出去
    QString getDeivcesForType(int32_t authType);
    
    // 获取当前认证类型下所支持的所有驱动信息，从认证服务之中拿到，以JSON格式提供，转发出去
    QString getDriversForType(int32_t authType);
    bool deleteFeature(const QString& dataID);
    bool setDrivereEanbled(const QString& driverName,bool enabled);

private:
    void init();

private:
    QSharedPointer<DeviceAdaptor> createDeviceAdaptor(int32_t authType);
    QSharedPointer<AuthDeviceProxy> getDBusDeviceProxy(int authType, const QString &suggestDeviceID);

private slots:
    void onAuthDeviceManagerLost(const QString& service);
    void onDeviceDeleted(int deviceType, const QString &deviceID);
    void onDefaultDeviceChanged(int authType, const QString &deviceID);

private:
    static DeviceAdaptorFactory *m_instance;
    AuthManager *m_authManager;
    AuthDeviceManagerProxy *m_authDeviceManagerProxy;
    QMap<int32_t, QSharedPointer<DeviceAdaptor>> m_devices;
    QDBusServiceWatcher *m_serviceWatcher;
};

}  // namespace Kiran
