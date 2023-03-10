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

    QSharedPointer<DeviceAdaptor> getDeviceAdaptor(int32_t authType);
    QString getDeivcesForType(int32_t authType);
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
