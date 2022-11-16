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

class BiometricsProxy;

namespace Kiran
{
class AuthManager;

class DeviceAdaptorFactory : public QObject
{
    Q_OBJECT
public:
    DeviceAdaptorFactory(AuthManager *authManager);
    virtual ~DeviceAdaptorFactory(){};

    static DeviceAdaptorFactory *getInstance() { return m_instance; };

    static void globalInit(AuthManager *authManager);

    static void globalDeinit() { delete m_instance; };

    QSharedPointer<DeviceAdaptor> getDeviceAdaptor(int32_t deviceType);

private:
    void init();

private:
    QSharedPointer<DeviceAdaptor> createDeviceAdaptor(int32_t deviceType);
    QSharedPointer<DeviceProxy> getDBusDeviceProxy(int deviceType, const QString &suggestDeviceID);
    void onDefaultDeviceChanged(int deviceType, const QString &deviceID);

private:
    static DeviceAdaptorFactory *m_instance;
    AuthManager *m_authManager;
    BiometricsProxy *m_biometricsProxy;
    QMap<int32_t, QSharedPointer<DeviceAdaptor>> m_devices;
};

}  // namespace Kiran
