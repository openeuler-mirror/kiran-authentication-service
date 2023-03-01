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
#include <QDBusContext>
#include <QDBusObjectPath>
#include <QList>
#include <QRandomGenerator>
#include "kas-authentication-i.h"

class AuthManagerAdaptor;
class QSettings;
class BiometricsProxy;
class QDBusServiceWatcher;

namespace Kiran
{
class Session;
class UserManager;
class AuthConfig;
class AuthManager : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_PROPERTY(int AuthMode READ getAuthMode)
    Q_PROPERTY(int MaxFailures READ getMaxFailures)
private:
    AuthManager(UserManager *userManager,AuthConfig* config);

public:
    virtual ~AuthManager(){};

    static AuthManager *getInstance() { return m_instance; };
    static void globalInit(UserManager *userManager,AuthConfig* auhtConfig);
    static void globalDeinit() { delete m_instance; };
    
    int getAuthMode();
    int getMaxFailures();

public Q_SLOTS:  // DBUS METHODS
    // 认证会话创建以及销毁
    QDBusObjectPath CreateSession(const QString &userName, int timeout,int authApp);
    void DestroySession(uint sessionID);

    // 获取认证服务中用户DBUS对象
    QDBusObjectPath FindUserByID(qulonglong uid);
    QDBusObjectPath FindUserByName(const QString &userName);
    
    // 获取认证设备
    QString GetDevicesForType(int authType);
    // 获取默认认证设备
    QString GetDefaultDeviceID(int authType);
    // 设置默认设备ID
    void SetDefaultDeviceID(int authType, const QString &deviceID);

    // 认证类型总开关
    bool GetAuthTypeEnabled(int authType);
    void SetAuthTypeEnabled(int authType,bool enabled);

    // 获取/设置指定认证场景下认证类型的开关
    bool GetAuthTypeEnabledForApp(int authType,int authApp);
    void SetAuthTypeEnabledForApp(int authType, int authApp, bool enabled);
    
    // 通过pam服务名查询属于哪个认证场景
    int QueryAuthApp(const QString &pamServiceName);
    // 通过指定的认证应用获取支持的认证类型,返回值为有序列表
    QList<int> GetAuthTypeByApp(int32_t authApp);

    void onNameLost(const QString &serviceName);

signals:
    void defaultDeviceChanged(int authType,const QString& deviceID,QPrivateSignal);

private:
    void init();
    // 生成一个唯一的会话ID
    int32_t generateSessionID();

private:
    static AuthManager *m_instance;
    AuthConfig *m_authConfig;
    UserManager *m_userManager;
    AuthManagerAdaptor *m_dbusAdaptor;

    // 结合其他信息生成的认证顺序
    QList<KADAuthType> m_authOrder;

    // <会话ID，会话>
    QMap<int32_t, Session *> m_sessions;
    QRandomGenerator m_randomGenerator;
    QDBusServiceWatcher *m_serviceWatcher;
};

}  // namespace Kiran
