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
#if (QT_VERSION >= QT_VERSION_CHECK(5, 10, 0))
#include <QRandomGenerator>
#endif
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
    /// normal
    // 获取认证服务中用户DBUS对象
    QDBusObjectPath FindUserByID(qulonglong uid);
    QDBusObjectPath FindUserByName(const QString &userName);

    // 认证会话创建以及销毁
    QDBusObjectPath CreateSession(const QString &userName, int timeout,int authApp);
    void DestroySession(uint sessionID);

    // 根据认证类型获取驱动列表
    QString GetDriversForType(int authType);

    // 根据认证类型获取设备列表
    QString GetDevicesForType(int authType);

    // 获取认证类型是否启用
    bool GetAuthTypeEnabled(int authType);

    // 获取认证类型认证场景(认证应用)是否启用
    bool GetAuthTypeEnabledForApp(int authType,int authApp);

    // 默认设备
    QString GetDefaultDeviceID(int authType);
    void SetDefaultDeviceID(int authType, const QString &deviceID);
    
    // 通过pam服务名查询属于哪个认证场景
    // 例如:
    // lightdm->KAD_AUTH_APPLICATION_LOGIN,
    // iran-screensaver->KAD_AUTH_APPLICATION_UNLOCK
    int QueryAuthApp(const QString &pamServiceName);

    // 通过指定的认证应用获取支持的认证类型,返回值为有序列表
    QList<int> GetAuthTypeByApp(int32_t authApp);

    void onNameLost(const QString &serviceName);

    // root
    // 设备驱动控制
    void SetDrivereEnabled(const QString& driverName,bool enabled);

    // 认证类型总开关
    void SetAuthTypeEnabled(int authType,bool enabled);
    
    // 获取/设置指定认证场景下认证类型的开关
    void SetAuthTypeEnabledForApp(int authType, int authApp, bool enabled);

signals:
    void defaultDeviceChanged(int authType,const QString& deviceID,QPrivateSignal);

private:
    void init();
    // 需要管理员权限
    QString calcAction(const QString &originAction);
    // 生成一个唯一的会话ID
    int32_t generateSessionID();
    void onSetDriverEnabled(const QDBusMessage &message,const QString& driverName,bool enabled);
    void onSetAuthTypeEnabled(const QDBusMessage &message,int authType,bool enabled);
    void onSetAuthTypeEnabledForApp(const QDBusMessage &message,int authType, int authApp, bool enabled);

private:
    static AuthManager *m_instance;
    AuthConfig *m_authConfig;
    UserManager *m_userManager;
    AuthManagerAdaptor *m_dbusAdaptor;

    // 结合其他信息生成的认证顺序
    QList<KADAuthType> m_authOrder;

    // <会话ID，会话>
    QMap<int32_t, Session *> m_sessions;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 10, 0))
    QRandomGenerator m_randomGenerator;
#endif
    QDBusServiceWatcher *m_serviceWatcher;
};

}  // namespace Kiran
