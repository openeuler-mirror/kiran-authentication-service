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

class AuthManagerAdaptor;
class QSettings;
class BiometricsProxy;
class QDBusServiceWatcher;

namespace Kiran
{
class Session;
class UserManager;

class AuthManager : public QObject, protected QDBusContext
{
    Q_OBJECT

    Q_PROPERTY(QString FPDeviceID READ getFPDeviceID WRITE setFPDeviceID NOTIFY fpDeviceIDChanged)
    Q_PROPERTY(int AuthMode READ getAuthMode NOTIFY authModeChanged)
public:
    AuthManager(UserManager *userManager);
    virtual ~AuthManager(){};

    static AuthManager *getInstance() { return m_instance; };

    static void globalInit(UserManager *userManager);

    static void globalDeinit() { delete m_instance; };

    QString getFPDeviceID() { return this->m_fpDeviceID; }
    void setFPDeviceID(const QString &fpDeviceID);
    int getAuthMode() { return this->m_authMode; }
    QList<int32_t> getAuthOrder() { return this->m_authOrder; }

public Q_SLOTS:  // DBUS METHODS
    QDBusObjectPath CreateSession(const QString &userName, int timeout);
    void DestroySession(uint sessionID);
    QDBusObjectPath FindUserByID(qulonglong uid);
    QDBusObjectPath FindUserByName(const QString &userName);
    QString GetPAMServies();
    void SwitchPAMServie(bool enabled, const QString &service);
    bool PAMServieIsEnabled(const QString &service);
    void onNameLost(const QString &serviceName);

Q_SIGNALS:
    void fpDeviceIDChanged(const QString &fpDeviceID);
    void authModeChanged(int authMode);

private:
    void init();

    // 生成一个唯一的会话ID
    int32_t generateSessionID();

private:
    static AuthManager *m_instance;
    UserManager *m_userManager;
    QSettings *m_settings;
    AuthManagerAdaptor *m_dbusAdaptor;
    // <会话ID，会话>
    QMap<int32_t, Session *> m_sessions;
    // 默认使用的指纹设备
    QString m_fpDeviceID;
    int32_t m_authMode;
    QList<int32_t> m_authOrder;
    QRandomGenerator m_randomGenerator;
    QDBusServiceWatcher *m_serviceWatcher;
};

}  // namespace Kiran
