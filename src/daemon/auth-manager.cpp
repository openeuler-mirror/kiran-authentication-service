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

#include "src/daemon/auth-manager.h"
#include "auxiliary.h"
#include "logging-category.h"
#include "src/daemon/auth-config.h"
#include "src/daemon/auth_manager_adaptor.h"
#include "src/daemon/config-daemon.h"
#include "src/daemon/device/device-adaptor-factory.h"
#include "src/daemon/error.h"
#include "src/daemon/proxy/dbus-daemon-proxy.h"
#include "src/daemon/proxy/polkit-proxy.h"
#include "src/daemon/session.h"
#include "src/daemon/user-manager.h"
#include "src/utils/utils.h"

#include <kas-authentication-i.h>
#include <pwd.h>
#include <QDBusServiceWatcher>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaEnum>
#include <QSettings>
#include <QTime>

#define AUTH_USER_ADMIN "com.kylinsec.kiran.authentication.user-administration"

namespace Kiran
{
// 会话ID的最大值
#define MAX_SESSION_ID 10000
AuthManager::AuthManager(UserManager *userManager, AuthConfig *authConfig)
    : m_authConfig(authConfig),
      m_userManager(userManager)
{
    this->m_dbusAdaptor = new AuthManagerAdaptor(this);
    this->m_serviceWatcher = new QDBusServiceWatcher(this);
}

AuthManager *AuthManager::m_instance = nullptr;
void AuthManager::globalInit(UserManager *userManager, AuthConfig *authConfig)
{
    m_instance = new AuthManager(userManager, authConfig);
    m_instance->init();
}

int AuthManager::getAuthMode()
{
    return m_authConfig->getAuthMode();
}

int AuthManager::getMaxFailures()
{
    return m_authConfig->getMaxFailures();
}

QDBusObjectPath AuthManager::CreateSession(const QString &username, int timeout, int authApp)
{
    auto sessionID = this->generateSessionID();
    if (sessionID < 0)
    {
        KLOG_WARNING() << "create session error,generate session id failed";
        DBUS_ERROR_REPLY_WITH_RET(QDBusObjectPath(),
                                  QDBusError::LimitsExceeded,
                                  KADErrorCode::ERROR_SESSION_EXCEED_MAX_SESSION_NUM);
    }

    this->m_serviceWatcher->addWatchedService(this->message().service());

    auto session = new Session(sessionID, this->message().service(), username, (KADAuthApplication)authApp, this);
    this->m_sessions.insert(sessionID, session);

    KLOG_DEBUG() << QString("create session user(%1) timeout(%2) app type(%3) for %4 -> session(%5)")
                        .arg(username)
                        .arg(timeout)
                        .arg(authApp)
                        .arg(this->message().service())
                        .arg(sessionID);

    return QDBusObjectPath(session->getObjectPath());
}

void AuthManager::DestroySession(uint sessionID)
{
    auto session = this->m_sessions.value(sessionID, nullptr);
    if (!session)
    {
        KLOG_WARNING() << "destory session error,can't find session" << sessionID;
        return;
    }
    KLOG_DEBUG() << sessionID << "destory session";
    this->m_sessions.remove(sessionID);
    session->StopAuth();
    delete session;
}

QString AuthManager::GetDriversForType(int authType)
{
    return DeviceAdaptorFactory::getInstance()->getDriversForType(authType);
}

QDBusObjectPath AuthManager::FindUserByID(qulonglong uid)
{
    auto pwent = getpwuid(uid);
    if (!pwent)
    {
        DBUS_ERROR_REPLY_WITH_RET(QDBusObjectPath(),
                                  QDBusError::InvalidArgs,
                                  KADErrorCode::ERROR_FAILED);
    }
    return this->FindUserByName(pwent->pw_name);
}

QDBusObjectPath AuthManager::FindUserByName(const QString &userName)
{
    auto user = this->m_userManager->findUser(userName);
    if (!user)
    {
        DBUS_ERROR_REPLY_WITH_RET(QDBusObjectPath(),
                                  QDBusError::InvalidArgs,
                                  KADErrorCode::ERROR_FAILED);
    }
    return QDBusObjectPath(user->getObjectPath());
}

QString AuthManager::GetDevicesForType(int authType)
{
    return DeviceAdaptorFactory::getInstance()->getDeivcesForType(authType);
}

QString AuthManager::GetDefaultDeviceID(int authType)
{
    return m_authConfig->getDefaultDeviceID((KADAuthType)authType);
}

void AuthManager::SetDefaultDeviceID(int authType, const QString &deviceID)
{
    auto oldDeviceID = this->GetDefaultDeviceID(authType);
    RETURN_IF_TRUE(deviceID == oldDeviceID);

    m_authConfig->setDefaultDeviceID((KADAuthType)authType, deviceID);
}

bool AuthManager::GetAuthTypeEnabled(int authType)
{
    return m_authConfig->getAuthTypeEnable((KADAuthType)authType);
}

bool AuthManager::GetAuthTypeEnabledForApp(int authType, int authApp)
{
    return m_authConfig->getAuthTypeEnabledForApp((KADAuthType)authType, (KADAuthApplication)authApp);
}

/// @brief 通过认证应用枚举获取支持的认证类型或认证顺序
/// @param authApp 应用程序所属的认证应用类型
/// @return 与模式下为需认证类型的认证顺序,或模式下为可选的认证类型
QList<int> AuthManager::GetAuthTypeByApp(int32_t authApp)
{
    auto enabledAuthTypes = m_authConfig->getAuthTypeByApp(authApp);
    auto authOrder = m_authConfig->getAuthOrder();

    // 在认证顺序指定的认证类型中过滤掉未开启的认证类型
    auto autoOrderIter = authOrder.begin();
    while (autoOrderIter != authOrder.end())
    {
        if (!enabledAuthTypes.contains(*autoOrderIter))
        {
            autoOrderIter = authOrder.erase(autoOrderIter);
        }
        else
            autoOrderIter++;
    }

    auto sortedAuthTypes = authOrder;

    auto enabledAuthTypeIter = enabledAuthTypes.begin();
    while (enabledAuthTypeIter != enabledAuthTypes.end())
    {
        if (!sortedAuthTypes.contains(*enabledAuthTypeIter))
        {
            sortedAuthTypes << *enabledAuthTypeIter;
        }
        enabledAuthTypeIter++;
    }

    sortedAuthTypes << KAD_AUTH_TYPE_PASSWORD;
    KLOG_DEBUG() << "get auth types by app:" << authApp << "result:" << sortedAuthTypes;
    return sortedAuthTypes;
}

int AuthManager::QueryAuthApp(const QString &pamServiceName)
{
    static QMap<QString, int> pamAuthAppMap = {
        {"lightdm", KAD_AUTH_APPLICATION_LOGIN},
        {"kiran-screensaver", KAD_AUTH_APPLICATION_UNLOCK},
        {"polkit-1", KAD_AUTH_APPLICATION_EMPOWERMENT},

        {"sudo", KAD_AUTH_APPLICATION_EMPOWERMENT}};

    int authApp = KAD_AUTH_APPLICATION_NONE;

    auto iter = pamAuthAppMap.find(pamServiceName);
    if (iter != pamAuthAppMap.end())
    {
        authApp = iter.value();
    }

    KLOG_DEBUG("query auth application by service(%s) result:%d", pamServiceName.toStdString().c_str(), authApp);
    return authApp;
}

void AuthManager::onNameLost(const QString &serviceName)
{
    this->m_serviceWatcher->removeWatchedService(serviceName);

    // 一般会话不会特别多，所以直接遍历
    QList<Session *> deletedSessions;
    for (auto session : this->m_sessions)
    {
        if (session->getServiceName() == serviceName)
        {
            deletedSessions.push_back(session);
        }
    }

    for (auto session : deletedSessions)
    {
        KLOG_DEBUG() << QString("caller name %1 lost,destory session %2").arg(serviceName).arg(session->getID());
        this->DestroySession(session->getSessionID());
    }
}

CHECK_AUTH_WITH_2ARGS(AuthManager, SetDrivereEnabled, onSetDriverEnabled, AUTH_USER_ADMIN, const QString &, bool);
CHECK_AUTH_WITH_2ARGS(AuthManager, SetAuthTypeEnabled, onSetAuthTypeEnabled, AUTH_USER_ADMIN, int, bool);
CHECK_AUTH_WITH_3ARGS(AuthManager, SetAuthTypeEnabledForApp, onSetAuthTypeEnabledForApp, AUTH_USER_ADMIN, int, int, bool);

void AuthManager::init()
{
    auto systemConnection = QDBusConnection::systemBus();
    if (!systemConnection.registerService(KAD_MANAGER_DBUS_NAME))
    {
        KLOG_WARNING() << "failed to register dbus name: " << KAD_MANAGER_DBUS_NAME;
    }

    if (!systemConnection.registerObject(KAD_MANAGER_DBUS_OBJECT_PATH, this))
    {
        KLOG_WARNING() << "can't register object:" << systemConnection.lastError();
    }

    this->m_serviceWatcher->setConnection(systemConnection);
    this->m_serviceWatcher->setWatchMode(QDBusServiceWatcher::WatchForUnregistration);
    connect(this->m_serviceWatcher, SIGNAL(serviceUnregistered(const QString &)), this, SLOT(onNameLost(const QString &)));
    connect(m_authConfig, SIGNAL(defaultDeviceChanged(int, QString)), this, SIGNAL(defaultDeviceChanged(int, QString)));
}

QString AuthManager::calcAction(const QString &originAction)
{
    return AUTH_USER_ADMIN;
}

int32_t AuthManager::generateSessionID()
{
    // 最多生成10次，超过次数则返回失败
    for (int i = 0; i <= 10; ++i)
    {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 10, 0))
        auto sessionID = this->m_randomGenerator.bounded(1, MAX_SESSION_ID);
#else
        qsrand(QTime(0, 0, 0).secsTo(QTime::currentTime()));
        auto sessionID = qrand() % MAX_SESSION_ID + 1;
#endif
        auto session = this->m_sessions.value(sessionID, nullptr);
        // KLOG_DEBUG() << "session: " << session << ", sessionID: " << sessionID;
        RETURN_VAL_IF_TRUE(session == nullptr, sessionID);
    }
    return -1;
}

void AuthManager::onSetDriverEnabled(const QDBusMessage &message, const QString &driverName, bool enabled)
{
    if (!DeviceAdaptorFactory::getInstance()->setDrivereEanbled(driverName, enabled))
    {
        DBUS_ERROR_REPLY_ASYNC(message, QDBusError::InternalError, KADErrorCode::ERROR_FAILED);
    }

    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

void AuthManager::onSetAuthTypeEnabled(const QDBusMessage &message, int authType, bool enabled)
{
    m_authConfig->setAuthTypeEnable((KADAuthType)authType, enabled);

    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

void AuthManager::onSetAuthTypeEnabledForApp(const QDBusMessage &message, int authType, int authApp, bool enabled)
{
    m_authConfig->setAuthTypeEnabledForApp((KADAuthType)authType, (KADAuthApplication)authApp, enabled);

    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

}  // namespace Kiran
