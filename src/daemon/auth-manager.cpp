/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
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

#include <pwd.h>
#include <QDBusInterface>
#include <QDBusMessage>
#include <QDBusReply>
#include <QDBusServiceWatcher>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaEnum>
#include <QSettings>
#include <QTime>

#include "auth-config.h"
#include "auth-manager.h"
#include "auth_manager_adaptor.h"
#include "auxiliary.h"
#include "config-daemon.h"
#include "device/device-adaptor-factory.h"
#include "error.h"
#include "kas-authentication-i.h"
#include "lib/utils.h"
#include "logging-category.h"
#include "proxy/dbus-daemon-proxy.h"
#include "proxy/polkit-proxy.h"
#include "qt5-log-i.h"
#include "session.h"
#include "user-manager.h"

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

/// @brief 检查CZHT服务是否可用
/// @details 检查是否存在虚拟设备以及CZHT D-Bus服务是否已注册
/// @return 如果服务可用（设备存在且D-Bus服务已注册）返回true，否则返回false
bool AuthManager::isCZHTServiceAvailable()
{
    // 检查是否存在虚拟人脸和虚拟码认证设备
    QString virtualFaceDevices = GetDevicesForType(KAD_AUTH_TYPE_VIRTUAL_FACE);
    QString virtualCodeDevices = GetDevicesForType(KAD_AUTH_TYPE_VIRTUAL_CODE);

    bool hasVirtualFaceDevice = !virtualFaceDevices.isEmpty();
    bool hasVirtualCodeDevice = !virtualCodeDevices.isEmpty();

    // 如果不存在虚拟设备，不需要使用CZHT服务
    if (!hasVirtualFaceDevice && !hasVirtualCodeDevice)
    {
        return false;
    }

    // 检查 CZHT D-Bus 服务是否存在
    static const QString CZHT_DBUS_SERVICE = "com.czht.face.daemon";
    if (!QDBusConnection::systemBus().interface()->isServiceRegistered(CZHT_DBUS_SERVICE))
    {
        return false;
    }

    return true;
}

/// @brief 从CZHT服务获取认证类型列表
/// @details 调用CZHT服务的GetWorkMode接口，解析JSON返回结果，根据工作模式返回对应的认证类型列表
///           工作模式定义：1=人脸，2=人脸+密码，3=人脸+授权码，4=人脸+密码+授权码
/// @return 如果成功获取，返回对应的认证类型列表；否则返回空列表
QList<int> AuthManager::GetAuthTypeFromCZHT()
{
    QList<int> authTypes;

    // CZHT服务相关常量
    static const QString CZHT_DBUS_SERVICE = "com.czht.face.daemon";
    static const QString CZHT_DBUS_PATH = "/com/czht/face/daemon";
    static const QString CZHT_DBUS_INTERFACE = "com.czht.face.daemon";
    static const QString CZHT_METHOD_GET_WORK_MODE = "GetWorkMode";

    // 调用 GetWorkMode 接口获取工作模式
    QDBusMessage message = QDBusMessage::createMethodCall(CZHT_DBUS_SERVICE,
                                                          CZHT_DBUS_PATH,
                                                          CZHT_DBUS_INTERFACE,
                                                          CZHT_METHOD_GET_WORK_MODE);
    QDBusReply<QString> reply = QDBusConnection::systemBus().call(message);
    if (!reply.isValid())
    {
        KLOG_WARNING() << "Failed to call GetWorkMode:" << reply.error().message();
        return authTypes;
    }
    KLOG_INFO() << "GetWorkMode from" << CZHT_DBUS_SERVICE << ", reply:" << reply.value();

    // 解析 JSON 返回结果
    QString jsonStr = reply.value();
    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonStr.toUtf8(), &parseError);

    if (parseError.error != QJsonParseError::NoError)
    {
        KLOG_WARNING() << "Failed to parse GetWorkMode JSON:" << parseError.errorString();
        return authTypes;
    }

    QJsonObject jsonObj = jsonDoc.object();
    int code = jsonObj.value("code").toInt(-1);
    if (code != 0)
    {
        KLOG_WARNING() << "GetWorkMode returned error code:" << code;
        return authTypes;
    }

    int workMode = jsonObj.value("work_mode").toInt(-1);
    KLOG_INFO() << "GetWorkMode from" << CZHT_DBUS_SERVICE << ", work_mode:" << workMode;

    // 根据工作模式返回对应的认证类型列表
    // 工作模式定义：1=人脸，2=人脸+密码，3=人脸+授权码，4=人脸+密码+授权码
    // NOTE: 这里直接使用的是数字，考虑使用枚举的话，需要将CZHT的define头文件放置在代码上层，是否过多牵扯到定制代码？
    switch (workMode)
    {
    case 1:  // 人脸
        authTypes << KAD_AUTH_TYPE_VIRTUAL_FACE;
        break;
    case 2:  // 人脸+密码
        authTypes << KAD_AUTH_TYPE_VIRTUAL_FACE << KAD_AUTH_TYPE_PASSWORD;
        break;
    case 3:  // 人脸+授权码
        authTypes << KAD_AUTH_TYPE_VIRTUAL_FACE << KAD_AUTH_TYPE_VIRTUAL_CODE;
        break;
    case 4:  // 人脸+密码+授权码
        authTypes << KAD_AUTH_TYPE_VIRTUAL_FACE << KAD_AUTH_TYPE_VIRTUAL_CODE << KAD_AUTH_TYPE_PASSWORD;
        break;
    default:
        KLOG_WARNING() << "Unknown work_mode:" << workMode;
        break;
    }

    return authTypes;
}

/// @brief 通过认证应用枚举获取支持的认证类型或认证顺序
/// @param authApp 应用程序所属的认证应用类型
/// @return 与模式下为需认证类型的认证顺序,或模式下为可选的认证类型
QList<int> AuthManager::GetAuthTypeByApp(int32_t authApp)
{
    KLOG_INFO() << "GetAuthTypeByApp: authApp:" << authApp;

    // 从外部服务获取认证类型列表（当前支持CZHT服务）
    // 未来扩展：按照以下模式添加其他外部服务：
    //   1. 添加 isXXXServiceAvailable() 函数：检查该服务是否可用
    //   2. 添加 GetAuthTypeFromXXX() 函数：从该服务获取认证类型列表（调用D-Bus接口，解析工作模式并返回认证类型）
    //   3. 在下面依次判断各个服务是否可用，如果可用则获取认证类型并添加到结果中
    QList<int> externalAuthTypes;

    // CZHT服务
    if (isCZHTServiceAvailable())
    {
        QList<int> czhtAuthTypes = GetAuthTypeFromCZHT();
        externalAuthTypes.append(czhtAuthTypes);
        KLOG_INFO() << "GetAuthTypeByApp: CZHT service available, auth types:" << czhtAuthTypes;
    }

    // 未来可以添加其他外部服务，例如：
    // if (isOtherServiceAvailable())
    // {
    //     QList<int> otherAuthTypes = GetAuthTypeFromOther();
    //     externalAuthTypes.append(otherAuthTypes);
    // }

    // 如果所有外部服务都不可用，则使用后续的默认逻辑
    if (!externalAuthTypes.isEmpty())
    {
        KLOG_INFO() << "GetAuthTypeByApp: using external service auth types:" << externalAuthTypes;
        return externalAuthTypes;
    }

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
    KLOG_INFO() << "get auth types by app:" << authApp << "result:" << sortedAuthTypes;
    return sortedAuthTypes;
}

int AuthManager::QueryAuthApp(const QString &pamServiceName)
{
    static QMap<QString, int> pamAuthAppMap = {{"lightdm", KAD_AUTH_APPLICATION_LOGIN},
                                               {"kiran-screensaver", KAD_AUTH_APPLICATION_UNLOCK},
                                               {"polkit-1", KAD_AUTH_APPLICATION_EMPOWERMENT},
                                               {"sudo", KAD_AUTH_APPLICATION_EMPOWERMENT},
                                               {"gdm-password", KAD_AUTH_APPLICATION_LOGIN},
                                               {"gnome-screensaver", KAD_AUTH_APPLICATION_UNLOCK}};

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
