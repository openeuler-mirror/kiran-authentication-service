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
#include <auxiliary.h>
#include <biometrics-i.h>
#include <kas-authentication-i.h>
#include <pwd.h>
#include <QDBusServiceWatcher>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <QTime>
#include "src/daemon/auth_manager_adaptor.h"
#include "src/daemon/biometrics_proxy.h"
#include "src/daemon/config-daemon.h"
#include "src/daemon/device/face-device-decorator.h"
#include "src/daemon/device/fp-device-decorator.h"
#include "src/daemon/error.h"
#include "src/daemon/proxy/dbus-daemon-proxy.h"
#include "src/daemon/session.h"
#include "src/daemon/user-manager.h"
#include "src/daemon/utils.h"

namespace Kiran
{
// 会话ID的最大值
#define MAX_SESSION_ID 10000

#define KAD_MAIN_CONFIG_PATH KAS_INSTALL_SYSCONFDIR "/kad.ini"

#define INIFILE_GENERAL_GROUP_NAME "General"
#define INIFILE_GENERAL_KEY_DEFAULT_DEVICE "DefaultDeviceID"
#define INIFILE_GENERAL_KEY_AUTH_MODE "AuthMode"
#define INIFILE_GENERAL_KEY_AUTH_ORDER "AuthOrder"
#define INIFILE_GENERAL_KEY_SUPPORTED_PAM_SERVICES "SupportedPAMServices"
#define INIFILE_GENERAL_KEY_ENABLED_PAM_SERVICES "EnabledPAMServices"

AuthManager::AuthManager(UserManager *userManager) : m_userManager(userManager),
                                                     m_authMode(KADAuthMode::KAD_AUTH_MODE_OR)
{
    this->m_settings = new QSettings(KAD_MAIN_CONFIG_PATH, QSettings::IniFormat, this);
    this->m_dbusAdaptor = new AuthManagerAdaptor(this);
    this->m_serviceWatcher = new QDBusServiceWatcher(this);
}

AuthManager *AuthManager::m_instance = nullptr;
void AuthManager::globalInit(UserManager *userManager)
{
    m_instance = new AuthManager(userManager);
    m_instance->init();
}

void AuthManager::setFPDeviceID(const QString &fpDeviceID)
{
    // TODO: 判断设备的合法性
    this->m_fpDeviceID = fpDeviceID;
    Q_EMIT this->fpDeviceIDChanged(this->m_fpDeviceID);
}

QDBusObjectPath AuthManager::CreateSession(const QString &username, int timeout)
{
    auto sessionID = this->generateSessionID();
    if (sessionID < 0)
    {
        DBUS_ERROR_REPLY_WITH_RET(QDBusObjectPath(),
                                  QDBusError::LimitsExceeded,
                                  KADErrorCode::ERROR_SESSION_EXCEED_MAX_SESSION_NUM);
    }

    this->m_serviceWatcher->addWatchedService(this->message().service());

    auto session = new Session(sessionID, this->message().service(), username, this);
    this->m_sessions.insert(sessionID, session);
    return QDBusObjectPath(session->getObjectPath());
}

void AuthManager::DestroySession(uint sessionID)
{
    auto session = this->m_sessions.value(sessionID, nullptr);
    if (session)
    {
        this->m_sessions.remove(sessionID);
        delete session;
    }
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

QString AuthManager::GetPAMServies()
{
    auto supportedPAMServices = this->m_settings->value(INIFILE_GENERAL_KEY_SUPPORTED_PAM_SERVICES).toStringList();
    auto enabledPAMServices = this->m_settings->value(INIFILE_GENERAL_KEY_ENABLED_PAM_SERVICES).toStringList();

    QJsonDocument jsonDoc;
    QJsonArray jsonArry;

    for (auto &supportedPAMService : supportedPAMServices)
    {
        QJsonObject jsonObj{
            {KAD_IJK_KEY_PAM_SERVICE, supportedPAMService},
            {KAD_IJK_KEY_PAM_ENABLED, enabledPAMServices.contains(supportedPAMService)}};
        jsonArry.push_back(jsonObj);
    }

    jsonDoc.setArray(jsonArry);
    return QString(jsonDoc.toJson());
}

void AuthManager::SwitchPAMServie(bool enabled, const QString &service)
{
    auto supportedPAMServices = this->m_settings->value(INIFILE_GENERAL_KEY_SUPPORTED_PAM_SERVICES).toStringList();
    auto enabledPAMServices = this->m_settings->value(INIFILE_GENERAL_KEY_ENABLED_PAM_SERVICES).toStringList();
    bool isUpdate = false;

    if (enabled &&
        supportedPAMServices.contains(service) &&
        !enabledPAMServices.contains(service))
    {
        enabledPAMServices.push_back(service);
        isUpdate = true;
    }

    if (!enabled && enabledPAMServices.contains(service))
    {
        enabledPAMServices.removeOne(service);
        isUpdate = true;
    }

    if (isUpdate)
    {
        this->m_settings->setValue(INIFILE_GENERAL_KEY_ENABLED_PAM_SERVICES, enabledPAMServices);
    }
}

bool AuthManager::PAMServieIsEnabled(const QString &service)
{
    auto enabledPAMServices = this->m_settings->value(INIFILE_GENERAL_KEY_ENABLED_PAM_SERVICES).toStringList();
    return enabledPAMServices.contains(service);
}

void AuthManager::onNameLost(const QString &serviceName)
{
    KLOG_DEBUG() << "NameLost: " << serviceName;
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
        this->DestroySession(session->getSessionID());
    }
}

void AuthManager::init()
{
    this->m_fpDeviceID = this->m_settings->value(INIFILE_GENERAL_KEY_DEFAULT_DEVICE, QString()).toString();
    auto authMode = this->m_settings->value(INIFILE_GENERAL_KEY_AUTH_MODE, KAD_AUTH_MODE_STR_OR).toString();
    this->m_authMode = Utils::authModeStr2Enum(authMode);
    auto authOrder = this->m_settings->value(INIFILE_GENERAL_KEY_AUTH_ORDER, QStringList{AUTH_TYPE_STR_FINGERPRINT}).toStringList();
    this->m_authOrder = Utils::authOrderStr2Enum(authOrder);

    auto systemConnection = QDBusConnection::systemBus();
    if (!systemConnection.registerService(KAD_MANAGER_DBUS_NAME))
    {
        KLOG_WARNING() << "Failed to register dbus name: " << KAD_MANAGER_DBUS_NAME;
    }

    if (!systemConnection.registerObject(KAD_MANAGER_DBUS_OBJECT_PATH, this))
    {
        KLOG_WARNING() << "Can't register object:" << systemConnection.lastError();
    }

    DeviceRequestDispatcher::getDefault()->registerListener(MAJOR_REQUEST_TYPE(DeviceRequestType::DEVICE_REQUEST_TYPE_FP_START),
                                                            QSharedPointer<FPDeviceDecorator>::create());

    DeviceRequestDispatcher::getDefault()->registerListener(MAJOR_REQUEST_TYPE(DeviceRequestType::DEVICE_REQUEST_TYPE_FACE_START),
                                                            QSharedPointer<FaceDeviceDecorator>::create());

    this->m_serviceWatcher->setConnection(systemConnection);
    this->m_serviceWatcher->setWatchMode(QDBusServiceWatcher::WatchForUnregistration);
    connect(this->m_serviceWatcher, SIGNAL(serviceUnregistered(const QString &)), this, SLOT(onNameLost(const QString &)));
}

int32_t AuthManager::generateSessionID()
{
    // 最多生成10次，超过次数则返回失败
    for (int i = 0; i <= 10; ++i)
    {
        auto sessionID = this->m_randomGenerator.bounded(1, MAX_SESSION_ID);
        auto session = this->m_sessions.value(sessionID, nullptr);
        // KLOG_DEBUG() << "session: " << session << ", sessionID: " << sessionID;
        RETURN_VAL_IF_TRUE(session == nullptr, sessionID);
    }
    return -1;
}

}  // namespace Kiran
