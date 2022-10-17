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

#include "src/pam/authentication.h"
#include <auxiliary.h>
#include <kas-authentication-i.h>
#include <pam_ext.h>
#include <pam_modules.h>
#include <syslog.h>
#include <QDBusConnection>
#include <QJsonDocument>
#include <QMetaType>
#include <QTranslator>
#include "src/pam/auth_manager_proxy.h"
#include "src/pam/auth_session_proxy.h"
#include "src/pam/config-pam.h"
#include "src/pam/pam-handle.h"

namespace Kiran
{
Authentication::Authentication(PAMHandle *pamHandle) : m_pamHandle(pamHandle),
                                                       m_authManagerProxy(nullptr),
                                                       m_authSessionProxy(nullptr)
{
}

Authentication::~Authentication()
{
    if (this->m_authSessionProxy && this->m_authManagerProxy)
    {
        this->m_authManagerProxy->DestroySession(this->m_authSessionProxy->iD());
    }
}

void Authentication::start()
{
    this->init();

    this->m_pamHandle->syslog(LOG_DEBUG, "Authentication thread start.");

    auto result = this->startAuthPre();
    if (result != PAM_SUCCESS)
    {
        this->finishAuth(result);
        return;
    }

    result = this->startAuth();
    if (result != PAM_SUCCESS)
    {
        this->finishAuth(result);
        return;
    }
}

void Authentication::init()
{
    this->m_authManagerProxy = new AuthManagerProxy(KAD_MANAGER_DBUS_NAME,
                                                    KAD_MANAGER_DBUS_OBJECT_PATH,
                                                    QDBusConnection::systemBus(),
                                                    this);
    this->m_serviceName = this->m_pamHandle->getItemDirect(PAM_SERVICE);
    this->m_userName = this->m_pamHandle->getItemDirect(PAM_USER);
}

int Authentication::startAuthPre()
{
    // 只对支持的PAM_SERVICE进行认证，其他默认成功
    if (!this->m_authManagerProxy->PAMServieIsEnabled(this->m_serviceName).value())
    {
        this->m_pamHandle->syslog(LOG_DEBUG, QString("The pam service '%1' is disabled or unsupported.").arg(this->m_serviceName));
        return PAM_IGNORE;
    }

    RETURN_VAL_IF_TRUE(!this->initSession(), PAM_SYSTEM_ERR);

    this->notifyAuthMode();

    if (this->m_authManagerProxy->authMode() == KADAuthMode::KAD_AUTH_MODE_OR)
    {
        auto authType = this->requestAuthType();

        switch (authType)
        {
        case KADAuthType::KAD_AUTH_TYPE_NONE:
            break;
        case KADAuthType::KAD_AUTH_TYPE_FINGERPRINT:
            this->m_authSessionProxy->SetAuthType(authType);
            break;
        default:
            return PAM_IGNORE;
        }
    }

    this->notifyAuthType();

    auto connected = QDBusConnection::systemBus().connect(QStringLiteral(KAD_MANAGER_DBUS_NAME),
                                                          this->m_authSessionProxy->path(),
                                                          QStringLiteral("org.freedesktop.DBus.Properties"),
                                                          QStringLiteral("PropertiesChanged"),
                                                          this,
                                                          SLOT(onPropertiesChanged(QString, QVariantMap, QStringList)));

    if (!connected)
    {
        this->m_pamHandle->syslog(LOG_WARNING,
                                  QString("Failed to connect signal PropertiesChanged for %1.").arg(this->m_authSessionProxy->path()));
    }

    return PAM_SUCCESS;
}

int Authentication::startAuth()
{
    this->m_pamHandle->syslog(LOG_DEBUG, "Start authentication.");

    auto reply = this->m_authSessionProxy->StartAuth();
    reply.waitForFinished();
    if (reply.isError())
    {
        this->m_pamHandle->syslog(LOG_WARNING,
                                  QString("Call startAuth failed: %1.").arg(reply.error().message()));
        return PAM_SYSTEM_ERR;
    }
    return PAM_SUCCESS;
}

void Authentication::finishAuth(int result)
{
    this->m_pamHandle->syslog(LOG_DEBUG, "Authentication thread ready quit.");
    this->m_pamHandle->finish(result);
}

bool Authentication::initSession()
{
    // 认证时不限定用户，如果认证的是其他用户则登录到其他用户的会话中
    auto reply = this->m_authManagerProxy->CreateSession(QString(), -1);
    auto sessionObjectPath = reply.value();

    if (reply.isError())
    {
        this->m_pamHandle->syslog(LOG_ERR, reply.error().message());
        return false;
    }
    else
    {
        this->m_pamHandle->syslog(LOG_DEBUG, QString("The created session object path is %1").arg(sessionObjectPath.path()));
    }

    this->m_authSessionProxy = new AuthSessionProxy(KAD_MANAGER_DBUS_NAME,
                                                    sessionObjectPath.path(),
                                                    QDBusConnection::systemBus(),
                                                    this);

    connect(this->m_authSessionProxy, SIGNAL(AuthPrompt(const QString &, int)), this, SLOT(onAuthPrompt(const QString &, int)));
    connect(this->m_authSessionProxy, SIGNAL(AuthMessage(const QString &, int)), this, SLOT(onAuthMessage(const QString &, int)));
    connect(this->m_authSessionProxy, SIGNAL(AuthFailed()), this, SLOT(onAuthFailed()));
    connect(this->m_authSessionProxy, SIGNAL(AuthSuccessed(const QString &)), this, SLOT(onAuthSuccessed(const QString &)));

    return true;
}

void Authentication::onAuthPrompt(const QString &text, int type)
{
    QString response;
    int32_t retval = PAM_SUCCESS;
    switch (type)
    {
    case KADPromptType::KAD_PROMPT_TYPE_QUESTION:
        retval = this->m_pamHandle->sendQuestionPrompt(text, response);
        break;
    case KADPromptType::KAD_PROMPT_TYPE_SECRET:
        retval = this->m_pamHandle->sendSecretPrompt(text, response);
        break;
    default:
        this->m_pamHandle->syslog(LOG_WARNING, QString("Unknown message type: %1").arg(type));
        retval = PAM_AUTH_ERR;
        break;
    }

    if (retval != PAM_SUCCESS)
    {
        this->finishAuth(retval);
    }
    else
    {
        this->m_authSessionProxy->ResponsePrompt(response);
    }
}

void Authentication::onAuthMessage(const QString &text, int type)
{
    QString response;
    int32_t retval = PAM_SUCCESS;
    switch (type)
    {
    case KADMessageType::KAD_MESSAGE_TYPE_ERROR:
        retval = this->m_pamHandle->sendErrorMessage(text);
        break;
    case KADMessageType::KAD_MESSAGE_TYPE_INFO:
        retval = this->m_pamHandle->sendTextMessage(text);
        break;
    default:
        this->m_pamHandle->syslog(LOG_WARNING, QString("Unknown message type: %1").arg(type));
        retval = PAM_AUTH_ERR;
        break;
    }

    if (retval != PAM_SUCCESS)
    {
        this->finishAuth(retval);
    }
}

void Authentication::onAuthFailed()
{
    this->m_pamHandle->syslog(LOG_DEBUG, "Authentication failed");
    this->finishAuth(PAM_AUTH_ERR);
}

void Authentication::onAuthSuccessed(const QString &userName)
{
    if (!userName.isEmpty())
    {
        this->m_pamHandle->setItem(PAM_USER, userName);
    }
    this->finishAuth(PAM_SUCCESS);
}

void Authentication::onPropertiesChanged(const QString &interfaceName,
                                         const QVariantMap &changedProperties,
                                         const QStringList &invalidatedProperties)
{
    const QVariant authType = changedProperties.value(QStringLiteral("AuthType"));
    if (authType.isValid())
    {
        this->notifyAuthType();
    }
}

}  // namespace Kiran
