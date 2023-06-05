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
#include "src/pam/auth_user_proxy.h"
#include "src/pam/config-pam.h"
#include "src/pam/pam-args-parser.h"
#include "src/pam/pam-handle.h"

namespace Kiran
{
Authentication::Authentication(PAMHandle *pamHandle,
                               const QStringList &arguments)
    : QObject(),
      m_pamHandle(pamHandle),
      m_arguments(arguments),
      m_authManagerProxy(nullptr),
      m_authSessionProxy(nullptr),
      m_authUserProxy(nullptr)
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
    this->m_pamHandle->syslog(LOG_DEBUG, "Authentication thread start.");

#define CHECK_RESULT(expr)            \
    {                                 \
        auto result = expr;           \
        if (result != PAM_SUCCESS)    \
        {                             \
            this->finishAuth(result); \
            return;                   \
        }                             \
    }

    CHECK_RESULT(this->init());
    CHECK_RESULT(this->startAction());
#undef CHECK_RESULT
}

int Authentication::init()
{
    this->m_serviceName = this->m_pamHandle->getItem(PAM_SERVICE);
    this->m_userName = this->m_pamHandle->getItem(PAM_USER);

    if (!QDBusConnection::systemBus().interface()->isServiceRegistered(KAD_MANAGER_DBUS_NAME))
    {
        this->m_pamHandle->syslog(LOG_ERR, QString("authentication service %1 is not registered!").arg(KAD_MANAGER_DBUS_NAME));
        return PAM_IGNORE;
    }

    this->m_authManagerProxy = new AuthManagerProxy(KAD_MANAGER_DBUS_NAME,
                                                    KAD_MANAGER_DBUS_OBJECT_PATH,
                                                    QDBusConnection::systemBus(),
                                                    this);
    auto authAppReply = this->m_authManagerProxy->QueryAuthApp(this->m_serviceName);
    this->m_authApplication = authAppReply.value();
    if (authAppReply.isError())
    {
        this->m_pamHandle->syslog(LOG_ERR, QString("query authentication app type failed,%1").arg(authAppReply.error().message()));
        return PAM_IGNORE;
    }

    auto reply = this->m_authManagerProxy->FindUserByName(this->m_userName);
    auto userPath = reply.value();
    if (userPath.path().isEmpty() || reply.isError())
    {
        this->m_pamHandle->syslog(LOG_ERR, QString("auth manager find user %1 failed,%2").arg(this->m_userName).arg(reply.error().message()));
        return PAM_IGNORE;
    }

    this->m_authUserProxy = new AuthUserProxy(KAD_MANAGER_DBUS_NAME,
                                              userPath.path(),
                                              QDBusConnection::systemBus(),
                                              this);

    return PAM_SUCCESS;
}

int Authentication::checkFailures()
{
    if (this->m_authUserProxy->failures() >= this->m_authManagerProxy->maxFailures())
    {
        KLOG_DEBUG() << "current failures:" << this->m_authUserProxy->failures();
        KLOG_DEBUG() << "max failures:    " << this->m_authManagerProxy->maxFailures();

        this->m_pamHandle->syslog(LOG_DEBUG, QString("user:%1,failures:%2,max filures:%3")
                                                 .arg(m_userName)
                                                 .arg(this->m_authUserProxy->failures())
                                                 .arg(this->m_authManagerProxy->maxFailures()));
        this->m_pamHandle->sendErrorMessage(tr("Too many authentication failures, so the authentication mode is locked."));
        const int authMode = this->m_authManagerProxy->authMode();
        auto ret = authMode == KAD_AUTH_MODE_AND ? PAM_SYSTEM_ERR : PAM_IGNORE;
        KLOG_DEBUG() << "ret" << ret;
        return ret;
    }

    return PAM_SUCCESS;
}

int Authentication::startAction()
{
    int result = PAM_SUCCESS;
    QScopedPointer<PAMArgsParser> pamArgsParser(new PAMArgsParser());
    auto argsInfo = pamArgsParser->parser(this->m_arguments);

    switch (shash(argsInfo.action.toStdString().c_str()))
    {
    case CONNECT(KAP_ARG_ACTION_DO_AUTH, _hash):
    {
        result = this->startActionDoAuth();
        break;
    }
    case CONNECT(KAP_ARG_ACTION_AUTH_SUCC, _hash):
        result = this->startActionAuthSucc();
        break;
    default:
        this->m_pamHandle->syslog(LOG_WARNING, QString("PAM action %1 is unsupported, so the pam module is ignored.").arg(argsInfo.action));
        result = PAM_IGNORE;
        break;
    }

    return result;
}

int Authentication::startActionDoAuth()
{
    auto result = this->startAuthPre();
    RETURN_VAL_IF_TRUE(result != PAM_SUCCESS, result);
    result = this->startAuth();
    RETURN_VAL_IF_TRUE(result != PAM_SUCCESS, result);
    return PAM_SUCCESS;
}

int Authentication::startActionAuthSucc()
{
    auto reply = this->m_authManagerProxy->FindUserByName(this->m_userName);
    auto userObjectPath = reply.value();
    this->m_pamHandle->syslog(LOG_DEBUG, QString("handler auth success,%1,path:%2").arg(m_userName).arg(userObjectPath.path()));

    if (!userObjectPath.path().isEmpty())
    {
        auto userProxy = new AuthUserProxy(KAD_MANAGER_DBUS_NAME,
                                           userObjectPath.path(),
                                           QDBusConnection::systemBus(),
                                           this);
        userProxy->ResetFailures().waitForFinished();
    }
    return PAM_IGNORE;
}

int Authentication::startAuthPre()
{
    auto authTypeReply = m_authManagerProxy->GetAuthTypeByApp(m_authApplication);
    QList<int> authTypeList = authTypeReply.value();

    this->notifyAuthMode();
    RETURN_VAL_IF_TRUE(!this->initSession(), PAM_SYSTEM_ERR);

    if (this->m_authManagerProxy->authMode() == KADAuthMode::KAD_AUTH_MODE_OR)
    {
        if (this->requestLoginUserSwitchable())
        {
            this->m_authSessionProxy->SetLoginUserSwitchable(true);
        }

        this->notifySupportAuthType();

        auto authType = this->requestAuthType();
        // 密码认证不经过认证服务，直接通知界面更新认证方式,然后退出进行密码认证
        if (authType == KAD_AUTH_TYPE_PASSWORD)
        {
            this->notifyAuthType(authType);
            return PAM_IGNORE;
        }

        // 在选择非密码认证类型后，再开始检查失败
        auto result = checkFailures();
        RETURN_VAL_IF_TRUE(result != PAM_SUCCESS, result);

        auto setAuthTypeReply = this->m_authSessionProxy->SetAuthType(authType);
        setAuthTypeReply.waitForFinished();
        if (setAuthTypeReply.isError())
        {
            this->m_pamHandle->syslog(LOG_WARNING, QString("auth session set auth type %1 failed").arg(authType));
            return PAM_SYSTEM_ERR;
        }
    }
    
    this->notifyAuthType(this->m_authSessionProxy->authType());
    auto connected = connect(m_authSessionProxy, &AuthSessionProxy::AuthTypeChanged, this, &Authentication::onAuthTypeChanged);
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
    this->m_pamHandle->syslog(LOG_DEBUG,
                              QString("Authentication thread ready quit,result:%1").arg(result));
    this->m_pamHandle->finish(result);
}

bool Authentication::initSession()
{
    auto userName = this->m_pamHandle->getItem(PAM_USER);
    auto reply = this->m_authManagerProxy->CreateSession(userName, -1, m_authApplication);
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

    m_sessionID = this->m_authSessionProxy->iD();
    connect(this->m_authSessionProxy, &AuthSessionProxy::AuthPrompt, this, &Authentication::onAuthPrompt);
    connect(this->m_authSessionProxy, &AuthSessionProxy::AuthMessage, this, &Authentication::onAuthMessage);
    connect(this->m_authSessionProxy, &AuthSessionProxy::AuthFailed, this, &Authentication::onAuthFailed);
    connect(this->m_authSessionProxy, &AuthSessionProxy::AuthUnavail, this, &Authentication::onAuthUnavail);
    connect(this->m_authSessionProxy, &AuthSessionProxy::AuthSuccessed, this, &Authentication::onAuthSuccessed);
    this->m_pamHandle->syslog(LOG_DEBUG, QString("init session,%1").arg(m_sessionID));
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
    this->m_pamHandle->syslog(LOG_DEBUG, QString("Authentication failed,session ID:%1").arg(m_sessionID));
    this->finishAuth(PAM_AUTH_ERR);
}

void Authentication::onAuthUnavail()
{
    this->m_pamHandle->syslog(LOG_DEBUG, QString("Authentication unavail,session ID:%1").arg(m_sessionID));
    this->finishAuth(PAM_AUTHINFO_UNAVAIL);
}

void Authentication::onAuthSuccessed(const QString &userName)
{
    if (!userName.isEmpty())
    {
        this->m_pamHandle->setItem(PAM_USER, userName);
    }

    auto authMode = this->m_authManagerProxy->authMode();
    if( authMode == KAD_AUTH_MODE_AND )
    {
        this->notifyAuthType(KAD_AUTH_TYPE_PASSWORD);
    }

    this->m_pamHandle->syslog(LOG_DEBUG, QString("Authentication successed,session ID:%1").arg(m_sessionID));
    this->finishAuth(PAM_SUCCESS);
}

void Authentication::onAuthTypeChanged(int authType)
{
    this->notifyAuthType(authType);
}

}  // namespace Kiran
