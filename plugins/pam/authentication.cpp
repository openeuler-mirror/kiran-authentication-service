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

#include <auxiliary.h>
#include <pam_ext.h>
#include <pam_modules.h>
#include <syslog.h>
#include <QDBusConnection>
#include <QJsonDocument>
#include <QMetaType>
#include <QTimer>
#include <QTranslator>
#include <functional>
#include <memory>

#include "auth_manager_proxy.h"
#include "auth_session_proxy.h"
#include "auth_user_proxy.h"
#include "authentication.h"
#include "config-pam.h"
#include "kas-authentication-i.h"
#include "pam-args-parser.h"
#include "pam-handle.h"

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
        auto reply = this->m_authManagerProxy->DestroySession(this->m_authSessionProxy->iD());
        reply.waitForFinished();
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
    m_lastNotifiedAuthType = this->m_authSessionProxy->authType();
    auto connected = connect(m_authSessionProxy, &AuthSessionProxy::AuthTypeChanged, this, &Authentication::onAuthTypeChanged);
    return PAM_SUCCESS;
}

int Authentication::startAuth()
{
    this->m_pamHandle->syslog(LOG_DEBUG, "Start authentication.");

    m_pendingAuthMessages.clear();
    m_pendingAuthPrompts.clear();
    m_pendingFinishResult = -1;
    m_inStartAuth = true;

    auto reply = this->m_authSessionProxy->StartAuth();
    reply.waitForFinished();
    m_inStartAuth = false;

    if (reply.isError())
    {
        m_pendingAuthMessages.clear();
        m_pendingAuthPrompts.clear();
        m_pendingFinishResult = -1;
        this->m_pamHandle->syslog(LOG_WARNING,
                                  QString("Call startAuth failed: %1, sessionID=%2, authType=%3.")
                                      .arg(reply.error().message())
                                      .arg(m_sessionID)
                                      .arg(this->m_authSessionProxy->authType()));
        return PAM_SYSTEM_ERR;
    }

    this->m_pamHandle->syslog(LOG_DEBUG,
                              QString("StartAuth succeeded, sessionID=%1").arg(m_sessionID));
    flushPendingSessionSignals();
    return PAM_SUCCESS;
}

void Authentication::flushPendingSessionSignals()
{
    const auto pendingPrompts = m_pendingAuthPrompts;
    m_pendingAuthPrompts.clear();

    // 先同步处理缓冲的协议 prompt（与 onAuthMessage 同理，避免 DBus 回调栈上
    // sendQuestionPrompt 嵌套阻塞与 PAM 主线程互等死锁）。
    for (const auto& prompt : pendingPrompts)
    {
        this->onAuthPrompt(prompt.first, prompt.second);
    }

    const auto pendingMessages = m_pendingAuthMessages;
    m_pendingAuthMessages.clear();
    const int pendingFinish = m_pendingFinishResult;
    m_pendingFinishResult = -1;

    if (pendingMessages.isEmpty())
    {
        if (pendingFinish >= 0)
        {
            this->flushPendingSshMessagesBeforeFinish();
            this->scheduleFinishAuth(pendingFinish);
        }
        return;
    }

    // 逐条异步投递，避免 StartAuth 返回后在 worker 栈上同步 conv 与主 PAM 线程互等
    auto deliverIndex = std::make_shared<int>(0);
    auto deliverOne = std::make_shared<std::function<void()>>();
    *deliverOne = [this, pendingMessages, pendingFinish, deliverIndex, deliverOne]() {
        if (*deliverIndex < pendingMessages.size())
        {
            const auto item = pendingMessages.at(*deliverIndex);
            ++(*deliverIndex);
            this->deliverAuthMessage(item.first, item.second);
            QTimer::singleShot(0, this, [deliverOne]() {
                (*deliverOne)();
            });
            return;
        }
        if (pendingFinish >= 0)
        {
            this->flushPendingSshMessagesBeforeFinish();
            this->scheduleFinishAuth(pendingFinish);
        }
    };
    QTimer::singleShot(0, this, [deliverOne]() {
        (*deliverOne)();
    });
}

void Authentication::finishAuth(int result)
{
    this->m_pamHandle->syslog(LOG_DEBUG,
                              QString("Authentication thread ready quit,result:%1").arg(result));
    this->m_pamHandle->finish(result);
}

void Authentication::scheduleFinishAuth(int result)
{
    QTimer::singleShot(0, this, [this, result]() {
        this->finishAuth(result);
    });
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

QString Authentication::mergePendingSshInfoIntoPrompt(const QString &text)
{
    if (this->m_pendingSshInfoMessages.isEmpty())
    {
        return text;
    }
    auto prompt = this->m_pendingSshInfoMessages.join(QLatin1Char('\n')) + QLatin1Char('\n') + text;
    this->m_pendingSshInfoMessages.clear();
    return prompt;
}

void Authentication::flushPendingSshMessagesBeforeFinish()
{
    if (!this->isSshService() || this->m_pendingSshInfoMessages.isEmpty())
    {
        return;
    }

    const auto text = this->m_pendingSshInfoMessages.join(QLatin1Char('\n'));
    this->m_pendingSshInfoMessages.clear();

    QString response;
    const auto retval = this->m_pamHandle->sendQuestionPrompt(text, response);
    if (retval != PAM_SUCCESS)
    {
        this->m_pamHandle->syslog(LOG_WARNING,
                                  QString("Flush pending ssh message via prompt failed,result:%1,text:%2")
                                      .arg(retval)
                                      .arg(text));
    }
}

void Authentication::onAuthPrompt(const QString &text, int type)
{
    if (m_inStartAuth)
    {
        m_pendingAuthPrompts.append(qMakePair(text, type));
        return;
    }

    QString prompt = text;
    if (this->isSshService() && !this->m_pendingSshInfoMessages.isEmpty())
    {
        prompt = this->mergePendingSshInfoIntoPrompt(text);
    }

    QString response;
    int32_t retval = PAM_SUCCESS;
    switch (type)
    {
    case KADPromptType::KAD_PROMPT_TYPE_QUESTION:
        retval = this->m_pamHandle->sendQuestionPrompt(prompt, response);
        break;
    case KADPromptType::KAD_PROMPT_TYPE_SECRET:
        retval = this->m_pamHandle->sendSecretPrompt(prompt, response);
        break;
    default:
        this->m_pamHandle->syslog(LOG_WARNING, QString("Unknown message type: %1").arg(type));
        retval = PAM_AUTH_ERR;
        break;
    }

    if (retval != PAM_SUCCESS)
    {
        this->scheduleFinishAuth(retval);
    }
    else
    {
        this->m_authSessionProxy->ResponsePrompt(response);
    }
}

bool Authentication::isSshService() const
{
    return this->m_serviceName == QLatin1String("sshd");
}

void Authentication::onAuthMessage(const QString &text, int type)
{
    if (m_inStartAuth)
    {
        m_pendingAuthMessages.append(qMakePair(text, type));
        return;
    }
    this->handleAuthMessage(text, type);
}

void Authentication::handleAuthMessage(const QString &text, int type)
{
    // 统一异步投递到 worker 事件循环，避免 DBus 回调栈上同步 conv 死锁
    QTimer::singleShot(0, this, [this, text, type]() {
        this->deliverAuthMessage(text, type);
    });
}

void Authentication::deliverAuthMessage(const QString &text, int type)
{
    if (this->isSshService() &&
        (type == KADMessageType::KAD_MESSAGE_TYPE_INFO || type == KADMessageType::KAD_MESSAGE_TYPE_ERROR))
    {
        this->m_pendingSshInfoMessages.append(text);
        return;
    }

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
        this->m_pamHandle->syslog(LOG_WARNING, QString("Authentication message failed(info or msg may not supported by application),result:%1,session ID:%2,text:%3,type:%4").arg(retval).arg(m_sessionID).arg(text).arg(type));
        // 显示消息，失败了只记录日志，不退出认证。gnome程序显示消息的返回是PAM_AUTH_ERR（gnome bug）。
        // this->finishAuth(retval);
    }
}

void Authentication::onAuthFailed()
{
    this->m_pamHandle->syslog(LOG_INFO,
                              QString("Authentication AuthFailed signal,session ID:%1").arg(m_sessionID));
    if (m_inStartAuth)
    {
        m_pendingFinishResult = PAM_AUTH_ERR;
        return;
    }
    this->flushPendingSshMessagesBeforeFinish();
    this->scheduleFinishAuth(PAM_AUTH_ERR);
}

void Authentication::onAuthUnavail()
{
    this->m_pamHandle->syslog(LOG_DEBUG, QString("Authentication unavail,session ID:%1").arg(m_sessionID));
    if (m_inStartAuth)
    {
        m_pendingFinishResult = PAM_AUTHINFO_UNAVAIL;
        return;
    }
    this->flushPendingSshMessagesBeforeFinish();
    this->scheduleFinishAuth(PAM_AUTHINFO_UNAVAIL);
}

void Authentication::onAuthSuccessed(const QString &userName)
{
    if (!userName.isEmpty())
    {
        this->m_pamHandle->setItem(PAM_USER, userName);
    }

    auto authMode = this->m_authManagerProxy->authMode();
    if (authMode == KAD_AUTH_MODE_AND)
    {
        this->notifyAuthType(KAD_AUTH_TYPE_PASSWORD);
    }

    this->m_pamHandle->syslog(LOG_DEBUG, QString("Authentication successed,session ID:%1").arg(m_sessionID));
    this->m_pendingSshInfoMessages.clear();
    this->scheduleFinishAuth(PAM_SUCCESS);
}

void Authentication::onAuthTypeChanged(int authType)
{
    if (m_inStartAuth)
    {
        return;
    }
    if (m_lastNotifiedAuthType == authType)
    {
        this->m_pamHandle->syslogDirect(LOG_DEBUG,
                                  QString("Skip duplicate AuthTypeChanged notify,session ID:%1 authType:%2")
                                      .arg(m_sessionID)
                                      .arg(authType));
        return;
    }
    m_lastNotifiedAuthType = authType;
    this->notifyAuthType(authType);
}

}  // namespace Kiran
