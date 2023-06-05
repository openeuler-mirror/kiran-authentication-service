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

#include "src/daemon/session.h"
#include "auxiliary.h"
#include "logging-category.h"
#include "src/daemon/auth-manager.h"
#include "src/daemon/device/device-adaptor-factory.h"
#include "src/daemon/error.h"
#include "src/daemon/proxy/dbus-daemon-proxy.h"
#include "src/daemon/session_adaptor.h"
#include "src/daemon/user-manager.h"
#include "src/utils/utils.h"

#include <kas-authentication-i.h>
#include <kiran-authentication-devices/kiran-auth-device-i.h>
#include <qt5-log-i.h>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QEventLoop>
#include <QJsonDocument>
#include <QMetaEnum>

namespace Kiran
{
Session::Session(uint32_t sessionID,
                 const QString &serviceName,
                 const QString &userName,
                 KADAuthApplication authApp,
                 QObject *parent)
    : QObject(parent),
      m_sessionID(sessionID),
      m_serviceName(serviceName),
      m_userName(userName),
      m_loginUserSwitchable(false),
      m_authApplication(authApp),
      m_authMode(KADAuthMode::KAD_AUTH_MODE_OR),
      m_authType(KADAuthType::KAD_AUTH_TYPE_NONE)
{
    this->m_dbusAdaptor = new SessionAdaptor(this);
    this->m_objectPath = QDBusObjectPath(QString("%1/%2").arg(KAD_SESSION_DBUS_OBJECT_PATH).arg(this->m_sessionID));

    this->m_authMode = AuthManager::getInstance()->getAuthMode();
    auto authTypes = AuthManager::getInstance()->GetAuthTypeByApp(m_authApplication);
    this->m_authType = authTypes.count() > 0 ? authTypes.first() : KAD_AUTH_TYPE_NONE;
    if (m_authMode == KAD_AUTH_MODE_AND)
    {
        this->m_authOrderWaiting = authTypes;
        this->m_verifyInfo.m_authenticatedUserName = m_userName;
    }

    auto systemConnection = QDBusConnection::systemBus();
    if (!systemConnection.registerObject(this->m_objectPath.path(), this))
    {
        KLOG_WARNING() << m_sessionID << "can't register object:" << systemConnection.lastError();
    }

    KLOG_DEBUG() << QString("new session authmode(%1),login user switchable(%2),default auth type(%3),auth order(%4)")
                        .arg(m_authMode)
                        .arg(m_loginUserSwitchable)
                        .arg(Utils::authTypeEnum2Str(m_authType))
                        .arg(Utils::authOrderEnum2Str(m_authOrderWaiting).join(","));
}

Session::~Session()
{
}

int Session::getAuthType() const
{
    return m_authType;
}

uint Session::getID() const
{
    return m_sessionID;
}

QString Session::getRSAPublicKey() const
{
    // FIXME:暂时不做加密
    return "";
}

QString Session::getUsername() const
{
    return m_userName;
}

void Session::ResponsePrompt(const QString &text)
{
    RETURN_IF_FALSE(m_waitForResponseFunc);
    m_waitForResponseFunc(text);
    m_waitForResponseFunc = nullptr;
}

void Session::SetAuthType(int authType)
{
    if (this->m_authMode == KADAuthMode::KAD_AUTH_MODE_AND)
    {
        KLOG_WARNING() << m_sessionID << "can't change authentication type in this authentication mode" << m_authMode;
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_FAILED);
    }

    if (authType <= KAD_AUTH_TYPE_NONE || authType >= KAD_AUTH_TYPE_LAST)
    {
        DBUS_ERROR_REPLY_AND_RET(QDBusError::InvalidArgs, KADErrorCode::ERROR_INVALID_ARGUMENT);
    }
    this->m_authType = authType;
    KLOG_DEBUG() << m_sessionID << "session change auth type to:" << this->m_authType;
}

void Session::StartAuth()
{
    if (this->m_verifyInfo.m_requestID > 0)
    {
        KLOG_WARNING() << m_sessionID << "auth is in process,start auth failed";
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_USER_IDENTIFIYING);
    }

    KLOG_DEBUG() << m_sessionID << "start auth";
    this->m_verifyInfo.m_inAuth = true;
    this->m_verifyInfo.m_dbusMessage = this->message();
    this->startPhaseAuth();
}

void Session::StopAuth()
{
    KLOG_DEBUG() << m_sessionID << "stop auth";

    m_waitForResponseFunc = nullptr;

    if (this->m_verifyInfo.m_requestID != -1 &&
        this->m_verifyInfo.deviceAdaptor)
    {
        this->m_verifyInfo.deviceAdaptor->stop(this->m_verifyInfo.m_requestID);
    }

    this->m_verifyInfo.m_inAuth = false;
}

bool Session::GetLoginUserSwitchable()
{
    return m_loginUserSwitchable;
}

void Session::SetLoginUserSwitchable(bool switchable)
{
    if (this->m_authMode == KADAuthMode::KAD_AUTH_MODE_AND)
    {
        KLOG_WARNING() << m_sessionID << "can't set login-user-switchable in this authentication mode" << m_authMode;
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_FAILED);
    }

    if (m_verifyInfo.m_inAuth)
    {
        KLOG_WARNING() << m_sessionID << "can't set login-user-switchable when authentication is started";
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_FAILED);
    }

    RETURN_IF_FALSE(switchable != m_loginUserSwitchable);
    m_loginUserSwitchable = switchable;
    KLOG_DEBUG() << m_sessionID << "set login-user-switchable:" << m_loginUserSwitchable;
}

int32_t Session::getPriority()
{
    return DeviceRequestPriority::DEVICE_REQUEST_PRIORITY_LOW;
}

int64_t Session::getPID()
{
    return DBusDaemonProxy::getDefault()->getConnectionUnixProcessID(this->m_verifyInfo.m_dbusMessage);
}

QString Session::getSpecifiedUser()
{
    return this->m_userName;
}

void Session::queued(QSharedPointer<DeviceRequest> request)
{
    this->m_verifyInfo.m_requestID = request->reqID;
    KLOG_DEBUG() << m_sessionID << "session (request id:" << request->reqID << ") queued";
    auto tips = QString(tr("Please wait while the %1 request is processed")).arg(Utils::authTypeEnum2LocaleStr(m_authType));
    Q_EMIT this->AuthMessage(tips, KAD_MESSAGE_TYPE_INFO);
}

void Session::interrupt()
{
    KLOG_DEBUG() << m_sessionID << "session (request id:" << this->m_verifyInfo.m_requestID << ") interrupt";
}

void Session::cancel()
{
    KLOG_DEBUG() << m_sessionID << "session (request id:" << this->m_verifyInfo.m_requestID << ") cancel";
    this->finishPhaseAuth(SESSION_AUTH_CANCEL);
}

void Session::end()
{
    KLOG_DEBUG() << m_sessionID << "session (request id:" << this->m_verifyInfo.m_requestID << ") end";
    this->m_verifyInfo.m_requestID = -1;
    this->m_verifyInfo.deviceAdaptor = nullptr;
}

void Session::onIdentifyStatus(const QString &bid, int result, const QString &message)
{
    KLOG_DEBUG() << m_sessionID << "verify identify  status:" << bid << result << message;

    if (!this->matchUser(this->m_verifyInfo.authType, bid) &&
        result == IdentifyStatus::IDENTIFY_STATUS_MATCH)
    {
        KLOG_DEBUG() << m_sessionID << "feature match successfully, but it isn't a legal user.";
        result = IdentifyStatus::IDENTIFY_STATUS_NOT_MATCH;
    }

    auto verifyResultStr = Utils::identifyResultEnum2Str(result);
    if (result == IdentifyStatus::IDENTIFY_STATUS_MATCH)
    {
        Q_EMIT this->AuthMessage(verifyResultStr, KADMessageType::KAD_MESSAGE_TYPE_INFO);
    }
    else if (result == IdentifyStatus::IDENTIFY_STATUS_NOT_MATCH)
    {
        Q_EMIT this->AuthMessage(verifyResultStr, KADMessageType::KAD_MESSAGE_TYPE_ERROR);
    }
    else
    {
        Q_EMIT this->AuthMessage(message, KADMessageType::KAD_MESSAGE_TYPE_INFO);
    }

    if (result == IdentifyStatus::IDENTIFY_STATUS_MATCH ||
        result == IdentifyStatus::IDENTIFY_STATUS_NOT_MATCH)
    {
        this->finishPhaseAuth(result == IDENTIFY_STATUS_MATCH ? SESSION_AUTH_MATCH : SESSION_AUTH_NOT_MATCH);
    }
}

void Session::startPhaseAuth()
{
    m_waitForResponseFunc = nullptr;

    // 开始阶段认证前,通知认证类型状态变更
    emit this->m_dbusAdaptor->AuthTypeChanged(this->m_authType);

    switch (this->m_authType)
    {
    case KAD_AUTH_TYPE_UKEY:
        startUkeyAuth();
        break;
    case KAD_AUTH_TYPE_PASSWORD:
        startPasswdAuth();
        break;
    default:
        startGeneralAuth();
        break;
    }
}

void Session::startUkeyAuth()
{
    m_waitForResponseFunc = [this](const QString &response)
    {
        QJsonDocument jsonDoc(QJsonObject{QJsonObject{{"ukey", QJsonObject{{"pin", response}}}}});
        startGeneralAuth(jsonDoc.toJson());
    };

    KLOG_DEBUG() << "auth prompt: input ukey code";
    Q_EMIT this->AuthMessage(tr("Insert the UKey and enter the PIN code"), KADMessageType::KAD_MESSAGE_TYPE_INFO);
    Q_EMIT this->AuthPrompt(tr("please input ukey code."), KADPromptType::KAD_PROMPT_TYPE_SECRET);
}

void Session::startPasswdAuth()
{
    KLOG_DEBUG() << "The authentication service does not take over password authentication,ignore!";

    this->m_verifyInfo.m_inAuth = true;
    if (this->m_verifyInfo.m_authenticatedUserName.isEmpty())
    {
        this->m_verifyInfo.m_authenticatedUserName = m_userName;
    }

    this->finishPhaseAuth(SESSION_AUTH_PASSWD_AUTH_IGNORE);
}

void Session::startGeneralAuth(const QString &extraInfo)
{
    auto deviceType = Utils::authType2DeviceType(this->m_authType);
    if (deviceType == -1)
    {
        auto authTypeStr = Utils::authTypeEnum2Str(this->m_authType);
        KLOG_WARNING() << m_sessionID << "start phase auth failed,invalid auth type:" << m_authType;
        Q_EMIT this->AuthMessage(tr(QString("Auth type %1 invalid").arg(authTypeStr).toStdString().c_str()), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        this->finishPhaseAuth(SESSION_AUTH_INTERNAL_ERROR);
        return;
    }

    auto device = DeviceAdaptorFactory::getInstance()->getDeviceAdaptor(this->m_authType);
    if (!device)
    {
        auto authTypeStr = Utils::authTypeEnum2Str(this->m_authType);
        KLOG_WARNING() << m_sessionID << "start phase auth failed,can not find device,auth type:" << m_authType;
        Q_EMIT this->AuthMessage(QString(tr("can not find %1 device")).arg(Utils::authTypeEnum2LocaleStr(this->m_authType)), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        this->finishPhaseAuth(SESSION_AUTH_NO_DEVICE);
        return;
    }

    QJsonObject rootObject;
    if (!extraInfo.isEmpty())
    {
        QJsonDocument tempDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
        rootObject = tempDoc.object();
    }

    QJsonDocument doc(rootObject);

    QStringList bids;
    if (!m_loginUserSwitchable)
    {
        auto user = UserManager::getInstance()->findUser(this->m_userName);
        if (user)
        {
            bids = user->getBIDs(this->m_authType);
        }
    }

    KLOG_DEBUG() << m_sessionID << "start phase auth for auth type:" << m_authType;
    rootObject["feature_ids"] = QJsonArray::fromStringList(bids);
    this->m_verifyInfo.deviceAdaptor = device;
    this->m_verifyInfo.authType = this->m_authType;
    this->m_verifyInfo.deviceAdaptor->identify(this, doc.toJson(QJsonDocument::Compact));
}

void Session::finishPhaseAuth(SessionAuthResult authResult)
{
    auto authResultEnum = QMetaEnum::fromType<Session::SessionAuthResult>();
    auto authResultKey = authResultEnum.valueToKey(authResult);

    KLOG_DEBUG() << m_sessionID
                 << "session finish phase auth, auth type:" << this->m_authType
                 << "auth result:" << (authResultKey ? authResultKey : "NULL");

    switch (authResult)
    {
    case SESSION_AUTH_MATCH:
    case SESSION_AUTH_PASSWD_AUTH_IGNORE:
    {
        if (this->m_authMode == KAD_AUTH_MODE_OR)
        {
            // 多路认证，认证一个通过即算通过
            this->finishAuth(authResult);
        }
        else
        {
            // 检测是否所有认证类型都已通过
            // 存在还未认证，则继续开始认证
            if (this->m_authOrderWaiting.size() > 0)
            {
                this->m_authOrderWaiting.removeOne(this->m_authType);
            }

            if (this->m_authOrderWaiting.size() == 0)
            {
                this->finishAuth(SESSION_AUTH_MATCH);
            }
            else
            {
                this->m_authType = this->m_authOrderWaiting.first();
                this->startPhaseAuth();
            }
        }
        break;
    }
    case SESSION_AUTH_NOT_MATCH:
    case SESSION_AUTH_NO_DEVICE:
    case SESSION_AUTH_CANCEL:
    case SESSION_AUTH_INTERNAL_ERROR:
    {
        // 阶段认证失败，则算失败
        this->finishAuth(authResult);
        break;
    }
    default:
        KLOG_ERROR() << m_sessionID << "invalid session auth result:" << authResult << (authResultKey ? authResultKey : "NULL");
        break;
    }
}

void Session::finishAuth(SessionAuthResult authResult)
{
    auto authResultEnum = QMetaEnum::fromType<Session::SessionAuthResult>();
    auto authResultKey = authResultEnum.valueToKey(authResult);
    KLOG_DEBUG() << m_sessionID << "finish auth\n"
                 << "auth result:" << (authResultKey ? authResultKey : "NULL");

    const QString &authenticatedUserName = this->m_verifyInfo.m_authenticatedUserName;
    bool isSuccess = (authResult == SESSION_AUTH_MATCH) || (authResult == SESSION_AUTH_PASSWD_AUTH_IGNORE);
    if (isSuccess)
    {
        if (authenticatedUserName.isEmpty())
        {
            KLOG_ERROR() << "authentication succeeded, but the user name was empty!";
        }
        else
        {
            auto user = UserManager::getInstance()->findUser(authenticatedUserName);
            if (user)
            {
                user->setFailures(0);
            }
            Q_EMIT this->AuthSuccessed(authenticatedUserName);
        }
    }
    else
    {
        // 是否记录内部错误，内部错误达到上限将不能使用生物认证，只能使用密码解锁
        // 只在多路认证情况下，并且是特征不匹配的情况下记录
        bool recordInternalFailure = (this->m_authMode == KAD_AUTH_MODE_OR) &&
                                     (authResult == SESSION_AUTH_NOT_MATCH);

        if (recordInternalFailure)
        {
            // 认证失败，未通过一次阶段认证，记录失败用户为发起登录请求的用户
            const QString &currentUser = authenticatedUserName.isEmpty() ? m_userName : authenticatedUserName;
            auto user = UserManager::getInstance()->findUser(currentUser);
            if (user)
            {
                user->setFailures(user->getFailures() + 1);
            }
        }

        // 是否记录外部failock错误，达到上限，将会锁定账户
        // 多因子认证情况下，任何错误，都将被failock记录
        // 多路认证情况下，只有特征不匹配才被failock记录
        bool recordFailure = (this->m_authMode == KAD_AUTH_MODE_AND) ||
                             (authResult == SESSION_AUTH_NOT_MATCH);

        if (recordFailure)
        {
            Q_EMIT this->AuthFailed();
        }
        else
        {
            Q_EMIT this->AuthUnavail();
        }
    }

    m_verifyInfo.m_inAuth = false;
}

bool Session::matchUser(int32_t authType, const QString &dataID)
{
    RETURN_VAL_IF_TRUE(dataID.isEmpty(), false);

    auto iid = Utils::GenerateIID(authType, dataID);
    auto user = UserManager::getInstance()->getUserByIID(iid);

    RETURN_VAL_IF_TRUE(!user, false);

    // 特征匹配到的用户
    auto userName = user->getUserName();

    // 发起认证的用户
    auto specifiedUser = this->getSpecifiedUser();

    // 发起认证用户和特征匹配到的用户不一致 并且 登录用户切换功能未开启
    RETURN_VAL_IF_TRUE((userName != specifiedUser) && !m_loginUserSwitchable, false);

    // 用户切换功能只在第一阶段认证中生效，第一阶段认证通过后，后面的认证用户匹配必需和第一次一样
    RETURN_VAL_IF_TRUE(!this->m_verifyInfo.m_authenticatedUserName.isEmpty() && this->m_verifyInfo.m_authenticatedUserName != userName, false);

    // TODO: 会话复用时需要清理变量
    this->m_verifyInfo.m_authenticatedUserName = userName;
    return true;
}

}  // namespace Kiran
