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
    }

    KLOG_DEBUG() << QString("new session authmode(%1),login user switchable(%2),default auth type(%3),auth order(%4)")
                        .arg(m_authMode)
                        .arg(m_loginUserSwitchable)
                        .arg(Utils::authTypeEnum2Str(m_authType))
                        .arg(Utils::authOrderEnum2Str(m_authOrderWaiting).join(","));

    auto systemConnection = QDBusConnection::systemBus();
    if (!systemConnection.registerObject(this->m_objectPath.path(), this))
    {
        KLOG_WARNING() << m_sessionID << "can't register object:" << systemConnection.lastError();
    }
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

    if (this->m_authType == KAD_AUTH_TYPE_NONE || this->m_authType == KAD_AUTH_TYPE_PASSWORD)
    {
        KLOG_WARNING() << m_sessionID << "auth type is invalid" << this->m_authType << ",start auth failed";
        DBUS_ERROR_REPLY_AND_RET(QDBusError::Failed, KADErrorCode::ERROR_FAILED);
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
    auto tips = QString("Please wait while the %1 request is processed").arg(Utils::authTypeEnum2LocaleStr(m_authType));
    Q_EMIT this->AuthMessage(tips,KAD_MESSAGE_TYPE_INFO);
}

void Session::interrupt()
{
    KLOG_DEBUG() << m_sessionID << "session (request id:" << this->m_verifyInfo.m_requestID << ") interrupt";
}

void Session::cancel()
{
    KLOG_DEBUG() << m_sessionID << "session (request id:" << this->m_verifyInfo.m_requestID << ") cancel";
    this->finishPhaseAuth(false, false);
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
        result == IdentifyResult::IDENTIFY_RESULT_MATCH)
    {
        KLOG_DEBUG() << m_sessionID << "feature match successfully, but it isn't a legal user.";
        result = IdentifyResult::IDENTIFY_RESULT_NOT_MATCH;
    }

    auto verifyResultStr = Utils::identifyResultEnum2Str(result);
    if (result == IdentifyResult::IDENTIFY_RESULT_MATCH)
    {
        Q_EMIT this->AuthMessage(verifyResultStr, KADMessageType::KAD_MESSAGE_TYPE_INFO);
    }
    else
    {
        Q_EMIT this->AuthMessage(verifyResultStr, KADMessageType::KAD_MESSAGE_TYPE_ERROR);
    }

    if (result == IdentifyResult::IDENTIFY_RESULT_MATCH ||
        result == IdentifyResult::IDENTIFY_RESULT_NOT_MATCH)
    {
        this->finishPhaseAuth(result == IdentifyResult::IDENTIFY_RESULT_MATCH);
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
    default:
        startGeneralAuth();
        break;
    }
}

void Session::startUkeyAuth()
{
    auto deviceAdaptor = DeviceAdaptorFactory::getInstance()->getDeviceAdaptor(this->m_authType);
    if (deviceAdaptor.isNull())
    {
        Q_EMIT this->AuthMessage(tr("The UKey device could not be found"), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        this->finishPhaseAuth(false, m_authMode == KAD_AUTH_MODE_AND);
        return;
    }

    m_waitForResponseFunc = [this](const QString &response)
    {
        QJsonDocument jsonDoc(QJsonObject{QJsonObject{{"ukey", QJsonObject{{"pin", response}}}}});
        startGeneralAuth(jsonDoc.toJson());
    };
    
    KLOG_DEBUG() << "auth prompt: input ukey code";
    Q_EMIT this->AuthPrompt(tr("please input ukey code."), KADPromptType::KAD_PROMPT_TYPE_SECRET);
}

void Session::startGeneralAuth(const QString &extraInfo)
{
    auto deviceType = Utils::authType2DeviceType(this->m_authType);
    if (deviceType == -1)
    {
        auto authTypeStr = Utils::authTypeEnum2Str(this->m_authType);
        KLOG_WARNING() << m_sessionID << "start phase auth failed,invalid auth type:" << m_authType;
        Q_EMIT this->AuthMessage(tr(QString("Auth type %1 invalid").arg(authTypeStr).toStdString().c_str()), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        this->finishPhaseAuth(false, m_authMode == KAD_AUTH_MODE_AND);
        return;
    }

    auto device = DeviceAdaptorFactory::getInstance()->getDeviceAdaptor(this->m_authType);
    if (!device)
    {
        auto authTypeStr = Utils::authTypeEnum2Str(this->m_authType);
        KLOG_WARNING() << m_sessionID << "start phase auth failed,can not find device,auth type:" << m_authType;
        Q_EMIT this->AuthMessage(tr(QString("can not find %1 device").arg(authTypeStr).toStdString().c_str()), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        this->finishPhaseAuth(false, m_authMode == KAD_AUTH_MODE_AND);
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

void Session::finishPhaseAuth(bool isSuccess, bool recordFailure)
{
    KLOG_DEBUG() << m_sessionID
                 << "session finish phase auth, auth type:" << this->m_authType
                 << "auth result:" << isSuccess
                 << "record failure:" << recordFailure;

    // 如果阶段认证失败，则直接结束
    if (!isSuccess)
    {
        this->finishAuth(isSuccess, recordFailure);
        return;
    }

    // 阶段认证成功则进入下个阶段
    switch (this->m_authMode)
    {
    case KADAuthMode::KAD_AUTH_MODE_OR:
        this->finishAuth(isSuccess, recordFailure);
        break;
    case KADAuthMode::KAD_AUTH_MODE_AND:
    {
        this->m_authOrderWaiting.removeOne(this->m_authType);
        if (this->m_authOrderWaiting.size() == 0)
        {
            this->finishAuth(isSuccess, recordFailure);
        }
        else
        {
            this->m_authType = this->m_authOrderWaiting.first();
            this->startPhaseAuth();
        }
        break;
    }
    default:
        break;
    }
}

void Session::finishAuth(bool isSuccess, bool recordFailure)
{
    KLOG_DEBUG() << m_sessionID << "finish auth"
                 << "auth result:" << isSuccess
                 << "record failure:" << recordFailure;

    const QString &authenticatedUserName = this->m_verifyInfo.m_authenticatedUserName;
    if (isSuccess && !authenticatedUserName.isEmpty())
    {
        // 认证成功，清空认证通过用户的生物认证错误次数(针对于登录过程中用户跳转)
        auto user = UserManager::getInstance()->findUser(authenticatedUserName);
        if (user)
        {
            user->setFailures(0);
        }
        Q_EMIT this->AuthSuccessed(authenticatedUserName);
    }
    else
    {
        if (recordFailure)
        {
            // 认证失败，未通过一次阶段认证，记录失败用户为发起登录请求的用户
            const QString &currentUser = authenticatedUserName.isEmpty() ? m_userName : authenticatedUserName;
            auto user = UserManager::getInstance()->findUser(currentUser);
            if (user)
            {
                user->setFailures(user->getFailures() + 1);
            }
        }
        Q_EMIT this->AuthFailed();
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
