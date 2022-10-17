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
#include <auxiliary.h>
#include <biometrics-i.h>
#include <kas-authentication-i.h>
#include <qt5-log-i.h>
#include <QDBusConnection>
#include "src/daemon/auth-manager.h"
#include "src/daemon/device/device-request-dispatcher.h"
#include "src/daemon/error.h"
#include "src/daemon/proxy/dbus-daemon-proxy.h"
#include "src/daemon/session_adaptor.h"
#include "src/daemon/user-manager.h"
#include "src/daemon/utils.h"

namespace Kiran
{
Session::SessionDeviceRequestSource::SessionDeviceRequestSource(Session *session) : m_session(session),
                                                                                    m_requestID(-1)
{
}

int32_t Session::SessionDeviceRequestSource::getPriority()
{
    return DeviceRequestPriority::DEVICE_REQUEST_PRIORITY_LOW;
}

int64_t Session::SessionDeviceRequestSource::getPID()
{
    return DBusDaemonProxy::getDefault()->getConnectionUnixProcessID(this->m_dbusMessage);
}

QString Session::SessionDeviceRequestSource::getSpecifiedUser()
{
    return this->m_session->m_userName;
}

void Session::SessionDeviceRequestSource::event(const DeviceEvent &deviceEvent)
{
    KLOG_DEBUG() << "Receive device event, eventType: " << deviceEvent.eventType;

    switch (deviceEvent.eventType)
    {
    case DeviceEventType::DEVICE_EVENT_TYPE_FP_IDENTIFY_STATUS:
        this->fpIdentifyStatusEvent(deviceEvent.args);
        break;
    default:
        break;
    }
}

void Session::SessionDeviceRequestSource::fpIdentifyStatusEvent(const QVariantMap &vars)
{
    auto bid = vars[DEVICE_EVENT_ARGS_BID].toString();
    auto verifyResult = vars[DEVICE_EVENT_ARGS_RESULT].toInt();

    if (!this->matchUser(KADAuthType::KAD_AUTH_TYPE_FINGERPRINT, bid) &&
        verifyResult == FPVerifyResult::FP_VERIFY_RESULT_MATCH)
    {
        KLOG_DEBUG("Fingerprint match successfully, but it isn't a legal user.");
        verifyResult = FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH;
    }

    auto verifyResultStr = Utils::fpVerifyResultEnum2Str(verifyResult);
    if (verifyResult == FPVerifyResult::FP_VERIFY_RESULT_MATCH)
    {
        Q_EMIT this->m_session->AuthMessage(verifyResultStr, KADMessageType::KAD_MESSAGE_TYPE_INFO);
    }
    else
    {
        Q_EMIT this->m_session->AuthMessage(verifyResultStr, KADMessageType::KAD_MESSAGE_TYPE_ERROR);
    }

    if (verifyResult == FPVerifyResult::FP_VERIFY_RESULT_MATCH ||
        verifyResult == FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH)
    {
        this->m_session->finishPhaseAuth(verifyResult == FPVerifyResult::FP_VERIFY_RESULT_MATCH);
    }
}

bool Session::SessionDeviceRequestSource::matchUser(int32_t authType, const QString &dataID)
{
    RETURN_VAL_IF_TRUE(dataID.isEmpty(), false);

    auto iid = Utils::GenerateIID(authType, dataID);
    auto user = UserManager::getInstance()->getUserByIID(iid);

    RETURN_VAL_IF_TRUE(!user, false);
    auto userName = user->getUserName();
    auto specifiedUser = this->getSpecifiedUser();
    // 如果有指定认证用户，任何阶段都不能切换用户
    RETURN_VAL_IF_TRUE(!specifiedUser.isEmpty() && specifiedUser != userName, false);
    // 如果未指定认证用户，只有第一阶段认证时可以切换用户，后面阶段必须跟第一阶段认证的用户相同
    RETURN_VAL_IF_TRUE(!this->m_authenticatedUserName.isEmpty() && this->m_authenticatedUserName != userName, false);
    // TODO: 会话复用时需要清理变量
    this->m_authenticatedUserName = userName;
    return true;
}

Session::Session(uint32_t sessionID,
                 const QString &serviceName,
                 const QString &userName,
                 QObject *parent) : QObject(parent),
                                    m_sessionID(sessionID),
                                    m_serviceName(serviceName),
                                    m_userName(userName),
                                    m_authMode(KADAuthMode::KAD_AUTH_MODE_OR),
                                    m_authType(KADAuthType::KAD_AUTH_TYPE_NONE)
{
    this->m_dbusAdaptor = new SessionAdaptor(this);
    this->m_objectPath = QDBusObjectPath(QString("%1/%2").arg(KAD_SESSION_DBUS_OBJECT_PATH).arg(this->m_sessionID));
    this->m_authMode = AuthManager::getInstance()->getAuthMode();
    this->m_authType = this->calcNextAuthType();

    auto systemConnection = QDBusConnection::systemBus();
    if (!systemConnection.registerObject(this->m_objectPath.path(), this))
    {
        KLOG_WARNING() << "Can't register object:" << systemConnection.lastError();
    }
}

void Session::ResponsePrompt(const QString &text)
{
}

void Session::SetAuthType(int authType)
{
    if (this->m_authMode == KADAuthMode::KAD_AUTH_MODE_OR)
    {
        this->m_authType = authType;
    }
    // 其他模式下不能修改认证顺序
    else
    {
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_FAILED);
    }
}

void Session::StartAuth()
{
    if (this->m_sessionDeviceRequestSource)
    {
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_USER_IDENTIFIYING);
    }

    this->m_sessionDeviceRequestSource = QSharedPointer<SessionDeviceRequestSource>::create(this);
    this->m_sessionDeviceRequestSource->setDBusMessage(this->message());
    this->startPhaseAuth();
}

void Session::StopAuth()
{
    if (this->m_deviceRequest)
    {
        DeviceRequestType requestType = DeviceRequestType::DEVICE_REQUEST_TYPE_NONE;
        switch (this->m_deviceRequest->reqType)
        {
        case DeviceRequestType::DEVICE_REQUEST_TYPE_FP_IDENTIFY_START:
            requestType = DeviceRequestType::DEVICE_REQUEST_TYPE_FP_IDENTIFY_STOP;
            break;
        case DeviceRequestType::DEVICE_REQUEST_TYPE_FP_VERIFY_START:
            requestType = DeviceRequestType::DEVICE_REQUEST_TYPE_FP_VERIFY_STOP;
            break;
        default:
            break;
        }

        if (requestType != DeviceRequestType::DEVICE_REQUEST_TYPE_NONE)
        {
            this->m_deviceRequest = QSharedPointer<DeviceRequest>::create(DeviceRequest{
                .reqType = requestType,
                .time = QTime::currentTime(),
                .reqID = -1,
                .source = this->m_sessionDeviceRequestSource.dynamicCast<DeviceRequestSource>()});
            DeviceRequestDispatcher::getDefault()->deliveryRequest(this->m_deviceRequest);
        }
    }
}

int32_t Session::calcNextAuthType()
{
    auto user = UserManager::getInstance()->findUser(this->m_userName);
    auto authOrder = AuthManager::getInstance()->getAuthOrder();

    RETURN_VAL_IF_FALSE(authOrder.size() > 0, KADAuthType::KAD_AUTH_TYPE_NONE);
    RETURN_VAL_IF_TRUE(!user, authOrder.first());

    for (auto authType : authOrder)
    {
        RETURN_VAL_IF_TRUE(user->hasIdentification(authType), authType);
    }

    return KADAuthType::KAD_AUTH_TYPE_NONE;
}

void Session::startPhaseAuth()
{
    switch (this->m_authType)
    {
    case KADAuthType::KAD_AUTH_TYPE_FINGERPRINT:
        this->startPhaseFPAuth();
        break;
    default:
    {
        auto authTypeStr = Utils::authTypeEnum2Str(this->m_authType);
        Q_EMIT this->AuthMessage(tr(QString("Auth type %1 invalid").arg(authTypeStr).toStdString().c_str()),
                                 KADMessageType::KAD_MESSAGE_TYPE_ERROR);

        this->finishPhaseAuth(false);
        break;
    }
    }
}

void Session::startPhaseFPAuth()
{
    QStringList bids;
    auto user = UserManager::getInstance()->findUser(this->m_userName);
    if (user)
    {
        bids = user->getDataIDs(this->m_authType);
    }

    Q_EMIT this->AuthMessage(QObject::tr("Please press the fingerprint."), KADMessageType::KAD_MESSAGE_TYPE_INFO);

    this->m_deviceRequest = QSharedPointer<DeviceRequest>::create(DeviceRequest{
        .reqType = DeviceRequestType::DEVICE_REQUEST_TYPE_FP_IDENTIFY_START,
        .time = QTime::currentTime(),
        .reqID = -1,
        .source = this->m_sessionDeviceRequestSource.dynamicCast<DeviceRequestSource>()});
    this->m_deviceRequest->args.insert(DEVICE_REQUEST_ARGS_BIDS, bids);
    DeviceRequestDispatcher::getDefault()->deliveryRequest(this->m_deviceRequest);
}

void Session::finishPhaseAuth(bool isSuccess)
{
    // 如果阶段认证失败，则直接结束
    if (!isSuccess)
    {
        this->finishAuth(isSuccess);
        return;
    }

    // 阶段认证成功则进入下个阶段
    switch (this->m_authMode)
    {
    case KADAuthMode::KAD_AUTH_MODE_OR:
        this->finishAuth(isSuccess);
        break;
    case KADAuthMode::KAD_AUTH_MODE_AND:
    {
        this->m_authOrderWaiting.removeOne(this->m_authType);
        if (this->m_authOrderWaiting.size() == 0)
        {
            this->finishAuth(isSuccess);
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

void Session::finishAuth(bool isSuccess)
{
    auto userName = this->m_sessionDeviceRequestSource->getAuthenticatedUserName();
    if (isSuccess && !userName.isEmpty())
    {
        Q_EMIT this->AuthSuccessed(userName);
    }
    else
    {
        Q_EMIT this->AuthFailed();
    }

    this->m_sessionDeviceRequestSource = nullptr;
}

}  // namespace Kiran
