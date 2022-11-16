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
#include "src/daemon/device/device-adaptor-factory.h"
#include "src/daemon/error.h"
#include "src/daemon/proxy/dbus-daemon-proxy.h"
#include "src/daemon/session_adaptor.h"
#include "src/daemon/user-manager.h"
#include "src/daemon/utils.h"

namespace Kiran
{
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
    if (this->m_verifyInfo.m_requestID > 0)
    {
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_USER_IDENTIFIYING);
    }
    this->m_verifyInfo.m_dbusMessage = this->message();
    this->startPhaseAuth();
}

void Session::StopAuth()
{
    if (this->m_verifyInfo.m_requestID > 0 &&
        this->m_verifyInfo.deviceAdaptor)
    {
        this->m_verifyInfo.deviceAdaptor->stop(this->m_verifyInfo.m_requestID);
    }
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

void Session::start(QSharedPointer<DeviceRequest> request)
{
    this->m_verifyInfo.m_requestID = request->reqID;
}

void Session::interrupt()
{
}

void Session::end()
{
    this->m_verifyInfo.m_requestID = -1;
    this->m_verifyInfo.deviceAdaptor = nullptr;
}

void Session::onVerifyStatus(int result)
{
    // 暂时不需要该操作
    KLOG_DEBUG() << "Unsupported operation.";
}

void Session::onIdentifyStatus(const QString &bid, int result)
{
    if (!this->matchUser(this->m_verifyInfo.authType, bid) &&
        result == FPVerifyResult::FP_VERIFY_RESULT_MATCH)
    {
        KLOG_DEBUG() << "Fingerprint match successfully, but it isn't a legal user.";
        result = FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH;
    }

    auto verifyResultStr = Utils::fpVerifyResultEnum2Str(result);
    if (result == FPVerifyResult::FP_VERIFY_RESULT_MATCH)
    {
        Q_EMIT this->AuthMessage(verifyResultStr, KADMessageType::KAD_MESSAGE_TYPE_INFO);
    }
    else
    {
        Q_EMIT this->AuthMessage(verifyResultStr, KADMessageType::KAD_MESSAGE_TYPE_ERROR);
    }

    if (result == FPVerifyResult::FP_VERIFY_RESULT_MATCH ||
        result == FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH)
    {
        this->finishPhaseAuth(result == FPVerifyResult::FP_VERIFY_RESULT_MATCH);
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
    auto deviceType = Utils::authType2DeviceType(this->m_authType);
    auto device = DeviceAdaptorFactory::getInstance()->getDeviceAdaptor(deviceType);

    if (!device)
    {
        auto authTypeStr = Utils::authTypeEnum2Str(this->m_authType);
        Q_EMIT this->AuthMessage(tr(QString("Auth type %1 invalid").arg(authTypeStr).toStdString().c_str()),
                                 KADMessageType::KAD_MESSAGE_TYPE_ERROR);

        this->finishPhaseAuth(false);
    }
    else
    {
        QStringList bids;
        this->m_verifyInfo.deviceAdaptor = device;
        this->m_verifyInfo.authType = this->m_authType;
        auto user = UserManager::getInstance()->findUser(this->m_userName);
        if (user)
        {
            bids = user->getDataIDs(this->m_authType);
        }
        // TODO: 测试的时候再修改提示语
        // Q_EMIT this->AuthMessage(QObject::tr("Please press the fingerprint."), KADMessageType::KAD_MESSAGE_TYPE_INFO);
        this->m_verifyInfo.deviceAdaptor->identify(this);
    }
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
    if (isSuccess && !this->m_verifyInfo.m_authenticatedUserName.isEmpty())
    {
        auto user = UserManager::getInstance()->findUser(this->m_verifyInfo.m_authenticatedUserName);
        if (user)
        {
            user->setFailures(0);
        }
        Q_EMIT this->AuthSuccessed(this->m_verifyInfo.m_authenticatedUserName);
    }
    else
    {
        auto user = UserManager::getInstance()->findUser(this->m_userName);
        if (user)
        {
            user->setFailures(user->getFailures() + 1);
        }
        Q_EMIT this->AuthFailed();
    }
}

bool Session::matchUser(int32_t authType, const QString &dataID)
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
    RETURN_VAL_IF_TRUE(!this->m_verifyInfo.m_authenticatedUserName.isEmpty() && this->m_verifyInfo.m_authenticatedUserName != userName, false);
    // TODO: 会话复用时需要清理变量
    this->m_verifyInfo.m_authenticatedUserName = userName;
    return true;
}

}  // namespace Kiran
