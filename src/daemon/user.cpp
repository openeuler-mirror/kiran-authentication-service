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

#include "src/daemon/user.h"
#include <auxiliary.h>
#include <biometrics-i.h>
#include <kas-authentication-i.h>
#include <pwd.h>
#include <qt5-log-i.h>
#include <QDBusConnection>
#include <QSettings>
#include "src/daemon/config-daemon.h"
#include "src/daemon/device/device-adaptor-factory.h"
#include "src/daemon/error.h"
#include "src/daemon/proxy/dbus-daemon-proxy.h"
#include "src/daemon/proxy/polkit-proxy.h"
#include "src/daemon/user-config.h"
#include "src/daemon/user-manager.h"
#include "src/daemon/user_adaptor.h"
#include "src/daemon/utils.h"

namespace Kiran
{
#define AUTH_USER_ADMIN "com.kylinsec.kiran.authentication.user-administration"
#define AUTH_USER_SELF "com.kylinsec.kiran.authentication.user-self"

Passwd::Passwd(struct passwd *pwent)
{
    this->pw_name = QString(pwent->pw_name);
    this->pw_passwd = QString(pwent->pw_passwd);
    this->pw_uid = pwent->pw_uid;
    this->pw_gid = pwent->pw_gid;
    this->pw_gecos = QString(pwent->pw_gecos);
    this->pw_dir = QString(pwent->pw_dir);
    this->pw_shell = QString(pwent->pw_shell);
}

User::User(const Passwd &pwent, QObject *parent)
    : QObject(parent),
      m_pwent(pwent)
{
    this->m_dbusAdaptor = new UserAdaptor(this);
    this->m_userConfig = new UserConfig(m_pwent.pw_name);
    this->m_objectPath = QDBusObjectPath(QString("%1/%2").arg(KAD_USER_DBUS_OBJECT_PATH).arg(m_pwent.pw_uid));

    auto systemConnection = QDBusConnection::systemBus();
    if (!systemConnection.registerObject(this->m_objectPath.path(), this))
    {
        KLOG_WARNING() << "Can't register object:" << systemConnection.lastError();
    }
}

User::~User()
{
    this->EnrollStop();
}

QStringList User::getIIDs()
{
    return m_userConfig->getIIDs();
}

QStringList User::getIIDs(int authType)
{
    return this->m_userConfig->getIIDs(authType);
}

QStringList User::getBIDs(int authType)
{
    return this->m_userConfig->getBIDs(authType);
}

bool User::hasIdentification(int authType)
{
    return this->m_userConfig->getIIDs(authType).size() > 0;
}

void User::removeCache()
{
    this->m_userConfig->removeCache();
}

int32_t User::getFailures()
{
    return this->m_userConfig->getFailures();
}

void User::setFailures(int32_t failures)
{
    if (failures < 0)
    {
        if (calledFromDBus())
        {
            DBUS_ERROR_REPLY_AND_RET(QDBusError::InvalidArgs, KADErrorCode::ERROR_FAILED);
        }
        else
        {
            return;
        }
    }
    this->m_userConfig->setFailures(failures);
}

CHECK_AUTH_WITH_3ARGS_AND_RETVAL(User, QString, AddIdentification, onAddIdentification, AUTH_USER_SELF, int, const QString &, const QString &)
CHECK_AUTH_WITH_1ARGS(User, DeleteIdentification, onDeleteIdentification, AUTH_USER_SELF, const QString &)
CHECK_AUTH_WITH_2ARGS(User, EnrollStart, onEnrollStart, AUTH_USER_SELF, int, const QString &)
CHECK_AUTH(User, EnrollStop, onEnrollStop, AUTH_USER_SELF)
CHECK_AUTH(User, ResetFailures, onResetFailures, AUTH_USER_SELF)
QString User::GetIdentifications(int authType)
{
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;

    QStringList iids = this->m_userConfig->getIIDs(authType);
    for (auto &iid : iids)
    {
        QJsonObject jsonObj{
            {KAD_IJK_KEY_IID, iid},
            {KAD_IJK_KEY_DATA_ID, this->m_userConfig->getIIDBid(iid)},
            {KAD_IJK_KEY_NAME, this->m_userConfig->getIIDName(iid)}};
        jsonArray.append(jsonObj);
    }
    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

int32_t User::getPriority()
{
    return DeviceRequestPriority::DEVICE_REQUEST_PRIORITY_HIGH;
}

int64_t User::getPID()
{
    return DBusDaemonProxy::getDefault()->getConnectionUnixProcessID(this->m_enrollInfo.m_dbusMessage);
}

void User::start(QSharedPointer<DeviceRequest> request)
{
    this->m_enrollInfo.m_requestID = request->reqID;
}

void User::interrupt()
{
    Q_EMIT this->EnrollStatus(QString(), FPEnrollResult::FP_ENROLL_RESULT_FAIL, 0, true);
}

void User::cancel()
{
    Q_EMIT this->EnrollStatus(QString(), FPEnrollResult::FP_ENROLL_RESULT_FAIL, 0, true);
}

void User::end()
{
    this->m_enrollInfo.m_requestID = -1;
    this->m_enrollInfo.deviceAdaptor = nullptr;
}

void User::onEnrollStatus(const QString &bid, int result, int progress, const QString &message)
{
    KLOG_DEBUG() << "Enroll status:" << bid << result << progress << message;
    Q_EMIT this->EnrollStatus(bid, result, progress, false);
}

QString User::calcAction(const QString &originAction)
{
    RETURN_VAL_IF_TRUE(originAction == AUTH_USER_ADMIN, AUTH_USER_ADMIN);

    if (DBusDaemonProxy::getDefault()->getConnectionUnixUser(this->message()) == this->m_pwent.pw_uid)
    {
        return originAction;
    }
    return AUTH_USER_ADMIN;
}

void User::onEnrollStart(const QDBusMessage &message, int authType, const QString &extraInfo)
{
    if (this->m_enrollInfo.m_requestID > 0)
    {
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::AccessDenied, KADErrorCode::ERROR_USER_ENROLLING);
    }

    auto deviceAdaptor = DeviceAdaptorFactory::getInstance()->getDeviceAdaptor(authType);
    if (!deviceAdaptor)
    {
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::AddressInUse, KADErrorCode::ERROR_FAILED);
    }

    this->m_enrollInfo.m_dbusMessage = message;
    this->m_enrollInfo.deviceAdaptor = deviceAdaptor;
    this->m_enrollInfo.deviceAdaptor->enroll(this, extraInfo);
    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

void User::onEnrollStop(const QDBusMessage &message)
{
    if (this->m_enrollInfo.m_requestID > 0 &&
        this->m_enrollInfo.deviceAdaptor)
    {
        this->m_enrollInfo.deviceAdaptor->stop(this->m_enrollInfo.m_requestID);
    }
    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

void User::onResetFailures(const QDBusMessage &message)
{
    this->m_userConfig->setFailures(0);
    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

void User::onAddIdentification(const QDBusMessage &message, int authType, const QString &name, const QString &dataID)
{
    auto authTypeStr = Utils::authTypeEnum2Str(authType);
    if (authTypeStr.length() == 0)
    {
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::InvalidArgs, KADErrorCode::ERROR_FAILED);
    }

    auto iid = Utils::GenerateIID(authType, dataID);
    if (UserManager::getInstance()->getUserByIID(iid))
    {
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::Failed, KADErrorCode::ERROR_USER_IID_ALREADY_EXISTS);
    }

    this->m_userConfig->addIID(authType, iid, name, dataID);
    Q_EMIT this->IdentificationAdded(iid);
}

void User::onDeleteIdentification(const QDBusMessage &message, const QString &iid)
{
    // TODO:删除特征值同步删除认证设备管理中的fid
    if (!getIIDs().contains(iid))
    {
        DBUS_ERROR_REPLY_AND_RET(QDBusError::InvalidArgs, KADErrorCode::ERROR_INVALID_ARGUMENT);
    }

    this->m_userConfig->deleteIID(iid);
    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
    Q_EMIT this->IdentificationDeleted(iid);
}

}  // namespace Kiran
