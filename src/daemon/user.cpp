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
#include <kas-authentication-i.h>
#include <kiran-authentication-devices/kiran-auth-device-i.h>
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
#include "src/utils/utils.h"

#define USER_DEBUG() KLOG_DEBUG() << this->m_pwent.pw_uid
#define USER_WARNING() KLOG_WARNING() << this->m_pwent.pw_uid

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
        USER_WARNING() << "can't register object:" << systemConnection.lastError();
    }

    this->m_serviceWatcher = new QDBusServiceWatcher(this);
    this->m_serviceWatcher->setConnection(systemConnection);
    this->m_serviceWatcher->setWatchMode(QDBusServiceWatcher::WatchForUnregistration);
    // connect(this->m_serviceWatcher, &QDBusServiceWatcher::serviceUnregistered, this, &User::onNameLost);
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

CHECK_AUTH_WITH_1ARGS(User, DeleteIdentification, onDeleteIdentification, AUTH_USER_SELF, const QString &)
CHECK_AUTH_WITH_2ARGS(User, RenameIdentification, onRenameIdentification, AUTH_USER_SELF, const QString &, const QString &);
CHECK_AUTH_WITH_3ARGS(User, EnrollStart, onEnrollStart, AUTH_USER_SELF, int, const QString &, const QString &)
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
    USER_DEBUG() << "request interrupt";
    Q_EMIT this->EnrollStatus(QString(), false, 0, tr("Enroll has been interrupted. Please wait"));
}

void User::cancel()
{
    USER_DEBUG() << "request cancel";
    Q_EMIT this->EnrollStatus(QString(), true, 0, tr("Enroll has been cancelled"));
}

void User::end()
{
    USER_DEBUG() << "request end";
    this->m_enrollInfo.m_requestID = -1;
    this->m_enrollInfo.deviceAdaptor = nullptr;
    this->m_enrollInfo.m_authTpe = -1;
    this->m_enrollInfo.m_feautreName.clear();
}

void User::onEnrollStatus(const QString &dataID, int progress,
                          int result, const QString &message)
{
    USER_DEBUG() << "enroll status from device,"
                 << "data:" << dataID
                 << "result:" << result
                 << "progress:" << progress
                 << "message:" << message;

    bool isComplete = false;

    switch (result)
    {
    case ENROLL_RESULT_COMPLETE:
    {
        auto authType = this->m_enrollInfo.m_authTpe;
        auto iidName = this->m_enrollInfo.m_feautreName;
        auto iid = Utils::GenerateIID(authType, dataID);
        USER_DEBUG() << "enroll success,"
                     << "iid:" << iid
                     << "data id:" << dataID
                     << "name:" << iidName;

        this->m_userConfig->addIID(authType, iid, iidName, dataID);
        emit this->IdentificationAdded(iid);
        emit this->EnrollStatus(iid, true, progress, message);
        break;
    }
    case ENROLL_RESULT_FAIL:
        emit this->EnrollStatus(QString(), true, progress, message);
        break;
    default:
        emit this->EnrollStatus(QString(), false, progress, message);
        break;
    }
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

void User::onEnrollStart(const QDBusMessage &message, int authType,
                         const QString &name, const QString &extraInfo)
{
    if (this->m_enrollInfo.m_requestID > 0)
    {
        USER_DEBUG() << "start enroll failed,user is enrolling!";
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::AccessDenied, KADErrorCode::ERROR_USER_ENROLLING);
    }

    auto deviceAdaptor = DeviceAdaptorFactory::getInstance()->getDeviceAdaptor(authType);
    if (!deviceAdaptor)
    {
        USER_WARNING() << "start enroll failed,no such device!";
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::AddressInUse, KADErrorCode::ERROR_NO_DEVICE);
    }
    
    USER_DEBUG() << "enroll start" << authType << name << extraInfo;
    this->m_enrollInfo.m_dbusMessage = message;
    this->m_enrollInfo.deviceAdaptor = deviceAdaptor;
    this->m_enrollInfo.deviceAdaptor->enroll(this, extraInfo);
    this->m_enrollInfo.m_authTpe = authType;
    this->m_enrollInfo.m_feautreName = name;

    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

void User::onEnrollStop(const QDBusMessage &message)
{
    if (this->m_enrollInfo.m_requestID > 0 &&
        this->m_enrollInfo.deviceAdaptor)
    {
        USER_DEBUG() << "enroll stop,stop request" << this->m_enrollInfo.m_requestID;
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

void User::onDeleteIdentification(const QDBusMessage &message, const QString &iid)
{
    // TODO:删除特征值同步删除认证设备管理中的fid
    if (!getIIDs().contains(iid))
    {
        USER_WARNING() << "delete identification" << iid << "error,can not find!";
        DBUS_ERROR_REPLY_AND_RET(QDBusError::InvalidArgs, KADErrorCode::ERROR_INVALID_ARGUMENT);
    }

    USER_DEBUG() << "delete identification" << iid;
    QString dataID = this->m_userConfig->getIIDBid(iid);
    this->m_userConfig->deleteIID(iid);
    DeviceAdaptorFactory::getInstance()->deleteFeature(dataID);

    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);

    Q_EMIT this->IdentificationDeleted(iid);
}

void User::onRenameIdentification(const QDBusMessage &message, const QString &iid, const QString &name)
{
    if (!getIIDs().contains(iid))
    {
        USER_WARNING() << "rename identification" << iid << "error,can not find";
        DBUS_ERROR_REPLY_AND_RET(QDBusError::InvalidArgs, KADErrorCode::ERROR_INVALID_ARGUMENT);
    }

    USER_DEBUG() << "rename identification" << iid << name;
    if (this->m_userConfig->renameIID(iid, name))
    {
        emit IdentificationChanged(iid);
    }
    else
    {
        DBUS_ERROR_REPLY_AND_RET(QDBusError::InvalidArgs, KADErrorCode::ERROR_INVALID_ARGUMENT);
    }

    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}
}  // namespace Kiran
