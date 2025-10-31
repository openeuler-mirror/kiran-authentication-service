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
#include <pwd.h>
#include <qt5-log-i.h>
#include <QDBusConnection>
#include <QSettings>

#include "config-daemon.h"
#include "device/device-adaptor-factory.h"
#include "error.h"
#include "kas-authentication-i.h"
#include "lib/feature-db.h"
#include "lib/utils.h"
#include "proxy/dbus-daemon-proxy.h"
#include "proxy/polkit-proxy.h"
#include "user-config.h"
#include "user-manager.h"
#include "user.h"
#include "user_adaptor.h"

#define USER_DEBUG() KLOG_DEBUG() << this->m_pwent.pw_uid
#define USER_WARNING() KLOG_WARNING() << this->m_pwent.pw_uid
#define USER_INFO() KLOG_INFO() << this->m_pwent.pw_uid
#define FEATURE_COUNT_MAXIMUN 10

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
    return FeatureDB::getInstance()->getIID(m_pwent.pw_name);
}

QStringList User::getIIDs(int authType)
{
    return FeatureDB::getInstance()->getIID(m_pwent.pw_name, authType);
}

QStringList User::getFeatureIDs(int authType)
{
    return FeatureDB::getInstance()->getFeatureID(m_pwent.pw_name, authType);
}

QString User::getFetureIDByIID(const QString &IID)
{
    return FeatureDB::getInstance()->getFetureIDByIID(IID);
}
QString User::getFeatureNameByIID(const QString &IID)
{
    return FeatureDB::getInstance()->getFeatureNameByIID(IID);
}

bool User::updateFeatureNameByIID(const QString &iid, const QString &featureName)
{
    return FeatureDB::getInstance()->updateFeatureNameByIID(iid, featureName);
}

bool User::hasIdentification(int authType)
{
    return getIIDs(authType).size() > 0;
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

    QStringList iids = getIIDs(authType);
    for (auto &iid : iids)
    {
        QJsonObject jsonObj{
            {KAD_IJK_KEY_IID, iid},
            {KAD_IJK_KEY_DATA_ID, getFetureIDByIID(iid)},
            {KAD_IJK_KEY_NAME, getFeatureNameByIID(iid)}};
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

void User::queued(QSharedPointer<DeviceRequest> request)
{
    KLOG_DEBUG() << getUserName() << "enroll (request id:" << request->reqID << ") queued";
    this->m_enrollInfo.m_requestID = request->reqID;
    Q_EMIT this->EnrollStatus(tr("Please wait while the request is processed"), false, 0, "");
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
    this->m_enrollInfo.deviceAdaptor.clear();
    this->m_enrollInfo.m_authTpe = -1;
    this->m_enrollInfo.m_feautreName.clear();
}

void User::onEnrollStatus(const QString &data, int progress,
                          int result, const QString &message)
{
    USER_INFO() << "enroll status from device,"
                << "result:" << result
                << "progress:" << progress
                << "message:" << message;

    bool isComplete = false;

    switch (result)
    {
    case ENROLL_STATUS_COMPLETE:
    {
        FeatureData featureData = jsonStringToStruct<FeatureData>(data);

        auto authType = this->m_enrollInfo.m_authTpe;
        auto iidName = this->m_enrollInfo.m_feautreName;
        auto iid = Utils::GenerateIID(authType, featureData.featureID);
        USER_INFO() << "enroll success,"
                    << "iid:" << iid
                    << "data id:" << featureData.featureID
                    << "name:" << iidName
                    << "data len:" << featureData.feature.size();

        featureData.authType = authType;
        featureData.featureName = iidName;
        featureData.iid = iid;
        featureData.userName = getUserName();

        auto ret = FeatureDB::getInstance()->addFeature(featureData);
        USER_INFO() << "add feature to db:" << ret;

        emit this->EnrollStatus(iid, true, progress, message);
        break;
    }
    case ENROLL_STATUS_FAIL:
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
    if (this->m_enrollInfo.m_requestID >= 0)
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

    if (getIIDs(authType).count() >= FEATURE_COUNT_MAXIMUN)
    {
        USER_WARNING() << "the number of features has reached its maximum:" << FEATURE_COUNT_MAXIMUN;
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::LimitsExceeded, KADErrorCode::ERROR_USER_FEATURE_LIMITS_EXCEEDED);
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
    if (this->m_enrollInfo.m_requestID >= 0 &&
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
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::InvalidArgs, KADErrorCode::ERROR_INVALID_ARGUMENT);
    }

    USER_DEBUG() << "delete identification" << iid;
    FeatureDB::getInstance()->deleteFearureByIID(iid);

    QString dataID = getFetureIDByIID(iid);
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
    if (updateFeatureNameByIID(iid, name))
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
