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
#include "src/daemon/user-manager.h"
#include "src/daemon/user_adaptor.h"
#include "src/daemon/utils.h"

namespace Kiran
{
#define AUTH_USER_ADMIN "com.kylinsec.kiran.authentication.user-administration"
#define AUTH_USER_SELF "com.kylinsec.kiran.authentication.user-self"

#define INIFILE_GENERAL_GROUP_NAME "General"
#define INIFILE_GENERAL_GROUP_KEY_IIDS "IIDs"
// 连续认证失败次数计数
#define INIFILE_GENERAL_GROUP_KEY_FAILURES "Failures"

#define INIFILE_IID_GROUP_PREFIX_NAME "IID"
#define INIFILE_IID_GROUP_KEY_IID "IID"
#define INIFILE_IID_GROUP_KEY_AUTH_TYPE "AuthType"
#define INIFILE_IID_GROUP_KEY_NAME "Name"
#define INIFILE_IID_GROUP_KEY_DATA_ID "DataID"

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

User::User(const Passwd &pwent, QObject *parent) : QObject(parent),
                                                   m_pwent(pwent)
{
    this->m_dbusAdaptor = new UserAdaptor(this);
    this->m_settings = new QSettings(QString(KDA_UESR_DATA_DIR "/").append(m_pwent.pw_name), QSettings::IniFormat, this);
    this->m_objectPath = QDBusObjectPath(QString("%1/%2").arg(KAD_USER_DBUS_OBJECT_PATH).arg(m_pwent.pw_uid));

    auto systemConnection = QDBusConnection::systemBus();
    if (!systemConnection.registerObject(this->m_objectPath.path(), this))
    {
        KLOG_WARNING() << "Can't register object:" << systemConnection.lastError();
    }
}

User::~User()
{
    // 如果缓存已经被清理，则删除文件
    if (this->m_settings->childGroups().size() == 0)
    {
        QFile file(this->m_settings->fileName());
        file.remove();
        this->m_settings = nullptr;
    }

    this->EnrollStop();
}

QStringList User::getIIDs()
{
    return this->m_settings->value(INIFILE_GENERAL_GROUP_KEY_IIDS).toStringList();
}

QStringList User::getDataIDs(int authType)
{
    QStringList dataIDs;
    auto keyPrefix = Utils::authTypeEnum2Str(authType);
    RETURN_VAL_IF_FALSE(!keyPrefix.isEmpty(), QStringList());

    auto iids = this->m_settings->value(keyPrefix + INIFILE_GENERAL_GROUP_KEY_IIDS).toStringList();

    for (auto &iid : iids)
    {
        auto groupName = QString("%1 %2").arg(keyPrefix).arg(iid);
        this->m_settings->beginGroup(groupName);
        dataIDs.push_back(this->m_settings->value(INIFILE_IID_GROUP_KEY_DATA_ID).toString());
        this->m_settings->endGroup();
    }
    return dataIDs;
}

bool User::hasIdentification(int authType)
{
    auto keyPrefix = Utils::authTypeEnum2Str(authType);
    RETURN_VAL_IF_FALSE(!keyPrefix.isEmpty(), false);
    return this->m_settings->value(keyPrefix + INIFILE_GENERAL_GROUP_KEY_IIDS).toStringList().size() > 0;
}

void User::removeCache()
{
    // 清理文件内容
    this->m_settings->remove(QString());
}

int32_t User::getFailures()
{
    return this->m_settings->value(INIFILE_GENERAL_GROUP_KEY_FAILURES, 0).toInt();
}

void User::setFailures(int32_t failures)
{
    this->m_settings->setValue(INIFILE_GENERAL_GROUP_KEY_FAILURES, failures);
}

CHECK_AUTH_WITH_3ARGS_AND_RETVAL(User, QString, AddIdentification, onAddIdentification, AUTH_USER_SELF, int, const QString &, const QString &)
CHECK_AUTH_WITH_1ARGS(User, DeleteIdentification, onDeleteIdentification, AUTH_USER_SELF, const QString &)
CHECK_AUTH_WITH_1ARGS(User, EnrollStart, onEnrollStart, AUTH_USER_SELF, int)
CHECK_AUTH(User, EnrollStop, onEnrollStop, AUTH_USER_SELF)
CHECK_AUTH(User, ResetFailures, onResetFailures, AUTH_USER_SELF)

QString User::GetIdentifications(int authType)
{
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;
    auto keyPrefix = Utils::authTypeEnum2Str(authType);
    RETURN_VAL_IF_FALSE(!keyPrefix.isEmpty(), QString());

    auto iids = this->m_settings->value(keyPrefix + INIFILE_GENERAL_GROUP_KEY_IIDS).toStringList();

    for (auto &iid : iids)
    {
        auto groupName = QString("%1 %2").arg(keyPrefix).arg(iid);
        this->m_settings->beginGroup(groupName);
        QJsonObject jsonObj{
            {KAD_IJK_KEY_IID, this->m_settings->value(INIFILE_IID_GROUP_KEY_IID).toString()},
            {KAD_IJK_KEY_NAME, this->m_settings->value(INIFILE_IID_GROUP_KEY_NAME).toString()},
            {KAD_IJK_KEY_DATA_ID, this->m_settings->value(INIFILE_IID_GROUP_KEY_DATA_ID).toString()},
        };
        jsonArray.append(jsonObj);
        this->m_settings->endGroup();
    }

    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson());
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

void User::end()
{
    this->m_enrollInfo.m_requestID = -1;
    this->m_enrollInfo.deviceAdaptor = nullptr;
}

void User::onEnrollStatus(const QString &bid, int result, int progress)
{
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

void User::onEnrollStart(const QDBusMessage &message, int deviceType)
{
    if (this->m_enrollInfo.m_requestID > 0)
    {
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::AccessDenied, KADErrorCode::ERROR_USER_ENROLLING);
    }

    auto deviceAdaptor = DeviceAdaptorFactory::getInstance()->getDeviceAdaptor(deviceType);
    if (!deviceAdaptor)
    {
        DBUS_ERROR_REPLY_ASYNC_AND_RET(message, QDBusError::AddressInUse, KADErrorCode::ERROR_FAILED);
    }

    this->m_enrollInfo.m_dbusMessage = this->message();
    this->m_enrollInfo.deviceAdaptor = deviceAdaptor;
    this->m_enrollInfo.deviceAdaptor->enroll(this);
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
    this->m_settings->setValue(INIFILE_GENERAL_GROUP_KEY_FAILURES, 0);
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

    auto iids = this->m_settings->value(INIFILE_GENERAL_GROUP_KEY_IIDS).toStringList();
    iids.push_back(iid);
    this->m_settings->setValue(INIFILE_GENERAL_GROUP_KEY_IIDS, iids);

    auto groupName = QString("%1 %2").arg(INIFILE_IID_GROUP_PREFIX_NAME).arg(iid);
    this->m_settings->beginGroup(groupName);
    do
    {
        this->m_settings->setValue(INIFILE_IID_GROUP_KEY_IID, iid);
        this->m_settings->setValue(INIFILE_IID_GROUP_KEY_AUTH_TYPE, authType);
        this->m_settings->setValue(INIFILE_IID_GROUP_KEY_NAME, name);
        this->m_settings->setValue(INIFILE_IID_GROUP_KEY_DATA_ID, dataID);
        auto replyMessage = message.createReply();
        replyMessage << iid;
        QDBusConnection::systemBus().send(replyMessage);
        Q_EMIT this->IdentificationAdded(iid);
    } while (0);

    this->m_settings->endGroup();
}

void User::onDeleteIdentification(const QDBusMessage &message, const QString &iid)
{
    auto groupName = QString("%1 %2").arg(INIFILE_IID_GROUP_PREFIX_NAME).arg(iid);
    RETURN_IF_FALSE(this->m_settings->contains(groupName));

    this->m_settings->remove(groupName);
    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
    Q_EMIT this->IdentificationDeleted(iid);
}

}  // namespace Kiran
