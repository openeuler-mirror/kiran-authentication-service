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
#include "src/daemon/device/device-request-dispatcher.h"
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

User::FPDeviceRequestSource::FPDeviceRequestSource(User *user) : m_user(user),
                                                                 m_requestID(-1)
{
}

int32_t User::FPDeviceRequestSource::getPriority()
{
    return DeviceRequestPriority::DEVICE_REQUEST_PRIORITY_HIGH;
}

int64_t User::FPDeviceRequestSource::getPID()
{
    return DBusDaemonProxy::getDefault()->getConnectionUnixProcessID(this->m_dbusMessage);
}

void User::FPDeviceRequestSource::event(const DeviceEvent &deviceEvent)
{
    switch (deviceEvent.eventType)
    {
    case DeviceEventType::DEVICE_EVENT_TYPE_START:
        this->m_requestID = deviceEvent.request->reqID;
        break;
    case DeviceEventType::DEVICE_EVENT_TYPE_INTERRUPT:
        Q_EMIT this->m_user->EnrollStatus(QString(), FPEnrollResult::FP_ENROLL_RESULT_FAIL, 0, true);
        break;
    case DeviceEventType::DEVICE_EVENT_TYPE_FP_ENROLL_STATUS:
    {
        auto bid = deviceEvent.args.value(DEVICE_EVENT_ARGS_BID).toString();
        auto result = deviceEvent.args.value(DEVICE_EVENT_ARGS_RESULT).toInt();
        auto progress = deviceEvent.args.value(DEVICE_EVENT_ARGS_PROGRESS).toInt();
        Q_EMIT this->m_user->EnrollStatus(bid, result, progress, false);
        break;
    }
    default:
        break;
    }
}

User::User(const Passwd &pwent, QObject *parent) : QObject(parent),
                                                   m_pwent(pwent)
{
    this->m_dbusAdaptor = new UserAdaptor(this);
    this->m_settings = new QSettings(QString(KDA_UESR_DATA_DIR "/").append(m_pwent.pw_name), QSettings::IniFormat, this);
    this->m_objectPath = QDBusObjectPath(QString("%1/%2").arg(KAD_USER_DBUS_OBJECT_PATH).arg(m_pwent.pw_uid));
    this->m_fpEnrollRequestSource = QSharedPointer<FPDeviceRequestSource>::create(this);

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

    if (this->m_fpEnrollRequestSource && this->m_fpEnrollRequestSource->getRequestID() > 0)
    {
        auto request = QSharedPointer<DeviceRequest>::create(DeviceRequest{
            .reqType = DeviceRequestType::DEVICE_REQUEST_TYPE_FP_ENROLL_STOP,
            .time = QTime::currentTime(),
            .reqID = -1,
            .source = this->m_fpEnrollRequestSource.dynamicCast<DeviceRequestSource>()});
        request->args.insert(DEVICE_REQUEST_ARGS_REQUEST_ID, qulonglong(this->m_fpEnrollRequestSource->getRequestID()));
        DeviceRequestDispatcher::getDefault()->deliveryRequest(request);
    }
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

CHECK_AUTH_WITH_3ARGS_AND_RETVAL(User, QString, AddIdentification, onAddIdentification, AUTH_USER_SELF, int, const QString &, const QString &)
CHECK_AUTH_WITH_1ARGS(User, DeleteIdentification, onDeleteIdentification, AUTH_USER_SELF, const QString &)

void User::EnrollFPStart()
{
    if (this->m_fpEnrollRequestSource->getRequestID() > 0)
    {
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_USER_ENROLLING);
    }

    this->m_fpEnrollRequestSource->setDBusMessage(this->message());
    auto request = QSharedPointer<DeviceRequest>::create(DeviceRequest{
        .reqType = DeviceRequestType::DEVICE_REQUEST_TYPE_FP_ENROLL_START,
        .time = QTime::currentTime(),
        .reqID = -1,
        .source = this->m_fpEnrollRequestSource.dynamicCast<DeviceRequestSource>()});
    DeviceRequestDispatcher::getDefault()->deliveryRequest(request);
}

void User::EnrollFPStop()
{
    if (this->m_fpEnrollRequestSource)
    {
        auto request = QSharedPointer<DeviceRequest>::create(DeviceRequest{
            .reqType = DeviceRequestType::DEVICE_REQUEST_TYPE_FP_ENROLL_STOP,
            .time = QTime::currentTime(),
            .reqID = -1,
            .source = this->m_fpEnrollRequestSource.dynamicCast<DeviceRequestSource>()});
        request->args.insert(DEVICE_REQUEST_ARGS_REQUEST_ID, qulonglong(this->m_fpEnrollRequestSource->getRequestID()));
        DeviceRequestDispatcher::getDefault()->deliveryRequest(request);
    }
}

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

// bool User::hasIdentification(int authType, const QString &iid)
// {
//     auto keyPrefix = Utils::authTypeEnum2Str(authType);
//     RETURN_VAL_IF_FALSE(!keyPrefix.isEmpty(), false);
//     return this->m_settings->value(keyPrefix + INIFILE_GENERAL_GROUP_KEY_SUFFIX_IIDS).toStringList().contains(iid);
// }

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

QString User::calcAction(const QString &originAction)
{
    RETURN_VAL_IF_TRUE(originAction == AUTH_USER_ADMIN, AUTH_USER_ADMIN);

    if (DBusDaemonProxy::getDefault()->getConnectionUnixUser(this->message()) == this->m_pwent.pw_uid)
    {
        return originAction;
    }
    return AUTH_USER_ADMIN;
}

}  // namespace Kiran
