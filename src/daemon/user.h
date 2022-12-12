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

#pragma once

#include <QDBusContext>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include "src/daemon/device/device-protocol.h"

class UserAdaptor;
class QSettings;
struct passwd;

namespace Kiran
{
class DeviceAdaptor;

struct Passwd
{
    Passwd() = delete;
    Passwd(struct passwd *pwent);

    QString pw_name;   /* Username.  */
    QString pw_passwd; /* Hashed passphrase, if shadow database not in use (see shadow.h).  */
    uint32_t pw_uid;   /* User ID.  */
    uint32_t pw_gid;   /* Group ID.  */
    QString pw_gecos;  /* Real name.  */
    QString pw_dir;    /* Home directory.  */
    QString pw_shell;  /* Shell program.  */
};

class User : public QObject,
             protected DeviceRequestSource,
             protected QDBusContext
{
    Q_OBJECT

    Q_PROPERTY(QString UserName READ getUserName)
    Q_PROPERTY(QString Failures READ getFailures)

public:
    User() = delete;
    User(const Passwd &pwent, QObject *parent = nullptr);
    virtual ~User();

    QDBusObjectPath getObjectPath() { return this->m_objectPath; }
    QStringList getIIDs();
    QStringList getDataIDs(int authType);
    bool hasIdentification(int authType);
    void removeCache();

    QString getUserName() { return this->m_pwent.pw_name; }
    // 该用户连续登陆失败次数
    int32_t getFailures();
    void setFailures(int32_t failures);

public Q_SLOTS:  // DBUS METHODS
    QString AddIdentification(int authType, const QString &name, const QString &dataID);
    void DeleteIdentification(const QString &iid);
    void EnrollStart(int deviceType);
    void EnrollStop();
    QString GetIdentifications(int authType);
    void ResetFailures();

Q_SIGNALS:  // SIGNALS
    void EnrollStatus(const QString &bid, int result, int progress, bool interrupt);
    void IdentificationAdded(const QString &iid);
    void IdentificationChanged(const QString &iid);
    void IdentificationDeleted(const QString &iid);

private:
    struct UserEnrollInfo
    {
        UserEnrollInfo() : m_requestID(-1) {}
        int64_t m_requestID;
        QDBusMessage m_dbusMessage;
        QSharedPointer<DeviceAdaptor> deviceAdaptor;
    };

private:
    virtual int32_t getPriority();
    virtual int64_t getPID();
    virtual QString getSpecifiedUser() { return QString(); };
    virtual void start(QSharedPointer<DeviceRequest> request);
    virtual void interrupt();
    virtual void end();
    virtual void onEnrollStatus(const QString &bid, int result, int progress);
    virtual void onVerifyStatus(int result){};
    virtual void onIdentifyStatus(const QString &bid, int result){};

private:
    // 如果请求用户和当前用户相同则使用originAction，否则需要管理员权限
    QString calcAction(const QString &originAction);

    void onEnrollStart(const QDBusMessage &message, int deviceType);
    void onEnrollStop(const QDBusMessage &message);
    void onResetFailures(const QDBusMessage &message);
    void onAddIdentification(const QDBusMessage &message, int authType, const QString &name, const QString &dataID);
    void onDeleteIdentification(const QDBusMessage &message, const QString &iid);

private:
    UserAdaptor *m_dbusAdaptor;
    Passwd m_pwent;
    QSettings *m_settings;
    QDBusObjectPath m_objectPath;
    UserEnrollInfo m_enrollInfo;
};

}  // namespace Kiran
