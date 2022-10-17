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
             protected QDBusContext
{
    Q_OBJECT

private:
    class FPDeviceRequestSource : public DeviceRequestSource
    {
    public:
        FPDeviceRequestSource(User *user);
        virtual ~FPDeviceRequestSource(){};

        virtual int32_t getPriority();
        virtual int64_t getPID();
        virtual QString getSpecifiedUser() { return QString(); };
        virtual void event(const DeviceEvent &deviceEvent);

        void setDBusMessage(const QDBusMessage &dbusMessage) { this->m_dbusMessage = dbusMessage; }
        int64_t getRequestID() { return this->m_requestID; }

    private:
        User *m_user;
        QDBusMessage m_dbusMessage;
        int64_t m_requestID;
    };

public:
    User() = delete;
    User(const Passwd &pwent, QObject *parent = nullptr);
    virtual ~User();

    QDBusObjectPath getObjectPath() { return this->m_objectPath; }
    QString getUserName() { return this->m_pwent.pw_name; }
    QStringList getIIDs();
    QStringList getDataIDs(int authType);
    bool hasIdentification(int authType);
    void removeCache();

public Q_SLOTS:  // DBUS METHODS
    QString AddIdentification(int authType, const QString &name, const QString &dataID);
    void DeleteIdentification(const QString &iid);
    void EnrollFPStart();
    void EnrollFPStop();
    QString GetIdentifications(int authType);
    // bool hasIdentification(int authType, const QString &iid);

Q_SIGNALS:  // SIGNALS
    void EnrollStatus(const QString &bid, int result, int progress, bool interrupt);
    void IdentificationAdded(const QString &iid);
    void IdentificationChanged(const QString &iid);
    void IdentificationDeleted(const QString &iid);

private:
    // 如果请求用户和当前用户相同则使用originAction，否则需要管理员权限
    QString calcAction(const QString &originAction);

    void onAddIdentification(const QDBusMessage &message, int authType, const QString &name, const QString &dataID);
    void onDeleteIdentification(const QDBusMessage &message, const QString &iid);

private:
    UserAdaptor *m_dbusAdaptor;
    Passwd m_pwent;
    QSettings *m_settings;
    QDBusObjectPath m_objectPath;
    QSharedPointer<FPDeviceRequestSource> m_fpEnrollRequestSource;
};

}  // namespace Kiran
