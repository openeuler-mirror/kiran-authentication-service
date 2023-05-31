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

#include "kas-authentication-i.h"
#include "src/daemon/device/device-protocol.h"

class SessionAdaptor;
class QEventLoop;
namespace Kiran
{
class DeviceAdaptor;
class User;

class Session : public QObject,
                protected DeviceRequestSource,
                protected QDBusContext
{
    Q_OBJECT
    Q_PROPERTY(int AuthType READ getAuthType)
    Q_PROPERTY(uint ID READ getID)
    Q_PROPERTY(QString RSAPublicKey READ getRSAPublicKey)
    Q_PROPERTY(QString Username READ getUsername)
public:
    // 如果只允许对特定用户进行认证，则创建对象时需要指定用户名
    Session(uint32_t sessionID,
            const QString &serviceName,
            const QString &userName,
            KADAuthApplication authApp,
            QObject *parent = nullptr);
    virtual ~Session();

    uint32_t getSessionID() { return this->m_sessionID; };
    QString getServiceName() { return this->m_serviceName; };
    QDBusObjectPath getObjectPath() { return this->m_objectPath; };

    int getAuthType() const;
    uint getID() const;
    QString getRSAPublicKey() const;
    QString getUsername() const;

public Q_SLOTS:  // METHODS
    void ResponsePrompt(const QString &text);
    void SetAuthType(int authType);
    void StartAuth();
    void StopAuth();
    bool GetLoginUserSwitchable();
    void SetLoginUserSwitchable(bool switchable);

Q_SIGNALS:  // SIGNALS
    void AuthFailed();
    void AuthMessage(const QString &text, int type);
    void AuthPrompt(const QString &text, int type);
    void AuthSuccessed(const QString &username);

private:
    struct SessionVerifyInfo
    {
        SessionVerifyInfo() : m_inAuth(false),
                              m_requestID(-1),
                              authType(0) {}
        bool m_inAuth;
        int64_t m_requestID;
        QDBusMessage m_dbusMessage;
        QSharedPointer<DeviceAdaptor> deviceAdaptor;
        int32_t authType;
        // 当前已经认证成功的用户，如果未指定认证用户，第一次认证时可以更改用户
        QString m_authenticatedUserName;
    };

private:
    virtual int32_t getPriority();
    virtual int64_t getPID();
    virtual QString getSpecifiedUser();
    virtual void queued(QSharedPointer<DeviceRequest> request);
    virtual void interrupt();
    virtual void cancel();
    virtual void end();
    virtual void onEnrollStatus(const QString &dataID, int progress, int result, const QString &message){};
    virtual void onIdentifyStatus(const QString &bid, int result, const QString &message);

private:
    void startPhaseAuth();
    void startUkeyAuth();
    void startPasswdAuth();
    void startGeneralAuth(const QString &extraInfo = QString());

    void finishPhaseAuth(bool isSuccess,bool recordFailure = true);
    void finishAuth(bool isSuccess,bool recordFailures = true);

    bool matchUser(int32_t authType, const QString &dataID);

private:
    SessionAdaptor *m_dbusAdaptor;
    uint32_t m_sessionID;
    QString m_serviceName;
    QString m_userName;
    bool m_loginUserSwitchable;
    QDBusObjectPath m_objectPath;
    /* 记录所有剩余的待认证类型，如果是OR模式，当用户没有选择认证类型时，直接取列表中第一个作为默认认证类型;
    如果时AND模式，则按照列表的顺序进行认证，认证成功后则从队列中删除。*/
    QList<int> m_authOrderWaiting;
    // 当前认证的应用类型
    int m_authApplication;
    // 当前使用的认证模式
    int m_authMode;
    // 当前使用的认证类型
    int m_authType;
    SessionVerifyInfo m_verifyInfo;
    std::function<void(const QString &text)> m_waitForResponseFunc;
};
}  // namespace Kiran
