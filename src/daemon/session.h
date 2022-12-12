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

class SessionAdaptor;

namespace Kiran
{
class DeviceAdaptor;
class User;

class Session : public QObject,
                protected DeviceRequestSource,
                protected QDBusContext
{
    Q_OBJECT

public:
    // 如果只允许对特定用户进行认证，则创建对象时需要指定用户名
    Session(uint32_t sessionID,
            const QString &serviceName,
            const QString &userName,
            QObject *parent = nullptr);
    virtual ~Session() {}

    uint32_t getSessionID() { return this->m_sessionID; };
    QString getServiceName() { return this->m_serviceName; };
    QDBusObjectPath getObjectPath() { return this->m_objectPath; };

public Q_SLOTS:  // METHODS
    void ResponsePrompt(const QString &text);
    void SetAuthType(int authType);
    void StartAuth();
    void StopAuth();

Q_SIGNALS:  // SIGNALS
    void AuthFailed();
    void AuthMessage(const QString &text, int type);
    void AuthPrompt(const QString &text, int type);
    void AuthSuccessed(const QString &username);

private:
    struct SessionVerifyInfo
    {
        SessionVerifyInfo() : m_requestID(-1),
                              authType(0) {}
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
    virtual void start(QSharedPointer<DeviceRequest> request);
    virtual void interrupt();
    virtual void end();
    virtual void onEnrollStatus(const QString &bid, int result, int progress){};
    virtual void onVerifyStatus(int result);
    virtual void onIdentifyStatus(const QString &bid, int result);

private:
    int32_t calcNextAuthType();
    void startPhaseAuth();
    void finishPhaseAuth(bool isSuccess);
    void finishAuth(bool isSuccess);

    bool matchUser(int32_t authType, const QString &dataID);

private:
    SessionAdaptor *m_dbusAdaptor;
    uint32_t m_sessionID;
    // 远程调用进程的dbusServiceName
    QString m_serviceName;
    QString m_userName;
    QDBusObjectPath m_objectPath;
    /* 记录所有剩余的待认证类型，如果是OR模式，当用户没有选择认证类型时，直接取列表中第一个作为默认认证类型;
    如果时AND模式，则按照列表的顺序进行认证，认证成功后则从队列中删除。*/
    QList<int32_t> m_authOrderWaiting;
    // 当前使用的认证模式
    int32_t m_authMode;
    // 当前使用的认证类型
    int32_t m_authType;
    //
    SessionVerifyInfo m_verifyInfo;
};
}  // namespace Kiran
