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

#include <QObject>
#include "src/pam/pam-handle.h"

class AuthManagerProxy;
class AuthSessionProxy;
class AuthUserProxy;

namespace Kiran
{
class Authentication : public QObject
{
    Q_OBJECT
public:
    Authentication(PAMHandle *pamh, const QStringList &arguments);
    virtual ~Authentication();

Q_SIGNALS:
    void resultReady(int result);

public Q_SLOTS:
    void start();

private:
    int init();
    int checkFailures();
    int startAction();
    int startActionDoAuth();
    int startActionAuthSucc();
    // 开始认证前需要跟应用对接好数据
    int startAuthPre();
    int startAuth();
    void finishAuth(int result);

    // 告知上层应用当前的认证模式
    virtual void notifyAuthMode() = 0;
    virtual bool requestLoginUserSwitchable() = 0;
    // 告知上层应用可选的认证类型
    virtual void notifySupportAuthType() = 0;
    // 请求自定义的认证类型
    virtual int32_t requestAuthType() = 0;
    // 告知上层应用当前的认证模式
    virtual void notifyAuthType(int authType) = 0;

private:
    bool initSession();

private Q_SLOTS:
    void onAuthPrompt(const QString &text, int type);
    void onAuthMessage(const QString &text, int type);
    void onAuthFailed();
    void onAuthUnavail();
    void onAuthSuccessed(const QString &userName);
    void onAuthTypeChanged(int authType);

protected:
    PAMHandle *m_pamHandle;
    QStringList m_arguments;
    QString m_serviceName;
    QString m_userName;
    int32_t m_result;
    int m_authApplication;
    uint m_sessionID;

    AuthManagerProxy *m_authManagerProxy;
    AuthSessionProxy *m_authSessionProxy;
    AuthUserProxy *m_authUserProxy;
};
}  // namespace Kiran
