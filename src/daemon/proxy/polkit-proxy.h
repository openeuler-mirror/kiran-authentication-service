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

#include <QDBusMessage>
#include <QObject>
#include <QSharedPointer>
#include <QTimer>
#include <functional>

class QDBusPendingCallWatcher;

namespace Kiran
{
#define CHECK_AUTH_WITH_1ARGS(className, funName, callback, action, arg1Type)                                                \
    void className::funName(arg1Type value1)                                                                                 \
    {                                                                                                                        \
        auto newAction = this->calcAction(action);                                                                           \
        this->setDelayedReply(true);                                                                                         \
        PolkitProxy::getDefault()->checkAuthorization(newAction,                                                             \
                                                      true,                                                                  \
                                                      this->message(),                                                       \
                                                      std::bind(&className::callback, this, std::placeholders::_1, value1)); \
    }

#define CHECK_AUTH_WITH_2ARGS(className, funName, callback, action, arg1Type, arg2Type)                                              \
    void className::funName(arg1Type value1, arg2Type value2)                                                                        \
    {                                                                                                                                \
        auto newAction = this->calcAction(action);                                                                                   \
        this->setDelayedReply(true);                                                                                                 \
        PolkitProxy::getDefault()->checkAuthorization(newAction,                                                                     \
                                                      true,                                                                          \
                                                      this->message(),                                                               \
                                                      std::bind(&className::callback, this, std::placeholders::_1, value1, value2)); \
    }

#define CHECK_AUTH_WITH_3ARGS(className, funName, callback, action, arg1Type, arg2Type, arg3Type)                                            \
    void className::funName(arg1Type value1, arg2Type value2, arg3Type value3)                                                               \
    {                                                                                                                                        \
        auto newAction = this->calcAction(action);                                                                                           \
        this->setDelayedReply(true);                                                                                                         \
        PolkitProxy::getDefault()->checkAuthorization(newAction,                                                                             \
                                                      true,                                                                                  \
                                                      this->message(),                                                                       \
                                                      std::bind(&className::callback, this, std::placeholders::_1, value1, value2, value3)); \
    }

#define CHECK_AUTH_WITH_3ARGS_AND_RETVAL(className, retType, funName, callback, action, arg1Type, arg2Type, arg3Type)                        \
    retType className::funName(arg1Type value1, arg2Type value2, arg3Type value3)                                                            \
    {                                                                                                                                        \
        auto newAction = this->calcAction(action);                                                                                           \
        this->setDelayedReply(true);                                                                                                         \
        PolkitProxy::getDefault()->checkAuthorization(newAction,                                                                             \
                                                      true,                                                                                  \
                                                      this->message(),                                                                       \
                                                      std::bind(&className::callback, this, std::placeholders::_1, value1, value2, value3)); \
        return retType();                                                                                                                    \
    }

class PolkitProxy : public QObject
{
    Q_OBJECT
public:
    PolkitProxy();
    virtual ~PolkitProxy(){};

    static QSharedPointer<PolkitProxy> getDefault();

public:
    using checkAuthHandler = std::function<void(const QDBusMessage &)>;

    struct CheckAuthData
    {
        QTimer timer;
        QString cancelString;
        QDBusMessage message;
        checkAuthHandler handler;
    };

    void checkAuthorization(const QString &action,
                            bool userInteraction,
                            const QDBusMessage &message,
                            checkAuthHandler handler);

private:
    void onCancelCheckAuth(QSharedPointer<CheckAuthData> checkAuthData);
    void onFinishCheckAuth(QDBusPendingCallWatcher *watcher, QSharedPointer<CheckAuthData> checkAuthData);

private:
    static QSharedPointer<PolkitProxy> m_instance;
};

}  // namespace Kiran
