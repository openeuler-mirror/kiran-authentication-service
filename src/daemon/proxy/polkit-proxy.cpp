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

#include "src/daemon/proxy/polkit-proxy.h"
#include <auxiliary.h>
#include <qt5-log-i.h>
#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMetaType>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusVariant>
#include "src/daemon/config-daemon.h"

namespace Kiran
{
#define POLKIT_DBUS_NAME "org.freedesktop.PolicyKit1"
#define POLKIT_DBUS_OBJECT_PATH "/org/freedesktop/PolicyKit1/Authority"
#define POLKIT_DBUS_INTERFACE_NAME "org.freedesktop.PolicyKit1.Authority"
// 单位：秒
#define POLKIT_AUTH_CHECK_TIMEOUT 20

struct PolkitSubject
{
    QString kind;
    QMap<QString, QDBusVariant> details;
};

QDBusArgument &operator<<(QDBusArgument &argument, const PolkitSubject &subject)
{
    argument.beginStructure();
    argument << subject.kind;
    argument.beginMap(QVariant::String, qMetaTypeId<QDBusVariant>());
    for (auto iter = subject.details.begin(); iter != subject.details.end(); ++iter)
    {
        argument.beginMapEntry();
        argument << iter.key() << iter.value();
        argument.endMapEntry();
    }
    argument.endMap();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, PolkitSubject &subject)
{
    argument.beginStructure();
    argument >> subject.kind;
    argument.beginMap();
    subject.details.clear();
    while (!argument.atEnd())
    {
        QString key;
        QDBusVariant value;
        argument.beginMapEntry();
        argument >> key >> value;
        argument.endMapEntry();
        subject.details.insert(key, value);
    }
    argument.endMap();
    argument.endStructure();
    return argument;
}

struct PolkitCheckAuthResult
{
    bool is_authorized;
    bool is_challenge;
    QMap<QString, QString> details;
};

QDBusArgument &operator<<(QDBusArgument &argument, const PolkitCheckAuthResult &checkAuthResult)
{
    argument.beginStructure();
    argument << checkAuthResult.is_authorized << checkAuthResult.is_challenge;
    argument.beginMap(QVariant::String, QVariant::String);
    for (auto iter = checkAuthResult.details.begin(); iter != checkAuthResult.details.end(); ++iter)
    {
        argument.beginMapEntry();
        argument << iter.key() << iter.value();
        argument.endMapEntry();
    }

    argument.endMap();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, PolkitCheckAuthResult &checkAuthResult)
{
    argument.beginStructure();
    argument >> checkAuthResult.is_authorized >> checkAuthResult.is_challenge;
    argument.beginMap();
    checkAuthResult.details.clear();
    while (!argument.atEnd())
    {
        QString key;
        QString value;
        argument.beginMapEntry();
        argument >> key >> value;
        argument.endMapEntry();
        checkAuthResult.details.insert(key, value);
    }
    argument.endMap();
    argument.endStructure();
    return argument;
}

using PolkitDetails = QMap<QString, QString>;

PolkitProxy::PolkitProxy()
{
    qDBusRegisterMetaType<PolkitSubject>();
    qDBusRegisterMetaType<PolkitCheckAuthResult>();
    qDBusRegisterMetaType<PolkitDetails>();
}

QSharedPointer<PolkitProxy> PolkitProxy::m_instance = nullptr;
QSharedPointer<PolkitProxy> PolkitProxy::getDefault()
{
    if (!m_instance)
    {
        m_instance = QSharedPointer<PolkitProxy>::create();
    }
    return m_instance;
}

void PolkitProxy::checkAuthorization(const QString &action,
                                     bool userInteraction,
                                     const QDBusMessage &message,
                                     checkAuthHandler handler)
{
    auto checkAuthData = QSharedPointer<CheckAuthData>::create();
    checkAuthData->timer.setInterval(POLKIT_AUTH_CHECK_TIMEOUT * 1000);
    checkAuthData->cancelString = QString("%1-%2").arg(PROJECT_NAME).arg(quint64(&checkAuthData->timer));
    checkAuthData->message = message;
    checkAuthData->handler = handler;

    auto sendMessage = QDBusMessage::createMethodCall(POLKIT_DBUS_NAME,
                                                      POLKIT_DBUS_OBJECT_PATH,
                                                      POLKIT_DBUS_INTERFACE_NAME,
                                                      "CheckAuthorization");

    PolkitSubject subject;
    QDBusVariant name_detail(QVariant::fromValue(message.service()));
    subject.kind = "system-bus-name";
    subject.details.insert("name", name_detail);
    sendMessage << QVariant::fromValue(subject)
                << action
                << QVariant::fromValue(QMap<QString, QString>())
                << QVariant::fromValue(uint(userInteraction ? 1 : 0))
                << checkAuthData->cancelString;

    auto call = QDBusConnection::systemBus().asyncCall(sendMessage);
    auto watcher = new QDBusPendingCallWatcher(call, this);
    connect(watcher, &QDBusPendingCallWatcher::finished, std::bind(&PolkitProxy::onFinishCheckAuth, this, std::placeholders::_1, checkAuthData));
    connect(&checkAuthData->timer, &QTimer::timeout, std::bind(&PolkitProxy::onCancelCheckAuth, this, checkAuthData));
}

void PolkitProxy::onCancelCheckAuth(QSharedPointer<CheckAuthData> checkAuthData)
{
    auto sendMessage = QDBusMessage::createMethodCall(POLKIT_DBUS_NAME,
                                                      POLKIT_DBUS_OBJECT_PATH,
                                                      POLKIT_DBUS_INTERFACE_NAME,
                                                      "CancelCheckAuthorization");
    sendMessage << checkAuthData->cancelString;

    auto replyMessage = QDBusConnection::systemBus().call(sendMessage, QDBus::Block, DBUS_TIMEOUT_MS);

    if (replyMessage.type() == QDBusMessage::ErrorMessage)
    {
        KLOG_WARNING() << "Call CancelCheckAuthorization failed: " << replyMessage.errorMessage();
    }

    checkAuthData->timer.disconnect();
}

void PolkitProxy::onFinishCheckAuth(QDBusPendingCallWatcher *watcher, QSharedPointer<CheckAuthData> checkAuthData)
{
    bool isSuccess = false;
    QDBusPendingReply<PolkitCheckAuthResult> reply = *watcher;

    SCOPE_EXIT({
        watcher->deleteLater();
    });

    if (reply.isError())
    {
        KLOG_WARNING() << "Call CancelCheckAuthorization failed: " << reply.error().message();
    }
    else
    {
        auto checkAuthResult = reply.value();
        isSuccess = checkAuthResult.is_authorized;
        KLOG_DEBUG() << "IsAuthorized: " << checkAuthResult.is_authorized << ", isChallenge: " << checkAuthResult.is_challenge;
    }

    if (isSuccess)
    {
        checkAuthData->handler(checkAuthData->message);
    }
    else
    {
        auto replyMessage = checkAuthData->message.createErrorReply(QDBusError::AccessDenied, tr("Authorization failed."));
        QDBusConnection::systemBus().send(replyMessage);
    }
}

}  // namespace Kiran

Q_DECLARE_METATYPE(Kiran::PolkitSubject);
Q_DECLARE_METATYPE(Kiran::PolkitCheckAuthResult);
Q_DECLARE_METATYPE(Kiran::PolkitDetails);