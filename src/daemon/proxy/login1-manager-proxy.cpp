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

#include "src/daemon/proxy/login1-manager-proxy.h"
#include "include/auxiliary.h"
#include <QDBusConnection>
#include <QDBusMessage>
#include "src/daemon/config-daemon.h"
#include "src/daemon/proxy/login1-seat-proxy.h"

namespace Kiran
{
#define LOGIN1_MANAGE_DBUS_OBJECT_PATH "/org/freedesktop/login1"
#define LOGIN1_MANAGE_DBUS_INTERFACE_NAME "org.freedesktop.login1.Manager"

Login1ManagerProxy::Login1ManagerProxy()
{
}

QSharedPointer<Login1ManagerProxy> Login1ManagerProxy::m_instance = nullptr;
QSharedPointer<Login1ManagerProxy> Login1ManagerProxy::getDefault()
{
    if (!m_instance)
    {
        m_instance = QSharedPointer<Login1ManagerProxy>::create();
    }
    return m_instance;
}

QDBusObjectPath Login1ManagerProxy::getSessionByPID(uint32_t pid)
{
    auto sendMessage = QDBusMessage::createMethodCall(QStringLiteral(LOGIN1_MANAGE_DBUS_NAME),
                                                      QStringLiteral(LOGIN1_MANAGE_DBUS_OBJECT_PATH),
                                                      QStringLiteral(LOGIN1_MANAGE_DBUS_INTERFACE_NAME),
                                                      QStringLiteral("GetSessionByPID"));

    sendMessage << pid;

    auto replyMessage = QDBusConnection::systemBus().call(sendMessage, QDBus::Block, DBUS_TIMEOUT_MS);

    if (replyMessage.type() == QDBusMessage::ErrorMessage)
    {
        KLOG_WARNING() << "Call GetSessionByPID failed: " << replyMessage.errorMessage();
        return QDBusObjectPath();
    }

    auto firstArg = replyMessage.arguments().takeFirst();
    return qvariant_cast<QDBusObjectPath>(firstArg);
}

QDBusObjectPath Login1ManagerProxy::getSeat(const QString &seatID)
{
    auto sendMessage = QDBusMessage::createMethodCall(LOGIN1_MANAGE_DBUS_NAME,
                                                      LOGIN1_MANAGE_DBUS_OBJECT_PATH,
                                                      LOGIN1_MANAGE_DBUS_INTERFACE_NAME,
                                                      "GetSeat");

    sendMessage << seatID;

    auto replyMessage = QDBusConnection::systemBus().call(sendMessage, QDBus::Block, DBUS_TIMEOUT_MS);

    if (replyMessage.type() == QDBusMessage::ErrorMessage)
    {
        KLOG_WARNING() << "Call GetSeat failed: " << replyMessage.errorMessage();
        return QDBusObjectPath();
    }

    auto firstArg = replyMessage.arguments().takeFirst();
    return qvariant_cast<QDBusObjectPath>(firstArg);
}
}  // namespace Kiran