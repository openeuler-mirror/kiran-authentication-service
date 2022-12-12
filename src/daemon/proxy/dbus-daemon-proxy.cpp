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

#include "src/daemon/proxy/dbus-daemon-proxy.h"
#include <qt5-log-i.h>
#include <QDBusConnection>
#include "src/daemon/config-daemon.h"

namespace Kiran
{
#define DBUS_DAEMON_DBUS_NAME "org.freedesktop.DBus"
#define DBUS_DAEMON_DBUS_OBJECT_PATH "/org/freedesktop/DBus"
#define DBUS_DAEMON_DBUS_INTERFACE_NAME "org.freedesktop.DBus"

DBusDaemonProxy::DBusDaemonProxy()
{
}

QSharedPointer<DBusDaemonProxy> DBusDaemonProxy::m_instance = nullptr;
QSharedPointer<DBusDaemonProxy> DBusDaemonProxy::getDefault()
{
    if (!m_instance)
    {
        m_instance = QSharedPointer<DBusDaemonProxy>::create();
    }
    return m_instance;
}

int64_t DBusDaemonProxy::getConnectionUnixProcessID(const QDBusMessage& message)
{
    auto sendMessage = QDBusMessage::createMethodCall(DBUS_DAEMON_DBUS_NAME,
                                                      DBUS_DAEMON_DBUS_OBJECT_PATH,
                                                      DBUS_DAEMON_DBUS_INTERFACE_NAME,
                                                      "GetConnectionUnixProcessID");

    sendMessage << message.service();

    auto replyMessage = QDBusConnection::systemBus().call(sendMessage, QDBus::Block, DBUS_TIMEOUT_MS);

    if (replyMessage.type() == QDBusMessage::ErrorMessage)
    {
        KLOG_WARNING() << "Call GetConnectionUnixProcessID failed: " << replyMessage.errorMessage();
        return -1;
    }
    else
    {
        auto firstArg = replyMessage.arguments().takeFirst();
        return firstArg.toUInt();
    }
}

int64_t DBusDaemonProxy::getConnectionUnixUser(const QDBusMessage& message)
{
    auto sendMessage = QDBusMessage::createMethodCall(DBUS_DAEMON_DBUS_NAME,
                                                      DBUS_DAEMON_DBUS_OBJECT_PATH,
                                                      DBUS_DAEMON_DBUS_INTERFACE_NAME,
                                                      "GetConnectionUnixUser");

    sendMessage << message.service();

    auto replyMessage = QDBusConnection::systemBus().call(sendMessage, QDBus::Block, DBUS_TIMEOUT_MS);

    if (replyMessage.type() == QDBusMessage::ErrorMessage)
    {
        KLOG_WARNING() << "Call GetConnectionUnixUser failed: " << replyMessage.errorMessage();
        return -1;
    }
    else
    {
        auto firstArg = replyMessage.arguments().takeFirst();
        return firstArg.toUInt();
    }
}

}  // namespace Kiran
