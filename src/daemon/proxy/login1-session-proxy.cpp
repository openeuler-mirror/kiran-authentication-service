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

#include "src/daemon/proxy/login1-session-proxy.h"
#include <auxiliary.h>
#include <QDBusConnection>
#include <QDBusMessage>
#include "src/daemon/config-daemon.h"

namespace Kiran
{
#define LOGIN1_SESSION_DBUS_INTERFACE_NAME "org.freedesktop.login1.Session"

Login1SessionProxy::Login1SessionProxy(const QDBusObjectPath &objectPath) : m_objectPath(objectPath)
{
}

//FIXME:由方法调用修改为获取session属性
bool Login1SessionProxy::activate()
{
    auto getPropertyCall = QDBusMessage::createMethodCall(LOGIN1_MANAGE_DBUS_NAME, this->m_objectPath.path(), QStringLiteral("org.freedesktop.DBus.Properties"), QStringLiteral("Get"));
    getPropertyCall << LOGIN1_SESSION_DBUS_INTERFACE_NAME << "Active";

    auto replyMessage = QDBusConnection::systemBus().call(getPropertyCall, QDBus::Block, DBUS_TIMEOUT_MS);

    if (replyMessage.type() == QDBusMessage::ErrorMessage)
    {
        KLOG_WARNING() << "Call Activate failed: " << replyMessage.errorMessage();
        return false;
    }
    QVariant firstArg = replyMessage.arguments().first().value<QDBusVariant>().variant();
    bool isActivate = firstArg.value<bool>();
    return isActivate;
}
}  // namespace Kiran