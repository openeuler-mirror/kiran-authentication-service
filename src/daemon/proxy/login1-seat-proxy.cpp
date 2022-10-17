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

#include "src/daemon/proxy/login1-seat-proxy.h"
#include <qt5-log-i.h>
#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMetaType>
#include "src/daemon/config-daemon.h"
#include "src/daemon/proxy/login1-manager-proxy.h"

namespace Kiran
{
#define DEFAULT_SEAT_ID "seat0"

QDBusArgument &operator<<(QDBusArgument &argument, const Login1SessionItem &sessionItem)
{
    argument.beginStructure();
    argument << sessionItem.sessionID << sessionItem.sessionObjectPath;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Login1SessionItem &sessionItem)
{
    argument.beginStructure();
    argument >> sessionItem.sessionID >> sessionItem.sessionObjectPath;
    argument.endStructure();
    return argument;
}

Login1SeatProxy::Login1SeatProxy(const QDBusObjectPath &objectPath) : m_objectPath(objectPath)
{
    qDBusRegisterMetaType<Login1SessionItem>();

    auto connected = QDBusConnection::systemBus().connect(QStringLiteral(LOGIN1_MANAGE_DBUS_NAME),
                                                          this->m_objectPath.path(),
                                                          QStringLiteral("org.freedesktop.DBus.Properties"),
                                                          QStringLiteral("PropertiesChanged"),
                                                          this,
                                                          SLOT(onPropertiesChanged(QString, QVariantMap, QStringList)));

    if (!connected)
    {
        KLOG_WARNING() << "Failed to connect signal PropertiesChanged for" << this->m_objectPath.path();
    }
}

QSharedPointer<Login1SeatProxy> Login1SeatProxy::m_defaultSeat = nullptr;
QSharedPointer<Login1SeatProxy> Login1SeatProxy::getDefault()
{
    if (!m_defaultSeat)
    {
        auto objectPath = Login1ManagerProxy::getDefault()->getSeat(DEFAULT_SEAT_ID);
        m_defaultSeat = QSharedPointer<Login1SeatProxy>::create(objectPath);
    }
    return m_defaultSeat;
}

void Login1SeatProxy::onPropertiesChanged(const QString &interfaceName,
                                          const QVariantMap &changedProperties,
                                          const QStringList &invalidatedProperties)
{
    const QVariant activeSession = changedProperties.value(QStringLiteral("ActiveSession"));
    if (activeSession.isValid())
    {
        this->m_activeSession = qvariant_cast<Login1SessionItem>(activeSession);
        Q_EMIT this->activeSessionChanged(this->m_activeSession);
    }
}
}  // namespace Kiran

Q_DECLARE_METATYPE(Kiran::Login1SessionItem)