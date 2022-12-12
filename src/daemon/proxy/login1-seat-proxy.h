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

#include <QDBusObjectPath>
#include <QMetaType>
#include <QSharedPointer>

namespace Kiran
{
struct Login1SessionItem
{
    QString sessionID;
    QDBusObjectPath sessionObjectPath;
};

class Login1SeatProxy : public QObject
{
    Q_OBJECT

    Q_PROPERTY(Login1SessionItem ActiveSession READ getActiveSession NOTIFY activeSessionChanged)
public:
    Login1SeatProxy(const QDBusObjectPath &objectPath);
    virtual ~Login1SeatProxy(){};

    // 将seat0设置为默认seat
    static QSharedPointer<Login1SeatProxy> getDefault();

    Login1SessionItem getActiveSession() { return this->m_activeSession; }

Q_SIGNALS:
    void activeSessionChanged(const Login1SessionItem &sessionItem);

private Q_SLOTS:
    void onPropertiesChanged(const QString &interfaceName, const QVariantMap &changedProperties, const QStringList &invalidatedProperties);

private:
    static QSharedPointer<Login1SeatProxy> m_defaultSeat;
    QDBusObjectPath m_objectPath;
    Login1SessionItem m_activeSession;
};

}  // namespace Kiran