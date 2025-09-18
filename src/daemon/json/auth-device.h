/**
 * Copyright (c) 2025 ~ 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     yangfeng <yangfeng@kylinsec.com.cn>
 */

#pragma once

#include <QList>
#include <QString>

namespace Kiran
{
class AuthDevice
{
private:
    friend QList<AuthDevice> authDevicesfromJson(const QString& json);
    AuthDevice(const QString& id, const QString& name, const QString& obj);

public:
    QString id() const { return m_id; }
    QString name() const { return m_name; }
    QString objectPath() const { return m_objectPath; }

private:
    QString m_id;
    QString m_name;
    QString m_objectPath;
};
QList<AuthDevice> authDevicesfromJson(const QString& json);
}  // namespace Kiran
