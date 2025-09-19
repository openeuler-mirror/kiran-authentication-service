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

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "auth-device.h"

namespace Kiran
{
AuthDevice::AuthDevice(const QString& id, const QString& name, const QString& obj)
    : m_id(id),
      m_name(name),
      m_objectPath(obj)
{
}

QList<AuthDevice> authDevicesfromJson(const QString& json)
{
    QList<AuthDevice> list;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());

    if (!doc.isArray())
    {
        return list;
    }

    QJsonArray jsonArray = doc.array();
    for (int i = 0; i < jsonArray.count(); i++)
    {
        QJsonValue jsonValue = jsonArray.at(i);
        if (!jsonValue.isObject())
        {
            continue;
        }

        QJsonObject object = jsonValue.toObject();
        QString id = object.value("deviceID").toString();
        QString name = object.value("deviceName").toString();
        QString obj = object.value("objectPath").toString();

        list << AuthDevice(id, name, obj);
    }
    return list;
}
}  // namespace Kiran