#include "auth-device.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

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
        if( !jsonValue.isObject() )
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