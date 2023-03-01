#pragma once
#include <QString>
#include <QList>

namespace Kiran
{
class AuthDevice
{
private:
    friend QList<AuthDevice> authDevicesfromJson(const QString& json);
    AuthDevice(const QString& id,const QString& name,const QString& obj);

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
