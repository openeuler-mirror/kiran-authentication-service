#pragma once

#include <QMap>
#include <QString>
#include <QObject>

class QSettings;
namespace Kiran
{
class UserConfig:public QObject
{
    friend class User;
    Q_OBJECT
public:
    UserConfig() = delete;
    explicit UserConfig(const QString& userName,QObject* parent = nullptr);
    ~UserConfig();

    void removeCache();
    void deleteIID(const QString& iid);
    QStringList getIIDs();
    QStringList getIIDs(int authType);
    QStringList getBIDs(int authType);
    QString getIIDName(const QString& iid);
    QString getIIDBid(const QString& iid);
    int getIIDAuthType(const QString& iid);
    int getFailures();

private:
    void init();
    void addIID(int authType, const QString& iid, const QString& name,const QString& bid);
    void changeIIDName(const QString& iid, const QString& name);
    void setFailures(int failures);

private:
    struct IIDInfo
    {
        // iid名称
        QString name;
        // iid所属认证类型
        int authType;
        // iid对应的bid,该id为该生物特征对于设备的识别id
        QString bid;
    };
    QStringList m_iids;
    // QMap<iid,特征ID信息> - 每个特征ID关联的认证类型
    QMap<QString, IIDInfo> m_IIDAuthInfoMap;
    int m_failures;
    QSettings* m_settings;
};
}  // namespace Kiran