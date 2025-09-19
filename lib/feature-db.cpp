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

#include <qt5-log-i.h>
#include <QDir>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>

#include "config.h"
#include "feature-db.h"

#define DB_FILE "FeatureData.db"

static QSqlDatabase database;

namespace Kiran
{
FeatureDB::FeatureDB()
{
}

FeatureDB::~FeatureDB()
{
    if (database.isValid())
    {
        if (database.isOpen())
        {
            database.close();
        }
    }
}

FeatureDB *FeatureDB::m_instance = nullptr;
void FeatureDB::globalInit()
{
    m_instance = new FeatureDB();
    m_instance->init();
}

void FeatureDB::init()
{
    KLOG_INFO() << "QSqlDatabase::drivers:" << QSqlDatabase::drivers();

    createDBConnection();
}

bool FeatureDB::createDBConnection()
{
    if (QSqlDatabase::contains("qt_sql_default_connection"))
    {
        database = QSqlDatabase::database("qt_sql_default_connection");
    }
    else
    {
        QDir dir(KAS_INSTALL_DATADIR);
        if (!dir.exists())
        {
            dir.mkpath(KAS_INSTALL_DATADIR);
        }
        QString dbPath = QString("%1/%2").arg(KAS_INSTALL_DATADIR).arg(DB_FILE);
        database = QSqlDatabase::addDatabase("QSQLITE");
        database.setDatabaseName(DB_FILE);
        if (!database.open())
        {
            KLOG_ERROR() << "Failed to connect database:" << database.lastError();
            return false;
        }

        QSqlQuery query(database);
        QString createTable = QString("CREATE TABLE IF NOT EXISTS [feature]("
                                      "featureID TEXT PRIMARY KEY NOT NULL,"
                                      "feature BLOB NOT NULL,"
                                      "featureName TEXT,"
                                      "iid TEXT,"
                                      "userName TEXT,"
                                      "idVendor TEXT,"
                                      "idProduct TEXT,"
                                      "deviceType INT,"
                                      "deviceSerialNumber TEXT,"
                                      "authType INT);");

        if (!query.exec(createTable))
        {
            KLOG_DEBUG() << "failed to create table in the database:" << query.lastError();
        }
    }
    return true;
}

bool FeatureDB::addFeature(const FeatureData &featureData)
{
    return addFeature(featureData.featureID, featureData.feature, featureData.featureName, featureData.iid, featureData.userName, featureData.idVendor, featureData.idProduct, featureData.deviceType, featureData.deviceSerialNumber, featureData.authType);
}

bool FeatureDB::addFeature(const QString &featureID, const QByteArray &feature, const QString &featureName, const QString &IID, const QString &userName, const QString &idVendor, const QString &idProduct, const int &deviceType, const QString &deviceSerialNumber, const int &authType)
{
    QSqlQuery query(database);
    query.prepare("INSERT into feature(featureID, feature, featureName, iid, userName, idVendor, idProduct, deviceType, deviceSerialNumber, authType)"
                  "VALUES(:featureID, :feature, :featureName, :iid, :userName, :idVendor, :idProduct, :deviceType, :deviceSerialNumber, :authType) ;");
    query.bindValue(":featureID", featureID);
    query.bindValue(":feature", feature);
    query.bindValue(":featureName", featureName);
    query.bindValue(":iid", IID);
    query.bindValue(":userName", userName);
    query.bindValue(":idVendor", idVendor);
    query.bindValue(":idProduct", idProduct);
    query.bindValue(":deviceType", deviceType);
    query.bindValue(":deviceSerialNumber", deviceSerialNumber);
    query.bindValue(":authType", authType);
    auto ret = query.exec();
    if (!ret)
    {
        KLOG_ERROR() << "add feature to db failed:" << query.lastError();
    }
    else
    {
        KLOG_INFO() << "add feature to db success:" << featureID;
    }
    return ret;
}

bool FeatureDB::deleteFeature(const QString &featureID)
{
    QSqlQuery query(database);
    query.prepare("DELETE FROM feature WHERE featureID = :id");
    query.bindValue(":id", featureID);
    return query.exec();
}

bool FeatureDB::deleteFearureByUserName(const QString &userName)
{
    QSqlQuery query(database);
    query.prepare("DELETE FROM feature WHERE userName = :id");
    query.bindValue(":id", userName);
    return query.exec();
}

bool FeatureDB::deleteFearureByIID(const QString &IID)
{
    QSqlQuery query(database);
    query.prepare("DELETE FROM feature WHERE iid = :id");
    query.bindValue(":id", IID);
    return query.exec();
    return false;
}

QByteArray FeatureDB::getFeature(const QString &featureID)
{
    QSqlQuery query(database);
    query.prepare("SELECT feature  FROM feature WHERE featureID = :id");
    query.bindValue(":id", featureID);
    query.exec();
    if (query.next())
    {
        QByteArray feature = query.value(0).toByteArray();
        return feature;
    }
    return QByteArray();
}

QList<QByteArray> FeatureDB::getFeature(const QString &idVendor, const QString &idProduct, int deviceType, const QString &deviceSerialNumber)
{
    QSqlQuery query(database);
    QString sql = "SELECT feature  FROM feature WHERE idVendor = :Vid AND idProduct = :Pid AND deviceType = :devType";
    if (!deviceSerialNumber.isEmpty())
    {
        sql.append(" AND deviceSerialNumber = :serialNumber");
    }

    query.prepare(sql);
    query.bindValue(":Vid", idVendor);
    query.bindValue(":Pid", idProduct);
    query.bindValue(":devType", (int)deviceType);
    query.bindValue(":serialNumber", deviceSerialNumber);
    query.exec();

    QByteArrayList featuresList;
    while (query.next())
    {
        QByteArray feature = query.value(0).toByteArray();
        featuresList << feature;
    }
    return featuresList;
}

QList<QByteArray> FeatureDB::getFeature()
{
    QSqlQuery query(database);
    query.prepare("SELECT feature FROM feature");
    query.exec();
    QByteArrayList featuresList;
    while (query.next())
    {
        QByteArray feature = query.value(0).toByteArray();
        featuresList << feature;
    }
    return featuresList;
}

QStringList FeatureDB::getFeatureID(const QString &idVendor, const QString &idProduct, int deviceType, const QString &deviceSerialNumber)
{
    QSqlQuery query(database);
    QString sql = "SELECT featureID  FROM feature WHERE idVendor = :Vid AND idProduct = :Pid AND deviceType = :devType";
    if (!deviceSerialNumber.isEmpty())
    {
        sql.append(" AND deviceSerialNumber = :serialNumber");
    }

    query.prepare(sql);
    query.bindValue(":Vid", idVendor);
    query.bindValue(":Pid", idProduct);
    query.bindValue(":devType", (int)deviceType);
    if (!deviceSerialNumber.isEmpty())
    {
        query.bindValue(":serialNumber", deviceSerialNumber);
    }
    query.exec();
    QStringList featureIDs;
    while (query.next())
    {
        QString featureID = query.value(0).toString();
        featureIDs << featureID;
    }
    return featureIDs;
}

QString FeatureDB::getFeatureID(QByteArray feature)
{
    QSqlQuery query(database);
    query.prepare("SELECT featureID  FROM feature WHERE feature = :feature");
    query.bindValue(":feature", feature);
    query.exec();
    if (query.next())
    {
        QString featureID = query.value(0).toString();
        return featureID;
    }
    return QString();
}

QStringList FeatureDB::getFeatureID()
{
    QSqlQuery query(database);
    query.prepare("SELECT featureID  FROM feature");
    query.exec();
    QStringList featureIDs;
    while (query.next())
    {
        QString featureID = query.value(0).toString();
        featureIDs << featureID;
    }
    return featureIDs;
}

FeatureData FeatureDB::getFeatureData(const QString &featureID)
{
    QSqlQuery query(database);
    query.prepare("SELECT userName, idVendor, idProduct, deviceType, deviceSerialNumber FROM feature WHERE featureID = :id");
    query.bindValue(":id", featureID);
    query.exec();
    FeatureData featureData;
    if (query.next())
    {
        featureData.feature = query.value("feature").toByteArray();
        featureData.featureID = featureID;
        featureData.featureName = query.value("featureName").toString();
        featureData.iid = query.value("iid").toString();
        featureData.userName = query.value("userName").toString();
        featureData.idVendor = query.value("idVendor").toString();
        featureData.idProduct = query.value("idProduct").toString();
        featureData.deviceSerialNumber = query.value("deviceSerialNumber").toString();
        featureData.deviceType = query.value("deviceType").toInt();
        featureData.authType = query.value("authType").toInt();
    }
    return featureData;
}

QString FeatureDB::getUserNameByIID(const QString &IID)
{
    QSqlQuery query(database);
    query.prepare("SELECT userName  FROM feature WHERE iid = :id");
    query.bindValue(":id", IID);
    query.exec();
    QString userName;
    if (query.next())
    {
        userName = query.value(0).toString();
    }
    return userName;
}

QStringList FeatureDB::getIID(const QString &userName, const int &authType)
{
    QSqlQuery query(database);
    query.prepare("SELECT iid  FROM feature WHERE userName = :id AND authType = :authType");
    query.bindValue(":id", userName);
    query.bindValue(":authType", authType);
    query.exec();
    QStringList iids;
    while (query.next())
    {
        QString iid = query.value(0).toString();
        iids << iid;
    }
    return iids;
}

QStringList FeatureDB::getFeatureID(const QString &userName, const int &authType)
{
    QSqlQuery query(database);
    query.prepare("SELECT featureID  FROM feature WHERE userName = :id AND authType = :authType");
    query.bindValue(":id", userName);
    query.bindValue(":authType", authType);
    query.exec();
    QStringList featureIDs;
    while (query.next())
    {
        QString featureID = query.value(0).toString();
        featureIDs << featureID;
    }
    return featureIDs;
}

QString FeatureDB::getUserNameByFetureID(const QString &featureID)
{
    QSqlQuery query(database);
    query.prepare("SELECT userName  FROM feature WHERE featureID = :id");
    query.bindValue(":id", featureID);
    query.exec();
    QString userName;
    if (query.next())
    {
        userName = query.value(0).toString();
    }
    if (userName.isEmpty())
    {
        KLOG_ERROR() << "getUserNameByFetureID failed, featureID:" << featureID << database.lastError();
    }
    return userName;
}

QString FeatureDB::getFeatureNameByIID(const QString &IID)
{
    QSqlQuery query(database);
    query.prepare("SELECT featureName  FROM feature WHERE iid = :id");
    query.bindValue(":id", IID);
    query.exec();
    QString featureName;
    if (query.next())
    {
        featureName = query.value(0).toString();
    }
    return featureName;
}

QString FeatureDB::getFetureIDByIID(const QString &IID)
{
    QSqlQuery query(database);
    query.prepare("SELECT featureID  FROM feature WHERE iid = :id");
    query.bindValue(":id", IID);
    query.exec();
    QString featureID;
    if (query.next())
    {
        featureID = query.value(0).toString();
    }
    return featureID;
}

bool FeatureDB::updateFeatureNameByIID(const QString &iid, const QString &featureName)
{
    QSqlQuery query(database);
    query.prepare("UPDATE feature SET featureName = :featureName WHERE iid = :iid");
    query.bindValue(":iid", iid);
    query.bindValue(":featureName", featureName);
    return query.exec();
}

QStringList FeatureDB::getIID(const QString &userName)
{
    QSqlQuery query(database);
    query.prepare("SELECT iid  FROM feature WHERE userName = :id");
    query.bindValue(":id", userName);
    query.exec();
    QStringList iids;
    while (query.next())
    {
        QString iid = query.value(0).toString();
        iids << iid;
    }
    return iids;
}

}  // namespace Kiran
