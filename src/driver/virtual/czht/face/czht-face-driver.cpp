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
#include <QCoreApplication>
#include <QDBusInterface>
#include <QDBusReply>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSettings>
#include <QTranslator>

#include "config.h"
#include "czht-define.h"
#include "czht-face-driver.h"

CZHTFaceDriver::CZHTFaceDriver(QObject *parent) : VirtualFaceDriver(parent), m_iface(nullptr)
{
    static QTranslator translator;
    if (!translator.load(QLocale(), "czht-face", ".", KAS_INSTALL_TRANSLATIONDIR,
                         ".qm"))
    {
        KLOG_INFO() << "Load translator failed!";
    }
    else
    {
        QCoreApplication::installTranslator(&translator);
    }

    KLOG_INFO() << "CZHTFaceDriver config file:" << QString(VIRTUAL_CZHT_DRIVER_INSTALL_DIR) + "/config.ini";
    QSettings settings(QString(VIRTUAL_CZHT_DRIVER_INSTALL_DIR) + "/config.ini", QSettings::IniFormat);
    m_searchTimeOut = settings.value("search_time_out").toInt();
    m_detectTimeOut = settings.value("detect_time_out").toInt();
    KLOG_INFO() << "CZHTFaceDriver config: business_id:" << BUSINESS_ID << "search_time_out:" << m_searchTimeOut << "detect_time_out:" << m_detectTimeOut;
}

CZHTFaceDriver::~CZHTFaceDriver()
{

}

QString CZHTFaceDriver::getDriverName() { return tr("virtual-face-czht"); }

QString CZHTFaceDriver::getErrorMsg(int errorNum)
{
    return getCZHTErrorMsg(errorNum);
}

DriverType CZHTFaceDriver::getType() { return DRIVER_TYPE_Virtual_Face; }

int CZHTFaceDriver::identify(const QString &extraInfo)
{
    return startSearch(extraInfo);
}

void CZHTFaceDriver::identifySuccessedPostProcess(const QString &extraInfo)
{
    // 启动人走监测
    startLeaveDetect(extraInfo);
}

QDBusInterface *CZHTFaceDriver::getBusInterface()
{
    if (!m_iface || !m_iface->isValid())
    {
        m_iface = new QDBusInterface(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE,
                                     QDBusConnection::systemBus(), this);
    }
    return m_iface;
}

QString CZHTFaceDriver::dbusCall(QString method, QString args)
{
    QDBusInterface *iface = getBusInterface();
    if (!iface || !iface->isValid())
    {
        QJsonObject jsonObj;
        jsonObj.insert("code", CZHT_ERROR_DAEMON_NOT_RUNNING);
        QJsonDocument jsonDoc(jsonObj);
        KLOG_ERROR() << "D-Bus interface invalid";
        return jsonDoc.toJson();
    }

    KLOG_INFO() << "DBus call:" << method << args;
    QDBusReply<QString> reply = iface->call(method, args);
    if (reply.isValid())
    {
        return reply.value();
    }
    else
    {
        KLOG_INFO() << "Call failed:" << reply.error().message().toLocal8Bit();
        return "";
    }
}

int CZHTFaceDriver::startSearch(const QString &extraInfo)
{
    KLOG_INFO() << "CZHTFaceDriver startSearch";
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject extraInfoJsonObj = extraInfoJsonDoc.object();
    QString searchUserName = extraInfoJsonObj.value("user_name").toString();
    QString searchMachineCode = extraInfoJsonObj.value("machine_code").toString();

    QJsonObject jsonObj;
    jsonObj.insert("business_id", BUSINESS_ID);
    jsonObj.insert("search_time_out", m_searchTimeOut);
    QJsonDocument jsonDoc(jsonObj);

    QString reply = dbusCall("StartSearch", jsonDoc.toJson());
    jsonDoc = QJsonDocument::fromJson(reply.toUtf8());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    KLOG_INFO() << "StartSearch reply:" << jsonObj;
    if (error_code != CZHT_SUCCESS)
    {
        KLOG_ERROR() << "StartSearch failed:" << error_code << jsonObj;
        return error_code;
    }

    bool found = false;
    QJsonArray users = jsonObj.value("users").toArray();
    for (const QJsonValue &user : users)
    {
        QJsonObject userObj = user.toObject();
        int personID = userObj.value("person_id").toInt();
        QString personName = userObj.value("person_name").toString();
        QString user_id = userObj.value("user_id").toString();
        QJsonArray device_code = userObj.value("device_code").toArray();
        bool expired = userObj.value("expired").toBool();
        KLOG_INFO() << "person_id:" << personID << "personName:" << personName << "user_id:" << user_id << "device_code:" << device_code << "expired:" << expired;
        if (user_id == searchUserName && device_code.contains(searchMachineCode))
        {
            if (expired)
            {
                KLOG_ERROR() << "StartSearch user expired:" << searchUserName << searchMachineCode;
                return CZHT_ERROR_USER_EXPIRED;
            }

            // 人脸服务的用户，用于启动人走监测
            m_personIDLast = personID;
            found = true;
            break;
        }
    }

    if (!found)
    {
        KLOG_ERROR() << "StartSearch user not match:" << searchUserName << searchMachineCode;
        return CZHT_ERROR_MATCH_PERSON_NOT_FOUND;
    }

    return CZHT_SUCCESS;
}

int CZHTFaceDriver::startLeaveDetect(const QString &extraInfo)
{
    QJsonObject jsonObj;
    jsonObj.insert("business_id", BUSINESS_ID);
    jsonObj.insert("person_id", m_personIDLast);
    jsonObj.insert("os_user", extraInfo);
    jsonObj.insert("detect_time_out", m_detectTimeOut);
    QJsonDocument jsonDoc(jsonObj);

    auto reply = dbusCall("StartLeaveDetect", jsonDoc.toJson());
    jsonDoc = QJsonDocument::fromJson(reply.toUtf8());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    if (error_code != CZHT_SUCCESS)
    {
        KLOG_ERROR() << "DBus call failed:" << error_code << jsonObj;
        return error_code;
    }
    else
    {
        QString error_msg = jsonObj.value("error_msg").toString();
        KLOG_INFO() << "Reply from service:" << error_code << error_msg << jsonObj;
        return error_code;
    }
}

extern "C" Driver *createDriver() { return new CZHTFaceDriver(); }