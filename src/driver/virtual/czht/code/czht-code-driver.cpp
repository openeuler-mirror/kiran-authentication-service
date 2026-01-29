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
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSettings>
#include <QTranslator>

#include "config.h"
#include "czht-code-driver.h"
#include "czht-define.h"

CZHTCodeDriver::CZHTCodeDriver(QObject *parent) : VirtualCodeDriver(parent)
{
    static QTranslator translator;
    if (!translator.load(QLocale(), "czht-code", ".", KAS_INSTALL_TRANSLATIONDIR,
                         ".qm"))
    {
        KLOG_INFO() << "Load translator failed!";
    }
    else
    {
        QCoreApplication::installTranslator(&translator);
    }

    KLOG_INFO() << "CZHTCodeDriver config file:" << QString(VIRTUAL_CZHT_DRIVER_INSTALL_DIR) + "/config.ini";
    QSettings settings(QString(VIRTUAL_CZHT_DRIVER_INSTALL_DIR) + "/config.ini", QSettings::IniFormat);
    m_detectTimeOut = settings.value("detect_time_out").toInt();

    m_iface = new QDBusInterface(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE,
                                 QDBusConnection::systemBus(), this);
    if (!m_iface->isValid())
    {
        KLOG_ERROR() << "D-Bus interface invalid";
        return;
    }

    bool ret = QDBusConnection::systemBus().connect(
        DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE, "LeaveDetected", this,
        SLOT(leaveDetected(QString)));
    KLOG_INFO() << "connect to dbus signal com.czht.face.daemon.LeaveDetected:" << ret;
}

CZHTCodeDriver::~CZHTCodeDriver()
{
    // 断开 systemBus 上的信号连接
    QDBusConnection::systemBus().disconnect(
        DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE, "LeaveDetected", this,
        SLOT(leaveDetected(QString)));
}

QString CZHTCodeDriver::getDriverName() { return tr("virtual-code-czht"); }

QString CZHTCodeDriver::getErrorMsg(int errorNum)
{
    return getCZHTErrorMsg(errorNum);
}

DriverType CZHTCodeDriver::getType() { return DRIVER_TYPE_Virtual_Code; }

int CZHTCodeDriver::identify(const QString &extraInfo)
{
    return verifyAuthorizationCode(extraInfo);
}

int CZHTCodeDriver::verifyAuthorizationCode(const QString &extraInfo)
{
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject extraInfoJsonObj = extraInfoJsonDoc.object();
    QString searchUserName = extraInfoJsonObj.value("user_name").toString();
    QString searchMachineCode = extraInfoJsonObj.value("machine_code").toString();
    QString authorizationCode = extraInfoJsonObj.value("code").toString();

    QJsonObject jsonObj;
    jsonObj.insert("business_id", BUSINESS_ID);
    jsonObj.insert("user_id", searchUserName);
    jsonObj.insert("code", authorizationCode);
    jsonObj.insert("device_code", searchMachineCode);

    QJsonDocument jsonDoc(jsonObj);

    auto reply = dbusCall("CodeCheck", jsonDoc.toJson());
    KLOG_INFO() << "CodeCheck reply:" << reply;
    jsonDoc = QJsonDocument::fromJson(reply.toUtf8());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();

    if (error_code != CZHT_SUCCESS)
    {
        KLOG_ERROR() << "CodeCheck failed:" << error_code << jsonObj;
        return error_code;
    }

    bool found = false;
    bool expired = false;
    QJsonArray users = jsonObj.value("users").toArray();
    for (const QJsonValue &user : users)
    {
        QJsonObject userObj = user.toObject();
        int personID = userObj.value("person_id").toInt();
        QString personName = userObj.value("person_name").toString();
        QString userID = userObj.value("user_id").toString();
        QJsonArray device_code = userObj.value("device_code").toArray();
        KLOG_INFO() << "person_id:" << personID << "personName:" << personName << "user_id:" << userID << "device_code:" << device_code << "expired:" << expired;
        if (device_code.contains(searchMachineCode))
        {
            expired = userObj.value("expired").toBool();
            if (expired)
            {
                continue;
            }
            // 人脸服务的用户，用于启动人走监测
            m_personIDLast = personID;
            found = true;
            break;
        }
    }

    if (expired)
    {
        KLOG_ERROR() << "CodeCheck user expired:" << searchUserName << searchMachineCode;
        return CZHT_ERROR_USER_EXPIRED;
    }

    if (!found)
    {
        KLOG_ERROR() << "StartSearch user not match:" << searchUserName << searchMachineCode;
        return CZHT_ERROR_MATCH_PERSON_NOT_FOUND;
    }

    return CZHT_SUCCESS;
}

void CZHTCodeDriver::identifySuccessedPostProcess(const QString &extraInfo)
{
    // 启动人走监测
    startLeaveDetect(extraInfo);

    // 授权码登录需要录屏
    QString osUser = extraInfo;
    QString fileName = QString("%1_%2_%3.mp4").arg(m_personIDLast).arg(osUser).arg(QDateTime::currentDateTime().toString("yyyyMMddHHmmss"));
    QProcess::startDetached("sudo", QStringList() << "-u"
                                                  << osUser
                                                  << "kiran-screen-recorder"
                                                  << fileName);
}

int CZHTCodeDriver::startLeaveDetect(const QString &extraInfo)
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

QString CZHTCodeDriver::dbusCall(QString method, QString args)
{
    KLOG_INFO() << "DBus call:" << method << args;
    QDBusReply<QString> reply = m_iface->call(method, args);
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

extern "C" Driver *createDriver() { return new CZHTCodeDriver(); }