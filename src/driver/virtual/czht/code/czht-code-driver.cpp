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
#include <QDBusInterface>
#include <QDBusReply>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSettings>

#include "config.h"
#include "czht-code-driver.h"
#include "czht-define.h"

CZHTCodeDriver::CZHTCodeDriver(QObject *parent) : VirtualCodeDriver(parent), CZHTDriverBase(parent)
{
    // 加载翻译
    loadTranslator("czht-code");

    // 加载录屏配置
    KLOG_INFO() << "CZHTCodeDriver config file:" << VIRTUAL_CZHT_DRIVER_CONFIG_FILE;
    QSettings settings(VIRTUAL_CZHT_DRIVER_CONFIG_FILE, QSettings::IniFormat);
    m_enableScreenRecorder = settings.value(CZHT_CONFIG_KEY_ENABLE_SCREEN_RECORDER, true).toBool();
    KLOG_INFO() << "CZHTCodeDriver config: enable_screen_recorder:" << m_enableScreenRecorder;

    // 初始化 D-Bus 接口（直接初始化方式，不使用延迟初始化）
    m_iface = new QDBusInterface(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE,
                                 QDBusConnection::systemBus(), this);
    if (!m_iface->isValid())
    {
        KLOG_ERROR() << "D-Bus interface invalid";
        return;
    }

    // 连接 LeaveDetected 信号
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

QString CZHTCodeDriver::getDriverName() { return "virtual-code-czht"; }

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

void CZHTCodeDriver::identifyResultPostProcess(const QString &extraInfo)
{
    // 解析 extraInfo JSON
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject jsonObj = extraInfoJsonDoc.object();

    int result = jsonObj.value("result").toInt(0);
    QString osUser = jsonObj.value("os_user").toString();

    // 上报登录日志（调用基类方法）
    reportLoginLog(jsonObj);

    // 只有成功时才启动人走监测和录屏
    if (result == 1)
    {
        // 启动人走监测（调用基类方法）
        startLeaveDetect(osUser);

        // 授权码登录需要录屏（特有功能，根据配置决定是否开启）
        if (m_enableScreenRecorder)
        {
            QString fileName = QString("%1_%2_%3.mp4").arg(m_personIDLast).arg(osUser).arg(QDateTime::currentDateTime().toString("yyyyMMddHHmmss"));
            QProcess::startDetached("kiran-screen-recorder", QStringList() << fileName);
        }
    }
}

QString CZHTCodeDriver::dbusCall(QString method, QString args)
{
    // 覆盖基类方法，使用直接初始化方式（不使用延迟初始化）
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