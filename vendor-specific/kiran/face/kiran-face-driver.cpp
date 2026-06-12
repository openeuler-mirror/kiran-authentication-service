/**
 * Copyright (c) 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     licheng <licheng@kylinsec.com.cn>
 */

#include <qt5-log-i.h>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "config.h"
#include "kiran-define.h"
#include "kiran-face-driver.h"

KiranFaceDriver::KiranFaceDriver(QObject *parent) : VirtualFaceDriver(parent), KiranDriverBase(parent)
{
    loadTranslator("kiran-face");
}

KiranFaceDriver::~KiranFaceDriver()
{
}

QString KiranFaceDriver::getDriverName() { return "virtual-face-kiran"; }

QString KiranFaceDriver::getErrorMsg(int errorNum)
{
    return getKiranErrorMsg(errorNum);
}

DriverType KiranFaceDriver::getType() { return DRIVER_TYPE_Virtual_Face; }

int KiranFaceDriver::identify(const QString &extraInfo)
{
    return startSearch(extraInfo);
}

void KiranFaceDriver::identifyResultPostProcess(const QString &extraInfo)
{
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject jsonObj = extraInfoJsonDoc.object();

    int result = jsonObj.value("result").toInt(0);
    QString osUser = jsonObj.value("os_user").toString();

    jsonObj.insert("auth_type", tr("face auth"));

    reportLoginLog(jsonObj);

    if (result == 1)
    {
        startLeaveDetect(osUser);
    }
}

int KiranFaceDriver::startSearch(const QString &extraInfo)
{
    KLOG_INFO() << "KiranFaceDriver startSearch";
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject extraInfoJsonObj = extraInfoJsonDoc.object();
    QString searchUserName = extraInfoJsonObj.value("user_name").toString();
    QString searchMachineCode = extraInfoJsonObj.value("machine_code").toString();

    QJsonObject jsonObj;
    jsonObj.insert("business_id", KIRAN_BUSINESS_ID);
    // C1: 追加 user_name 字段
    jsonObj.insert("user_name", searchUserName);
    // C3: machine_code 字段
    jsonObj.insert("machine_code", searchMachineCode);
    jsonObj.insert("search_time_out", m_searchTimeOut);
    QJsonDocument jsonDoc(jsonObj);

    QString reply = dbusCall("StartSearch", jsonDoc.toJson());
    KLOG_INFO() << "Kiran StartSearch reply:" << reply;
    jsonDoc = QJsonDocument::fromJson(reply.toLatin1());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    if (error_code != KIRAN_SUCCESS)
    {
        KLOG_ERROR() << "Kiran StartSearch failed:" << error_code << jsonObj;
        return error_code;
    }

    bool found = false;
    bool foundExpired = false;
    QJsonArray users = jsonObj.value("users").toArray();
    if (users.isEmpty())
    {
        KLOG_ERROR() << "Kiran StartSearch: no face binding relation, user_id:" << searchUserName << "machine_code:" << searchMachineCode;
        return KIRAN_ERROR_NO_FACE_BINDING_RELATION;
    }

    for (const QJsonValue &user : users)
    {
        QJsonObject userObj = user.toObject();
        int personID = userObj.value("person_id").toInt();
        QString personName = userObj.value("person_name").toString();
        QString user_id = userObj.value("user_id").toString();
        QJsonArray device_code = userObj.value("device_code").toArray();
        bool expired = userObj.value("expired").toBool();
        KLOG_INFO() << "Kiran: person_id:" << personID << "personName:" << personName << "user_id:" << user_id << "device_code:" << device_code << "expired:" << expired;
        if (user_id == searchUserName && device_code.contains(searchMachineCode))
        {
            if (expired)
            {
                foundExpired = true;
                KLOG_INFO() << "Kiran StartSearch found expired user:" << searchUserName << searchMachineCode;
                continue;
            }
            else
            {
                m_personIDLast = personID;
                found = true;
                break;
            }
        }
    }

    if (!found && foundExpired)
    {
        KLOG_ERROR() << "Kiran StartSearch user expired:" << searchUserName << searchMachineCode;
        return KIRAN_ERROR_USER_EXPIRED;
    }
    else if (!found && !foundExpired)
    {
        KLOG_ERROR() << "Kiran StartSearch: no login permission, user_id:" << searchUserName << "machine_code:" << searchMachineCode;
        return KIRAN_ERROR_NO_LOGIN_PERMISSION;
    }

    return KIRAN_SUCCESS;
}

QList<int> KiranFaceDriver::getSupportedAuthTypes()
{
    return getSupportedAuthTypesFromService();
}

extern "C" Driver *createDriver() { return new KiranFaceDriver(); }
