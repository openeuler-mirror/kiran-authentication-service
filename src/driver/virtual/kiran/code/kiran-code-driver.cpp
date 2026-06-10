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
#include "kiran-code-driver.h"
#include "kiran-define.h"

KiranCodeDriver::KiranCodeDriver(QObject *parent)
    : VirtualCodeDriver(parent), KiranDriverBase(parent), m_enableScreenRecorder(false)
{
    loadTranslator("kiran-code");
}

KiranCodeDriver::~KiranCodeDriver()
{
}

QString KiranCodeDriver::getDriverName() { return "virtual-code-kiran"; }

QString KiranCodeDriver::getErrorMsg(int errorNum)
{
    return getKiranErrorMsg(errorNum);
}

DriverType KiranCodeDriver::getType() { return DRIVER_TYPE_Virtual_Code; }

int KiranCodeDriver::identify(const QString &extraInfo)
{
    return verifyAuthorizationCode(extraInfo);
}

void KiranCodeDriver::identifyResultPostProcess(const QString &extraInfo)
{
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject jsonObj = extraInfoJsonDoc.object();

    int result = jsonObj.value("result").toInt(0);
    QString osUser = jsonObj.value("os_user").toString();

    jsonObj.insert("auth_type", tr("authorization code auth"));

    reportLoginLog(jsonObj);

    if (result == 1)
    {
        startLeaveDetect(osUser);
    }
}

int KiranCodeDriver::verifyAuthorizationCode(const QString &extraInfo)
{
    KLOG_INFO() << "KiranCodeDriver verifyAuthorizationCode";
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject extraInfoJsonObj = extraInfoJsonDoc.object();
    QString authCode = extraInfoJsonObj.value("auth_code").toString();
    QString userName = extraInfoJsonObj.value("user_name").toString();
    QString machineCode = extraInfoJsonObj.value("machine_code").toString();

    QJsonObject jsonObj;
    jsonObj.insert("business_id", KIRAN_BUSINESS_ID);
    // C1: 追加 user_name 字段
    jsonObj.insert("user_name", userName);
    // C3: machine_code 字段
    jsonObj.insert("machine_code", machineCode);
    jsonObj.insert("auth_code", authCode);
    QJsonDocument jsonDoc(jsonObj);

    QString reply = dbusCall("CodeCheck", jsonDoc.toJson());
    KLOG_INFO() << "Kiran CodeCheck reply:" << reply;
    jsonDoc = QJsonDocument::fromJson(reply.toLatin1());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    if (error_code != KIRAN_SUCCESS)
    {
        KLOG_ERROR() << "Kiran CodeCheck failed:" << error_code << jsonObj;
        return error_code;
    }

    QJsonArray users = jsonObj.value("users").toArray();
    if (users.isEmpty())
    {
        KLOG_ERROR() << "Kiran CodeCheck: no valid users returned";
        return KIRAN_ERROR_AUTHORIZATION_CODE_NOT_FOUND;
    }

    // 取第一个匹配用户
    QJsonObject userObj = users.first().toObject();
    m_personIDLast = userObj.value("person_id").toInt();
    KLOG_INFO() << "Kiran CodeCheck success, person_id:" << m_personIDLast;

    return KIRAN_SUCCESS;
}

extern "C" Driver *createDriver() { return new KiranCodeDriver(); }
