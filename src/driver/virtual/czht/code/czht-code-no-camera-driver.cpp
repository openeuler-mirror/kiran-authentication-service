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
#include <QJsonDocument>
#include <QJsonObject>

#include "config.h"
#include "czht-code-no-camera-driver.h"
#include "czht-define.h"

CZHTCodeNoCameraDriver::CZHTCodeNoCameraDriver(QObject *parent)
    : VirtualCodeDriver(parent), CZHTDriverBase(parent)
{
    loadTranslator("czht-code");
}

CZHTCodeNoCameraDriver::~CZHTCodeNoCameraDriver() {}

QString CZHTCodeNoCameraDriver::getDriverName()
{
    return "virtual-code-czht-no-camera";
}

DriverType CZHTCodeNoCameraDriver::getType()
{
    return DRIVER_TYPE_Virtual_Code_No_Camera;
}

QString CZHTCodeNoCameraDriver::getErrorMsg(int errorNum)
{
    return getCZHTErrorMsg(errorNum);
}

int CZHTCodeNoCameraDriver::identify(const QString &extraInfo)
{
    return verifyAuthorizationCode(extraInfo);
}

void CZHTCodeNoCameraDriver::identifyResultPostProcess(const QString &extraInfo)
{
    // 解析 extraInfo JSON
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject jsonObj = extraInfoJsonDoc.object();

    jsonObj.insert("auth_type", tr("code no camera auth"));
    // 上报登录日志（调用基类方法）
    reportLoginLog(jsonObj);
}

int CZHTCodeNoCameraDriver::verifyAuthorizationCode(const QString &extraInfo)
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

    if (reply.isEmpty())
    {
        KLOG_ERROR() << "CodeCheck D-Bus call returned empty reply";
        return CZHT_ERROR_SERVER_RETURN_ERROR;
    }

    jsonDoc = QJsonDocument::fromJson(reply.toLatin1());
    if (jsonDoc.isNull() || !jsonDoc.isObject())
    {
        KLOG_ERROR() << "CodeCheck invalid JSON reply:" << reply;
        return CZHT_ERROR_SERVER_RETURN_ERROR;
    }

    jsonObj = jsonDoc.object();
    if (!jsonObj.contains("code"))
    {
        KLOG_ERROR() << "CodeCheck reply missing code field:" << jsonObj;
        return CZHT_ERROR_SERVER_RETURN_ERROR;
    }

    int error_code = jsonObj.value("code").toInt();

    if (error_code != CZHT_SUCCESS)
    {
        KLOG_ERROR() << "CodeCheck failed:" << error_code << jsonObj;
        return error_code;
    }

    return CZHT_SUCCESS;
}

extern "C" Driver *createDriver() { return new CZHTCodeNoCameraDriver(); }
