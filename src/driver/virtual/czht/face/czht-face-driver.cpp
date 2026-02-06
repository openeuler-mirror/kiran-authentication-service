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
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "config.h"
#include "czht-define.h"
#include "czht-face-driver.h"

CZHTFaceDriver::CZHTFaceDriver(QObject *parent) : VirtualFaceDriver(parent), CZHTDriverBase(parent)
{
    // 加载翻译器
    loadTranslator("czht-face");
}

CZHTFaceDriver::~CZHTFaceDriver()
{
}

QString CZHTFaceDriver::getDriverName() { return "virtual-face-czht"; }

QString CZHTFaceDriver::getErrorMsg(int errorNum)
{
    return getCZHTErrorMsg(errorNum);
}

DriverType CZHTFaceDriver::getType() { return DRIVER_TYPE_Virtual_Face; }

int CZHTFaceDriver::identify(const QString &extraInfo)
{
    return startSearch(extraInfo);
}

void CZHTFaceDriver::identifyResultPostProcess(const QString &extraInfo)
{
    // 解析 extraInfo JSON
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject jsonObj = extraInfoJsonDoc.object();

    int result = jsonObj.value("result").toInt(0);
    QString osUser = jsonObj.value("os_user").toString();

    // 上报登录日志（调用基类方法）
    reportLoginLog(jsonObj);

    // 只有成功时才启动人走监测（调用基类方法）
    if (result == 1)
    {
        startLeaveDetect(osUser);
    }
}

// getBusInterface 和 dbusCall 已在基类中实现，使用延迟初始化方式

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

extern "C" Driver *createDriver() { return new CZHTFaceDriver(); }