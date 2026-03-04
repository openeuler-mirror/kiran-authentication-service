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
    // 加载翻译
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
    bool foundExpired = false;  // 记录是否找到匹配但已过期的数据
    QJsonArray users = jsonObj.value("users").toArray();
    if (users.isEmpty())
    {
        KLOG_ERROR() << "no face binding relation, user_id:" << searchUserName << "machine_code:" << searchMachineCode;
        return CZHT_ERROR_NO_FACE_BINDING_RELATION;
    }

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
                // 数据匹配但已过期，记录标志，继续遍历
                foundExpired = true;
                KLOG_INFO() << "StartSearch found expired user:" << searchUserName << searchMachineCode;
                continue;
            }
            else
            {
                // 数据匹配且未过期，跳出循环
                m_personIDLast = personID;
                found = true;
                break;
            }
        }
    }

    // 如果没找到匹配且未过期的数据，但存在过期数据，返回过期错误
    if (!found && foundExpired)
    {
        KLOG_ERROR() << "StartSearch user expired:" << searchUserName << searchMachineCode;
        return CZHT_ERROR_USER_EXPIRED;
    }
    // 存在绑定关系，但无当前机器绑定关系
    else if (!found && !foundExpired)
    {
        KLOG_ERROR() << "no login permission, user_id:" << searchUserName << "machine_code:" << searchMachineCode;
        return CZHT_ERROR_NO_LOGIN_PERMISSION;
    }

    return CZHT_SUCCESS;
}

extern "C" Driver *createDriver() { return new CZHTFaceDriver(); }