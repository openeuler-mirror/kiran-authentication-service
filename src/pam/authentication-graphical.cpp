/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-session-manager is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     tangjie02 <tangjie02@kylinos.com.cn>
 */

#include "src/pam/authentication-graphical.h"
#include <kas-authentication-i.h>
#include <pam_modules.h>
#include <qt5-log-i.h>
#include <syslog.h>
#include "src/pam/auth_manager_proxy.h"
#include "src/pam/auth_session_proxy.h"

namespace Kiran
{
AuthenticationGraphical::AuthenticationGraphical(PAMHandle* pamHandle,
                                                 const QStringList& arguments)
    : Authentication(pamHandle,
                     arguments)
{
}

void AuthenticationGraphical::notifyAuthMode()
{
    auto authMode = this->m_authManagerProxy->authMode();
    QJsonDocument jsonDoc(QJsonObject{
        {KAP_PJK_KEY_HEAD, QJsonObject{{KAP_PJK_KEY_CMD, KAPProtoID::KAP_REQ_CMD_NOTIFY_AUTH_MODE}}},
        {KAP_PJK_KEY_BODY, QJsonObject{{KAP_PJK_KEY_AUTH_MODE, authMode}}}});

    this->m_pamHandle->sendTextMessage(KAP_PROTO_JSON_PREFIX + QString(jsonDoc.toJson()));
}

bool AuthenticationGraphical::requestLoginUserSwitchable()
{
    QJsonDocument jsonReqDoc(QJsonObject{
        {KAP_PJK_KEY_HEAD, QJsonObject{{KAP_PJK_KEY_CMD, KAPProtoID::KAP_REQ_CMD_LOGIN_USER_SWITCHABLE}}},
    });

    QString response;
    auto retval = this->m_pamHandle->sendQuestionPrompt(KAP_PROTO_JSON_PREFIX + QString(jsonReqDoc.toJson()), response);
    auto jsonRspDoc = QJsonDocument::fromJson(response.toUtf8());

    // 请求失败的情况下使用默认值
    if (retval != PAM_SUCCESS)
    {
        auto errorMsg = jsonReqDoc[KAP_PJK_KEY_HEAD][KAP_PJK_KEY_ERROR].toString();
        this->m_pamHandle->syslog(LOG_WARNING, QString("Request login user switchable failed: %1").arg(errorMsg));
        return false;
    }

    return jsonRspDoc[KAP_PJK_KEY_BODY][KAP_PJK_KEY_LOGIN_USER_SWITCHABLE].toBool();
}

void AuthenticationGraphical::notifySupportAuthType()
{
    auto authType = this->m_authManagerProxy->GetAuthTypeByApp(m_authApplication);
    QList<int> authTypeList = authType.value();
    authTypeList << KAD_AUTH_TYPE_PASSWORD;

    QStringList authTypeStrList;
    for (auto authType : authTypeList)
    {
        authTypeStrList << QString::number(authType);
    }

    QJsonDocument jsonDoc(QJsonObject{
        {KAP_PJK_KEY_HEAD, QJsonObject{{KAP_PJK_KEY_CMD, KAPProtoID::KAP_REQ_CMD_NOTIFY_SUPPORT_AUTH_TYPE}}},
        {KAP_PJK_KEY_BODY, QJsonObject{{KAP_PJK_KEY_AUTH_TYPES, QJsonArray::fromStringList(authTypeStrList)}}}});

    this->m_pamHandle->sendTextMessage(KAP_PROTO_JSON_PREFIX + QString(jsonDoc.toJson()));
}

int32_t AuthenticationGraphical::requestAuthType()
{
    QJsonDocument jsonReqDoc(QJsonObject{
        {KAP_PJK_KEY_HEAD, QJsonObject{{KAP_PJK_KEY_CMD, KAPProtoID::KAP_REQ_CMD_AUTH_TYPE}}},
    });

    QString response;
    auto retval = this->m_pamHandle->sendQuestionPrompt(KAP_PROTO_JSON_PREFIX + QString(jsonReqDoc.toJson()), response);
    auto jsonRspDoc = QJsonDocument::fromJson(response.toUtf8());
    // 请求失败的情况下使用默认认证类型
    if (retval != PAM_SUCCESS)
    {
        auto errorMsg = jsonReqDoc[KAP_PJK_KEY_HEAD][KAP_PJK_KEY_ERROR].toString();
        this->m_pamHandle->syslog(LOG_WARNING, QString("Request auth type failed: %1").arg(errorMsg));
        return KADAuthType::KAD_AUTH_TYPE_NONE;
    }
    return jsonRspDoc[KAP_PJK_KEY_BODY][KAP_PJK_KEY_AUTH_TYPE].toInt();
}

void AuthenticationGraphical::notifyAuthType(int authType)
{
    QJsonDocument jsonDoc(QJsonObject{
        {KAP_PJK_KEY_HEAD, QJsonObject{{KAP_PJK_KEY_CMD, KAPProtoID::KAP_REQ_CMD_NOTIFY_AUTH_TYPE}}},
        {KAP_PJK_KEY_BODY, QJsonObject{{KAP_PJK_KEY_AUTH_TYPE, authType}}}});

    this->m_pamHandle->sendTextMessage(KAP_PROTO_JSON_PREFIX + QString(jsonDoc.toJson()));
}

}  // namespace Kiran
