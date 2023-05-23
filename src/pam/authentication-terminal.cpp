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

#include "src/pam/authentication-terminal.h"
#include <kas-authentication-i.h>
#include <pam_modules.h>
#include <qt5-log-i.h>
#include <syslog.h>
#include "src/pam/auth_manager_proxy.h"
#include "src/pam/auth_session_proxy.h"
#include "src/pam/authentication.h"
#include "src/utils/utils.h"

namespace Kiran
{
AuthenticationTerminal::AuthenticationTerminal(PAMHandle* pamHandle,
                                               const QStringList& arguments)
    : Authentication(pamHandle, arguments)
{
}

void AuthenticationTerminal::notifySupportAuthType()
{
    auto authType = this->m_authManagerProxy->GetAuthTypeByApp(m_authApplication);
    QList<int> authTypeList = authType.value();
    authTypeList << KAD_AUTH_TYPE_PASSWORD;

    QList<KADAuthType> tempAuthTypeList;
    for (auto authType : authTypeList)
    {
        tempAuthTypeList << (KADAuthType)authType;
    }

    m_supportAuthTypes.swap(tempAuthTypeList);
}

int32_t AuthenticationTerminal::requestAuthType()
{
    do
    {
        // 从1开始生成认证类型以及序号，例如："1 指纹认证","2 指静脉认证"
        QStringList authTypeStringList;
        for (int i = 0; i < m_supportAuthTypes.count(); i++)
        {
            auto authType = m_supportAuthTypes.at(i);
            QString authTypeStr = Utils::authTypeEnum2Str(authType);

            authTypeStr = Utils::authTypeEnum2LocaleStr(authType);
            if (authTypeStr.isEmpty())
            {
                KLOG_WARNING() << "cann't find auth type translator:" << authType;
                authTypeStr = QString("AuthType%1").arg(authType);
            }

            authTypeStringList << QString("%1 %2").arg(i + 1).arg(authTypeStr);
        }
        auto authTypeSelectDesc = authTypeStringList.join(",");
        auto request = QString(tr("Select Authentication type (%1): ")).arg(authTypeSelectDesc);

        QString response;
        auto retval = this->m_pamHandle->sendQuestionPrompt(request, response);

        // 请求失败的情况下使用密码认证类型
        if (retval != PAM_SUCCESS)
        {
            this->m_pamHandle->syslog(LOG_WARNING, "Request auth type failed.");
            return KADAuthType::KAD_AUTH_TYPE_PASSWORD;
        }

        // 校验输入正确
        bool toIntOk = false;
        int selectedIdx = response.toInt(&toIntOk);
        if (!toIntOk || selectedIdx <= 0 || selectedIdx > m_supportAuthTypes.count())
        {
            this->m_pamHandle->sendErrorMessage(tr("The authentication type is invalid. Please select a new one"));
            continue;
        }

        auto authType = m_supportAuthTypes.at(selectedIdx - 1);
        this->m_pamHandle->syslog(LOG_DEBUG, QString("AuthType %1 is selected.").arg(authType));
        if (authType == KADAuthType::KAD_AUTH_TYPE_PASSWORD ||
            authType == KADAuthType::KAD_AUTH_TYPE_FINGERPRINT ||
            authType == KADAuthType::KAD_AUTH_TYPE_FINGERVEIN ||
            authType == KADAuthType::KAD_AUTH_TYPE_UKEY ||
            authType == KADAuthType::KAD_AUTH_TYPE_FACE)
        {
            return authType;
        }

    } while (true);

    return KADAuthType::KAD_AUTH_TYPE_PASSWORD;
}
#if 0
void AuthenticationTerminal::notifyAuthType(int authType)
{
    QString tips = QString("%1 authentication is being performed").arg(Utils::authTypeEnum2Str(authType));
    this->m_pamHandle->sendTextMessage(tips);
}
#endif
}  // namespace Kiran
