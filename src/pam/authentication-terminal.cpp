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
#include "src/pam/auth_session_proxy.h"
#include "src/pam/authentication.h"

namespace Kiran
{
AuthenticationTerminal::AuthenticationTerminal(PAMHandle *pamHandle) : Authentication(pamHandle)
{
}

int32_t AuthenticationTerminal::requestAuthType()
{
    do
    {
        auto requestRaw = QObject::tr("Select Authentication type (%1 default, %2 password, %3 fingerprint): ");
        QString request = requestRaw.arg(KADAuthType::KAD_AUTH_TYPE_NONE)
                              .arg(KADAuthType::KAD_AUTH_TYPE_PASSWORD)
                              .arg(KADAuthType::KAD_AUTH_TYPE_FINGERPRINT);
        QString response;
        auto retval = this->m_pamHandle->sendQuestionPrompt(request, response);
        // 请求失败的情况下使用默认认证类型
        if (retval != PAM_SUCCESS)
        {
            this->m_pamHandle->syslog(LOG_WARNING, "Request auth type failed.");

            return KADAuthType::KAD_AUTH_TYPE_NONE;
        }

        auto authType = response.toInt();
        this->m_pamHandle->syslog(LOG_DEBUG, QString("AuthType %1 is selected.").arg(authType));

        if (authType == KADAuthType::KAD_AUTH_TYPE_NONE ||
            authType == KADAuthType::KAD_AUTH_TYPE_PASSWORD ||
            authType == KADAuthType::KAD_AUTH_TYPE_FINGERPRINT)
        {
            return authType;
        }
    } while (true);

    return KADAuthType::KAD_AUTH_TYPE_NONE;
}

}  // namespace Kiran
