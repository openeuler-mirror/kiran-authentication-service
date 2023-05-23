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

#pragma once

#include "src/pam/authentication.h"
#include "kas-authentication-i.h"
#include <QMap>

namespace Kiran
{
class AuthenticationTerminal : public Authentication
{
    Q_OBJECT
public:
    AuthenticationTerminal(PAMHandle* pamHandle, const QStringList& arguments);
    virtual ~AuthenticationTerminal(){};

private:
    virtual void notifyAuthMode() {}
    virtual bool requestLoginUserSwitchable() { return false; };
    virtual void notifySupportAuthType();
    virtual int32_t requestAuthType();
    virtual void notifyAuthType(int authType){};

private:
    QList<KADAuthType> m_supportAuthTypes;
    QMap<KADAuthType, QString> m_authTypeTranslator;
};

}  // namespace Kiran
