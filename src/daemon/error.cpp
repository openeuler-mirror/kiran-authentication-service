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

#include "src/daemon/error.h"
#include <QObject>

namespace Kiran
{
KADError::KADError()
{
}

QString KADError::getErrorDesc(KADErrorCode errorCode)
{
    QString errorDesc;
    switch (errorCode)
    {
    case KADErrorCode::ERROR_USER_IID_ALREADY_EXISTS:
        errorDesc = QObject::tr("Authentication ID already exists.");
        break;
    case KADErrorCode::ERROR_USER_ENROLLING:
        errorDesc = QObject::tr("The user is enrolling.");
        break;
    case ERROR_USER_FEATURE_LIMITS_EXCEEDED:
        errorDesc = QObject::tr("User Feature limits exceeded");
        break;
    case KADErrorCode::ERROR_SESSION_EXCEED_MAX_SESSION_NUM:
        errorDesc = QObject::tr("Too many sessions.");
        break;
    case KADErrorCode::ERROR_USER_IDENTIFIYING:
        errorDesc = QObject::tr("The session is in authentication.");
        break;
    case KADErrorCode::ERROR_FAILED:
        errorDesc = QObject::tr("Internel error.");
        break;
    case KADErrorCode::ERROR_NO_DEVICE:
        errorDesc = QObject::tr("No Such Device.");
        break;
    default:
        errorDesc = QObject::tr("Unknown error.");
        break;
    }

    errorDesc += QString::asprintf(QObject::tr(" (error code: 0x%x)").toStdString().c_str(), int32_t(errorCode));
    return errorDesc;
}

}  // namespace Kiran
