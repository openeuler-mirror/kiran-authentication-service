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

#include <QString>

namespace Kiran
{
#define KAD_ERROR2STR(errorCode) KADError::getErrorDesc(errorCode)

#define DBUS_ERROR_REPLY(type, errorCode, ...)                                                        \
    {                                                                                                 \
        auto errMessage = QString::asprintf(KAD_ERROR2STR(errorCode).toUtf8().data(), ##__VA_ARGS__); \
        sendErrorReply(type, errMessage);                                                             \
    }

#define DBUS_ERROR_REPLY_AND_RET(type, errorCode, ...) \
    DBUS_ERROR_REPLY(type, errorCode, ##__VA_ARGS__);  \
    return;

#define DBUS_ERROR_REPLY_WITH_RET(retval, type, errorCode, ...) \
    DBUS_ERROR_REPLY(type, errorCode, ##__VA_ARGS__);           \
    return retval;

#define DBUS_ERROR_REPLY_ASYNC(message, type, errorCode, ...)                                         \
    {                                                                                                 \
        auto errMessage = QString::asprintf(KAD_ERROR2STR(errorCode).toUtf8().data(), ##__VA_ARGS__); \
        auto replyMessage = message.createErrorReply(type, errMessage);                               \
        QDBusConnection::systemBus().send(replyMessage);                                              \
    }

#define DBUS_ERROR_REPLY_ASYNC_AND_RET(message, type, errorCode, ...) \
    DBUS_ERROR_REPLY_ASYNC(message, type, errorCode, ##__VA_ARGS__);  \
    return;

enum KADErrorCode
{
    // Common
    SUCCESS,
    ERROR_FAILED,
    ERROR_INVALID_ARGUMENT,
    
    // User
    ERROR_USER_IID_ALREADY_EXISTS = 0x10000,
    // 正在录入中
    ERROR_USER_ENROLLING,
    // 不存在该类型设备
    ERROR_NO_DEVICE,

    // Session
    ERROR_SESSION_EXCEED_MAX_SESSION_NUM = 0x20000,
    // 正在认证中
    ERROR_USER_IDENTIFIYING,

};

class KADError
{
public:
    KADError();
    virtual ~KADError(){};

    static QString getErrorDesc(KADErrorCode errorCode);
};

}  // namespace Kiran