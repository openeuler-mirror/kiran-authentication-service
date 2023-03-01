/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-cc-daemon is licensed under Mulan PSL v2.
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

#ifdef __cplusplus
extern "C"
{
#endif

    /* ------------ 认证后端相关的定义 ----------------- */

#define KAD_MANAGER_DBUS_NAME "com.kylinsec.Kiran.Authentication"
#define KAD_MANAGER_DBUS_OBJECT_PATH "/com/kylinsec/Kiran/Authentication"
#define KAD_MANAGER_DBUS_INTERFACE_NAME "com.kylinsec.Kiran.Authentication"

// 认证会话ObjectPath前缀
#define KAD_SESSION_DBUS_OBJECT_PATH "/com/kylinsec/Kiran/Authentication/Session"
#define KAD_SESSION_DBUS_INTERFACE_NAME "com.kylinsec.Kiran.Authentication.Session"

// 认证用户ObjectPath前缀
#define KAD_USER_DBUS_OBJECT_PATH "/com/kylinsec/Kiran/Authentication/User"
#define KAD_USER_DBUS_INTERFACE_NAME "com.kylinsec.Kiran.Authentication.User"

// IJK: identification json key
#define KAD_IJK_KEY_IID "iid"
#define KAD_IJK_KEY_NAME "name"
#define KAD_IJK_KEY_DATA_ID "data_id"
#define KAD_IJK_KEY_PAM_SERVICE "pam_service"
#define KAD_IJK_KEY_PAM_ENABLED "pam_enabled"

#define KAD_AUTH_MODE_STR_AND "And"
#define KAD_AUTH_MODE_STR_OR "Or"

    // 认证模式
    enum KADAuthMode
    {
        // 无
        KAD_AUTH_MODE_NONE = 0,
        // 需要所有配置的认证类型都成功才能通过认证
        KAD_AUTH_MODE_AND = 1,
        // 只要其中一种认证类型成功则可以通过认证
        KAD_AUTH_MODE_OR = 2,
        KAD_AUTH_MODE_LAST,
    };

#define AUTH_TYPE_STR_FINGERPRINT "fingerprint"
#define AUTH_TYPE_STR_FACE "face"
#define AUTH_TYPE_STR_UKEY "uKey"
#define AUTH_TYPE_STR_FINGERVEIN "fingervein"

    // 认证类型
    enum KADAuthType
    {
        // 无/默认方式
        KAD_AUTH_TYPE_NONE = 0,
        // 密码认证,认证服务不参与密码认证
        KAD_AUTH_TYPE_PASSWORD = (1 << 0),
        // 指纹认证
        KAD_AUTH_TYPE_FINGERPRINT = (1 << 1),
        // 人脸
        KAD_AUTH_TYPE_FACE = (1 << 2),
        // UKEY
        KAD_AUTH_TYPE_UKEY = (1 << 3),
        // 指静脉认证
        KAD_AUTH_TYPE_FINGERVEIN = (1 << 4),
        KAD_AUTH_TYPE_LAST = (1 << 5),
    };

    // 认证提示消息类型，接收方需要响应消息
    enum KADPromptType
    {
        // 请求密文应答信息
        KAD_PROMPT_TYPE_QUESTION = 1,
        // 请求明文应答信息
        KAD_PROMPT_TYPE_SECRET,
    };

    // 认证显示消息类型
    enum KADMessageType
    {
        // 错误消息
        KAD_MESSAGE_TYPE_ERROR,
        // 提示信息
        KAD_MESSAGE_TYPE_INFO,
    };

    /* ------------ 认证场景定义 ----------------- */
#define AUTH_APPLICATION_STR_LOGIN "login"
#define AUTH_APPLICATION_STR_UNLOCK "unlock"
#define AUTH_APPLICATION_STR_EMPOWERMENT "empowerment"

    enum KADAuthApplication
    {
        KAD_AUTH_APPLICATION_NONE = 0,
        // 登录场景
        KAD_AUTH_APPLICATION_LOGIN,
        // 解锁场景
        KAD_AUTH_APPLICATION_UNLOCK,
        // 授权场景
        KAD_AUTH_APPLICATION_EMPOWERMENT,
        KAD_AUTH_APPLICATION_LAST
    };
    /* ------------ PAM相关的定义 ----------------- */

    enum KAPProtoID
    {
        // 告知应用程序当前的认证模式
        KAP_REQ_CMD_NOTIFY_AUTH_MODE = 0x10,
        // 向应用程序请求当前是否允许切换登录用户
        KAP_REQ_CMD_LOGIN_USER_SWITCHABLE = 0x20,
        // 告知应用程序当前可选的认证类型
        KAP_REQ_CMD_NOTIFY_SUPPORT_AUTH_TYPE = 0x30,
        // 向应用请求需要使用的认证类型（只有图形应用才会使用）
        KAP_REQ_CMD_AUTH_TYPE = 0x40,
        // 回应PAM_REQ_CMD_AUTH_TYPE消息
        KAP_RSP_CMD_AUTH_TYPE = 0x50,
        // 告知应用程序最终使用的认证类型
        KAP_REQ_CMD_NOTIFY_AUTH_TYPE = 0x60,
    };

// PJK: proto json key
// json消息的提示头
#define KAP_PROTO_JSON_PREFIX "kiran_authentication:"
#define KAP_PJK_KEY_HEAD "head"
// 请求或响应命令，请求应该以PAM_REQ_CMD开头，响应以PAM_RSP_CMD开头
#define KAP_PJK_KEY_CMD "cmd"
// 如果响应出错，可以携带错误消息
#define KAP_PJK_KEY_ERROR "error"
#define KAP_PJK_KEY_BODY "body"
#define KAP_PJK_KEY_AUTH_MODE "auth_mode"
#define KAP_PJK_KEY_LOGIN_USER_SWITCHABLE "login_user_switchable"
#define KAP_PJK_KEY_AUTH_TYPE "auth_type"
#define KAP_PJK_KEY_AUTH_TYPES "auth_types"

#ifdef __cplusplus
}
#endif
