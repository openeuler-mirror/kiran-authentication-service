/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
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

#define AUTH_DEVICE_DBUS_NAME "com.kylinsec.Kiran.AuthDevice"
#define AUTH_DEVICE_DBUS_OBJECT_PATH "/com/kylinsec/Kiran/AuthDevice"
#define AUTH_DEVICE_DBUS_INTERFACE_NAME "com.kylinsec.Kiran.AuthDevice"

#define GENERAL_AUTH_DEVICE_DBUS_OBJECT_PATH "/com/kylinsec/Kiran/AuthDevice/Device"
#define GENERAL_AUTH_DEVICE_DBUS_INTERFACE_NAME "com.kylinsec.Kiran.AuthDevice.Device"

#define AUTH_DEVICE_JSON_KEY_UKEY "ukey"
#define AUTH_DEVICE_JSON_KEY_PIN "pin"
#define AUTH_DEVICE_JSON_KEY_SERIAL_NUMBER "serial_number"
#define AUTH_DEVICE_JSON_KEY_REBINDING "rebinding"
#define AUTH_DEVICE_JSON_KEY_FEATURE_IDS "feature_ids"

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

#define AUTH_TYPE_STR_PASSWORD "password"
#define AUTH_TYPE_STR_FINGERPRINT "fingerprint"
#define AUTH_TYPE_STR_FINGERVEIN "fingervein"
#define AUTH_TYPE_STR_FACE "face"
#define AUTH_TYPE_STR_IRIS "iris"
#define AUTH_TYPE_STR_UKEY "ukey"
#define AUTH_TYPE_STR_VIRTUAL_FACE "virtual face"
#define AUTH_TYPE_STR_VIRTUAL_CODE "virtual code"

/* ------------ 认证场景定义 ----------------- */
#define AUTH_APPLICATION_STR_LOGIN "login"
#define AUTH_APPLICATION_STR_UNLOCK "unlock"
#define AUTH_APPLICATION_STR_EMPOWERMENT "empowerment"

// PAM框架内通信协议
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

// 录入结果
enum EnrollStatus
{
    // 录入完成
    ENROLL_STATUS_COMPLETE,
    // 录入失败
    ENROLL_STATUS_FAIL,
    // 录入阶段性完成
    ENROLL_STATUS_PASS,
    // 因为扫描质量或者用户扫描过程中发生的问题引起
    ENROLL_STATUS_RETRY,
    // 重复录入同一特征
    ENROLL_STATUS_REPEATED,
    // 正常录入中，用来传递消息，不涉及状态改变
    ENROLL_STATUS_NORMAL
};

// 识别结果
enum IdentifyStatus
{
    // 认证失败
    IDENTIFY_STATUS_NOT_MATCH,
    // 认证成功
    IDENTIFY_STATUS_MATCH,
    // 因为扫描质量或者用户扫描过程中发生的问题导致认证不成功
    IDENTIFY_STATUS_RETRY,
    // 正常识别中，用来传递消息，不涉及状态改变
    IDENTIFY_STATUS_NORMAL
};

// 录入过程
enum EnrollProcess
{
    // 获取特征失败
    ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL,
    // 录入阶段性完成
    ENROLL_PROCESS_PASS,
    // 重复录入同一特征
    ENROLL_PROCESS_REPEATED_ENROLL,
    // 录入时前后录入的不是同一个特征（例如：不是同一根手指/同一个人脸）
    ENROLL_PROCESS_INCONSISTENT_FEATURE,
    // 特征融合失败
    ENROLL_PROCESS_MEGER_FAIL,
    // 录入成功
    ENROLL_PROCESS_SUCCESS,
    // 录入失败
    ENROLL_PROCESS_FAIL,
    // 特征保存失败
    ENROLL_PROCESS_SAVE_FAIL,
    // 合成后的指纹与先前录入的指纹不匹配
    ENROLL_PROCESS_INCONSISTENT_FEATURE_AFTER_MERGED,
};

enum IdentifyProcess
{
    // 验证超时
    IDENTIFY_PROCESS_TIME_OUT,
    // 获取特征失败
    IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL,
    // 匹配
    IDENTIFY_PROCESS_MACTCH,
    // 不匹配
    IDENTIFY_PROCESS_NO_MATCH,
    // PIN码不正确
    IDENTIFY_PROCESS_PIN_INCORRECT
};

// 设备类型
enum DeviceType
{
    DEVICE_TYPE_FingerPrint,          // 指纹
    DEVICE_TYPE_Face,                 // 人脸
    DEVICE_TYPE_FingerVein,           // 指静脉
    DEVICE_TYPE_Iris,                 // 虹膜
    DEVICE_TYPE_VoicePrint,           // 声纹
    DEVICE_TYPE_UKey,                 // ukey
                                      // ...预留，未来可能增加其他物理设备...
    DEVICE_TYPE_Virtual_Face = 1000,  // 虚拟人脸
    DEVICE_TYPE_Virtual_Code,         // 验证码
};

// 设备状态
enum DeviceStatusx
{
    DEVICE_STATUS_ERROR,           // 设备发生错误
    DEVICE_STATUS_BUSY,            // 设备忙碌
    DEVICE_STATUS_IDLE,            // 设备空闲
    DEVICE_STATUS_DOING_ENROLL,    // 设备正在录入中
    DEVICE_STATUS_DOING_IDENTIFY,  // 设备正在验证中
    DEVICE_STATUS_DISABLE,         // 设备被禁用
};

enum GeneralResult
{
    GENERAL_RESULT_UNSUPPORT = -1,        // 此接口不支持
    GENERAL_RESULT_OK = 0,                // 成功
    GENERAL_RESULT_FAIL = 1,              // 失败
    GENERAL_RESULT_TIMEOUT = 2,           // 超时
    GENERAL_RESULT_NO_FOUND_DEVICE = 3,   // 设备不存在
    GENERAL_RESULT_OPEN_DEVICE_FAIL = 4,  // 打开设备失败
};

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
    // 虹膜
    KAD_AUTH_TYPE_IRIS = (1 << 5),
    // 虚拟人脸
    KAD_AUTH_TYPE_VIRTUAL_FACE = (1 << 6),

    KAD_AUTH_TYPE_VIRTUAL_CODE = (1 << 7),
    KAD_AUTH_TYPE_LAST = (1 << 8),
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

struct DeviceInfo
{
    QString idVendor;
    QString idProduct;
    QString busPath;

    bool operator<(const DeviceInfo &dev) const
    {
        if (this->idVendor.compare(dev.idVendor) < 0)
            return true;
        else if (this->idVendor.compare(dev.idVendor) > 0)
            return false;

        if (this->idProduct.compare(dev.idProduct) < 0)
            return true;
        else if (this->idProduct.compare(dev.idProduct) > 0)
            return false;

        if (this->busPath.compare(dev.busPath) < 0)
            return true;
        else if (this->busPath.compare(dev.busPath) > 0)
            return false;

        return false;
    };

    bool operator==(const DeviceInfo &dev) const
    {
        if (this->idVendor == dev.idVendor &&
            this->idProduct == dev.idProduct)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
};
