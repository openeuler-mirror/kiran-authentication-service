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
 * Author:     licheng <licheng@kylinsec.com.cn>
 */

#pragma once

#include <QMap>
#include <QString>

/** kiran-face-dbus-service 的 D-Bus 接口名 */
#define KIRAN_DBUS_INTERFACE "com.kiran.face.service"
/** kiran-face-dbus-service 的 D-Bus 对象路径 */
#define KIRAN_DBUS_PATH "/com/kiran/face/service"
/** 业务标识（复用 czht 中 BUSINESS_ID） */
#define KIRAN_BUSINESS_ID "KylinsecOS"

// 配置文件字段名
#define KIRAN_CONFIG_KEY_SEARCH_TIME_OUT "search_time_out"
#define KIRAN_CONFIG_KEY_DETECT_TIME_OUT "detect_time_out"
#define KIRAN_CONFIG_KEY_ENABLE_SCREEN_RECORDER "enable_screen_recorder"

enum KIRAN_ERROR_NUM
{
    KIRAN_SUCCESS = 0,                                                              /**< 成功 */
    KIRAN_ERROR_JSON_FORMAT_ERROR = 1,                                              /**< JSON 格式错误 */
    KIRAN_ERROR_MISSING_REQUIRED_FIELD = 2,                                         /**< 缺少必需的 JSON 字段 */
    KIRAN_ERROR_PARAMETER_OUT_OF_RANGE = 3,                                         /**< 参数超出允许范围 */
    KIRAN_ERROR_SERVER_RETURN_ERROR = 4,                                            /**< 服务器返回错误信息 */
    KIRAN_ERROR_OFFLINE_MODE_NOT_ALLOWED = 5,                                       /**< 离线模式不允许执行授权码操作 */
    KIRAN_ERROR_REPORT_LOGIN_LOG_FAILED = 6,                                        /**< 记录登录日志失败 */
    KIRAN_ERROR_OTHER_TASK_EXECUTING = 7,                                           /**< 同一 business_id 已在执行任务 */
    KIRAN_ERROR_TASK_NOT_EXECUTED = 8,                                              /**< 任务未执行 */
    KIRAN_ERROR_CANNOT_CONNECT_USB_CAMERA = 9,                                      /**< 摄像头设备未连接或无法打开 */
    KIRAN_ERROR_START_MONITOR_PROCESS_FAILED = 11,                                  /**< 无法启动 leave-detecter 进程（离开检测） */
    KIRAN_ERROR_MATCH_PERSON_NOT_FOUND_OFFLINE = 12,                                /**< 本地数据库中未找到匹配的人脸 */
    KIRAN_ERROR_USER_EXPIRED = 13,                                                  /**< 绑定的用户账号已过期 */
    KIRAN_ERROR_USER_NOT_IN_CACHE = 14,                                             /**< 用户不在缓存中，无法开始离开检测 */
    KIRAN_ERROR_WORK_MODE_NOT_SUPPORTED = 15,                                       /**< 当前工作模式不支持授权码操作 */
    KIRAN_ERROR_SERVER_INTERNAL_ERROR = 101,                                        /**< 服务器内部错误，如算法服务异常 */
    KIRAN_ERROR_BUSINESS_ID_NOT_FOUND = 102,                                        /**< business_id 不存在 */
    KIRAN_ERROR_FACE_NOT_DETECTED = 104,                                            /**< 未检测到人脸 */
    KIRAN_ERROR_MATCH_PERSON_NOT_FOUND = 105,                                       /**< 未搜索到匹配的人员 */
    KIRAN_ERROR_PERSON_DELETED = 106,                                               /**< 搜索到的人员已被删除 */
    KIRAN_ERROR_AUTHORIZATION_CODE_NOT_FOUND = 107,                                 /**< 授权码不存在 */
    KIRAN_ERROR_AUTHORIZATION_CODE_EXPIRED = 108,                                   /**< 授权码已过期 */
    KIRAN_ERROR_PERSON_NOT_MATCH_AUTHORIZATION_CODE = 109,                          /**< 人脸与授权码绑定的人员不匹配 */
    KIRAN_ERROR_AUTHORIZATION_VERIFICATION_USER_ID_NOT_FOUND = 110,                 /**< 授权验证 user_id 不存在 */
    KIRAN_ERROR_AUTHORIZATION_VERIFICATION_DEVICE_CODE_NOT_FOUND = 111,             /**< 授权验证 device_code 不存在 */
    KIRAN_ERROR_AUTHORIZATION_VERIFICATION_BINDING_NOT_FOUND = 112,                 /**< 授权验证 user_id 与 device_code 关联绑定不存在 */
    KIRAN_ERROR_NO_LOGIN_PERMISSION = 10001,                                         /**< 无登录权限 */
    KIRAN_ERROR_NO_FACE_BINDING_RELATION = 10002,                                    /**< 未查询到人脸绑定关系 */
};

/** kiran 工作模式位标志，与 kiran-face-dbus-service 的 KiranWorkMode 一致 */
enum KiranWorkMode
{
    KIRAN_WORK_MODE_FACE     = 1 << 0,  /**< 人脸（F） */
    KIRAN_WORK_MODE_PASSWORD = 1 << 1,  /**< 密码（P） */
    KIRAN_WORK_MODE_SMS      = 1 << 2,  /**< 短信验证码（S） */
    KIRAN_WORK_MODE_CODE     = 1 << 3,  /**< 临时授权码（C） */
};

static const QString getKiranErrorMsg(int errorNum)
{
    static const QMap<int, QString> KIRAN_ERROR_MSG = {
        {KIRAN_SUCCESS, QObject::tr("success")},
        {KIRAN_ERROR_JSON_FORMAT_ERROR, QObject::tr("JSON format error")},
        {KIRAN_ERROR_MISSING_REQUIRED_FIELD, QObject::tr("missing required JSON field")},
        {KIRAN_ERROR_PARAMETER_OUT_OF_RANGE, QObject::tr("parameter out of range")},
        {KIRAN_ERROR_SERVER_RETURN_ERROR, QObject::tr("server return error")},
        {KIRAN_ERROR_OFFLINE_MODE_NOT_ALLOWED, QObject::tr("offline mode not allowed")},
        {KIRAN_ERROR_REPORT_LOGIN_LOG_FAILED, QObject::tr("report login log failed")},
        {KIRAN_ERROR_OTHER_TASK_EXECUTING, QObject::tr("other task executing")},
        {KIRAN_ERROR_TASK_NOT_EXECUTED, QObject::tr("task not executed")},
        {KIRAN_ERROR_CANNOT_CONNECT_USB_CAMERA, QObject::tr("cannot connect USB camera")},
        {KIRAN_ERROR_START_MONITOR_PROCESS_FAILED, QObject::tr("start monitor process failed (leave detection)")},
        {KIRAN_ERROR_MATCH_PERSON_NOT_FOUND_OFFLINE, QObject::tr("match person not found (offline mode)")},
        {KIRAN_ERROR_USER_EXPIRED, QObject::tr("user expired (not within valid time range)")},
        {KIRAN_ERROR_USER_NOT_IN_CACHE, QObject::tr("user not in cache, cannot start leave detection")},
        {KIRAN_ERROR_WORK_MODE_NOT_SUPPORTED, QObject::tr("work mode not supported")},
        {KIRAN_ERROR_SERVER_INTERNAL_ERROR, QObject::tr("server internal error, such as algorithm service exception")},
        {KIRAN_ERROR_BUSINESS_ID_NOT_FOUND, QObject::tr("business ID not found")},
        {KIRAN_ERROR_FACE_NOT_DETECTED, QObject::tr("face not detected")},
        {KIRAN_ERROR_MATCH_PERSON_NOT_FOUND, QObject::tr("match person not found")},
        {KIRAN_ERROR_PERSON_DELETED, QObject::tr("person deleted")},
        {KIRAN_ERROR_AUTHORIZATION_CODE_NOT_FOUND, QObject::tr("authorization code not found")},
        {KIRAN_ERROR_AUTHORIZATION_CODE_EXPIRED, QObject::tr("authorization code expired")},
        {KIRAN_ERROR_PERSON_NOT_MATCH_AUTHORIZATION_CODE, QObject::tr("person not match authorization code")},
        {KIRAN_ERROR_AUTHORIZATION_VERIFICATION_USER_ID_NOT_FOUND, QObject::tr("authorization verification user_id not found")},
        {KIRAN_ERROR_AUTHORIZATION_VERIFICATION_DEVICE_CODE_NOT_FOUND, QObject::tr("authorization verification device_code not found")},
        {KIRAN_ERROR_AUTHORIZATION_VERIFICATION_BINDING_NOT_FOUND, QObject::tr("authorization verification user_id device_code binding not found")},
        {KIRAN_ERROR_NO_LOGIN_PERMISSION, QObject::tr("no login permission")},
        {KIRAN_ERROR_NO_FACE_BINDING_RELATION, QObject::tr("no face binding relation")},
    };

    return KIRAN_ERROR_MSG.value(errorNum);
}
