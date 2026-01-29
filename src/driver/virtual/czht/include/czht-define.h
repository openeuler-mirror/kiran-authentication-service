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

#pragma once

#include <QMap>
#include <QString>

#define DBUS_INTERFACE "com.czht.face.daemon"
#define DBUS_PATH "/com/czht/face/daemon"
#define BUSINESS_ID "KylinsecOS"

/*
| 错误码 | 说明 | 可能的原因/场景 |
|--------|------|----------------|
| 0 | 成功 | 操作成功完成 |
| 1 | JSON 格式错误 | 输入的JSON字符串格式不正确 |
| 2 | 缺少必需的 JSON 字段 | 必填字段未提供 |
| 3 | 参数超出允许范围 | 参数值不在规定范围内 |
| 5 | 离线模式，操作失败 | 无法连接服务器，且本地无缓存 |
| 6 | 操作超时 | 任务执行超时 |
| 7 | 正在执行其他任务 | 同一 `business_id` 已在执行任务 |
| 8 | 任务未执行 | 尝试停止一个不存在的任务 |
| 9 | 无法连接 USB 摄像头 | 摄像头设备未连接或无法打开 |
| 10 | 源主机通信异常 | 远程主机（ZMQ）通信失败 |
| 11 | 启动监控进程失败 | 无法启动 `czht-sign` 进程 |
| 12 | 匹配人员未找到（离线模式） | 本地数据库中未找到匹配的人脸 |
| 13 | 用户已过期 | 绑定的用户账号已过期 |
| 14 | 用户不在缓存中 | 用户不在缓存中 |
| 101 | `server error` | 服务器内部错误，如算法服务异常 |
| 102 | `business_id is not found` | 业务ID不存在 |
| 103 | `no live` | 检测到非活体（活体检测失败） |
| 104 | `Face yaw too large` | 人脸偏航角度过大 |
| 105 | `match person is not found` | 未搜索到匹配的人员 |
| 106 | `person is delete` | 搜索到的人员已被删除 |
| 107 | `Authorization code is not found` | 授权码不存在 |
| 108 | `Authorization code expired` | 授权码已过期 |
| 109 | `person is not match` | 人脸与授权码绑定的人员不匹配 |
| 110 | `user_id is not found` | 授权验证user_id不存在 |
| 111 | `device_code is not found` | 授权验证device_code不存在 |
| 112 | `user_id device_code is not found` | 授权验证user_id与device_code关联绑定不存在 |

*/
enum CZHT_ERROR_NUM
{
    CZHT_SUCCESS = 0,
    CZHT_ERROR_JSON_FORMAT_ERROR = 1,
    CZHT_ERROR_MISSING_REQUIRED_FIELD = 2,
    CZHT_ERROR_PARAMETER_OUT_OF_RANGE = 3,
    // CZHT_ERROR_GENERATE_AUTHORIZATION_FAILED = 4,
    CZHT_ERROR_OFFLINE_MODE_FAILED = 5,
    CZHT_ERROR_OPERATION_TIMEOUT = 6,
    CZHT_ERROR_OTHER_TASK_EXECUTING = 7,
    CZHT_ERROR_TASK_NOT_EXECUTED = 8,
    CZHT_ERROR_CANNOT_CONNECT_USB_CAMERA = 9,
    CZHT_ERROR_HOST_COMMUNICATION_EXCEPTION = 10,
    CZHT_ERROR_START_MONITOR_PROCESS_FAILED = 11,
    CZHT_ERROR_MATCH_PERSON_NOT_FOUND_OFFLINE = 12,
    CZHT_ERROR_USER_EXPIRED = 13,
    CZHT_ERROR_USER_NOT_IN_CACHE = 14,
    CZHT_ERROR_SERVER_ERROR = 101,
    CZHT_ERROR_BUSINESS_ID_NOT_FOUND = 102,
    CZHT_ERROR_NO_LIVE_DETECTION = 103,
    CZHT_ERROR_FACE_YAW_TOO_LARGE = 104,
    CZHT_ERROR_MATCH_PERSON_NOT_FOUND = 105,
    CZHT_ERROR_PERSON_DELETED = 106,
    CZHT_ERROR_AUTHORIZATION_CODE_NOT_FOUND = 107,
    CZHT_ERROR_AUTHORIZATION_CODE_EXPIRED = 108,
    CZHT_ERROR_PERSON_NOT_MATCH_AUTHORIZATION_CODE = 109,
    CZHT_ERROR_USER_ID_NOT_FOUND = 110,
    CZHT_ERROR_DEVICE_CODE_NOT_FOUND = 111,
    CZHT_ERROR_USER_ID_DEVICE_CODE_NOT_FOUND = 112,
    CZHT_ERROR_DAEMON_NOT_RUNNING = 10000,
};

static const QString getCZHTErrorMsg(int errorNum)
{
    // 错误码对应的错误信息
    static const QMap<int, QString> CZHT_ERROR_MSG = {
        {CZHT_SUCCESS, QObject::tr("success")},
        {CZHT_ERROR_JSON_FORMAT_ERROR, QObject::tr("JSON format error")},
        {CZHT_ERROR_MISSING_REQUIRED_FIELD, QObject::tr("missing required JSON field")},
        {CZHT_ERROR_PARAMETER_OUT_OF_RANGE, QObject::tr("parameter out of range")},
        {CZHT_ERROR_OFFLINE_MODE_FAILED, QObject::tr("offline mode failed")},
        {CZHT_ERROR_OPERATION_TIMEOUT, QObject::tr("operation timeout")},
        {CZHT_ERROR_OTHER_TASK_EXECUTING, QObject::tr("other task executing")},
        {CZHT_ERROR_TASK_NOT_EXECUTED, QObject::tr("task not executed")},
        {CZHT_ERROR_CANNOT_CONNECT_USB_CAMERA, QObject::tr("cannot connect USB camera")},
        {CZHT_ERROR_HOST_COMMUNICATION_EXCEPTION, QObject::tr("host communication exception")},
        {CZHT_ERROR_START_MONITOR_PROCESS_FAILED, QObject::tr("start monitor process failed")},
        {CZHT_ERROR_MATCH_PERSON_NOT_FOUND_OFFLINE, QObject::tr("match person not found (offline mode)")},
        {CZHT_ERROR_USER_EXPIRED, QObject::tr("user expired")},
        {CZHT_ERROR_USER_NOT_IN_CACHE, QObject::tr("user not in cache")},
        {CZHT_ERROR_SERVER_ERROR, QObject::tr("server error")},
        {CZHT_ERROR_BUSINESS_ID_NOT_FOUND, QObject::tr("business ID not found")},
        {CZHT_ERROR_NO_LIVE_DETECTION, QObject::tr("no live detection")},
        {CZHT_ERROR_FACE_YAW_TOO_LARGE, QObject::tr("face yaw too large")},
        {CZHT_ERROR_MATCH_PERSON_NOT_FOUND, QObject::tr("match person not found")},
        {CZHT_ERROR_PERSON_DELETED, QObject::tr("person deleted")},
        {CZHT_ERROR_AUTHORIZATION_CODE_NOT_FOUND, QObject::tr("authorization code not found")},
        {CZHT_ERROR_AUTHORIZATION_CODE_EXPIRED, QObject::tr("authorization code expired")},
        {CZHT_ERROR_PERSON_NOT_MATCH_AUTHORIZATION_CODE, QObject::tr("person not match authorization code")},
        {CZHT_ERROR_USER_ID_NOT_FOUND, QObject::tr("user_id is not found")},
        {CZHT_ERROR_DEVICE_CODE_NOT_FOUND, QObject::tr("device_code is not found")},
        {CZHT_ERROR_USER_ID_DEVICE_CODE_NOT_FOUND, QObject::tr("user_id device_code is not found")},
        {CZHT_ERROR_DAEMON_NOT_RUNNING, QObject::tr("CZHT daemon not running")},
    };

    return CZHT_ERROR_MSG.value(errorNum);
}