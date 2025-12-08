#pragma once

#include <QMap>
#include <QString>

// TODO: 需要诚志海图提供一份错误码信息
/*
1 JSON格式错误
2 缺少必需的JSON字段
3 参数范围超过限制
4 生成授权失败
5 授权验证失败
6 后端处理超时
7 正在执行其他任务
8 任务未执行
9 无法连接USB摄像头
10 主机通信异常
*/
enum CZHT_ERROR_NUM
{
    CZHT_SUCCESS = 0,
    CZHT_ERROR_JSON_FORMAT_ERROR = 1,
    CZHT_ERROR_MISSING_REQUIRED_FIELD = 2,
    CZHT_ERROR_PARAMETER_OUT_OF_RANGE = 3,
    CZHT_ERROR_GENERATE_AUTHORIZATION_FAILED = 4,
    CZHT_ERROR_AUTHORIZATION_VERIFICATION_FAILED = 5,
    CZHT_ERROR_BACKEND_PROCESS_TIMEOUT = 6,
    CZHT_ERROR_OTHER_TASK_EXECUTING = 7,
    CZHT_ERROR_TASK_NOT_EXECUTED = 8,
    CZHT_ERROR_CANNOT_CONNECT_USB_CAMERA = 9,
    CZHT_ERROR_HOST_COMMUNICATION_EXCEPTION = 10,
    CZHT_ERROR_USER_NOT_MATCH = 11,
};

static const QString getCZHTErrorMsg(int errorNum)
{
    // 错误码对应的错误信息
    static const QMap<int, QString> CZHT_ERROR_MSG = {
        {CZHT_SUCCESS, "成功"},
        {CZHT_ERROR_JSON_FORMAT_ERROR, "JSON格式错误"},
        {CZHT_ERROR_MISSING_REQUIRED_FIELD, "缺少必需的JSON字段"},
        {CZHT_ERROR_PARAMETER_OUT_OF_RANGE, "参数范围超过限制"},
        {CZHT_ERROR_GENERATE_AUTHORIZATION_FAILED, "生成授权失败"},
        {CZHT_ERROR_AUTHORIZATION_VERIFICATION_FAILED, "授权验证失败"},
        {CZHT_ERROR_BACKEND_PROCESS_TIMEOUT, "后端处理超时"},
        {CZHT_ERROR_OTHER_TASK_EXECUTING, "正在执行其他任务"},
        {CZHT_ERROR_TASK_NOT_EXECUTED, "任务未执行"},
        {CZHT_ERROR_CANNOT_CONNECT_USB_CAMERA, "无法连接USB摄像头"},
        {CZHT_ERROR_HOST_COMMUNICATION_EXCEPTION, "主机通信异常"},
        {CZHT_ERROR_USER_NOT_MATCH, "用户无权限操作设备，请申请授权码"},
    };

    return CZHT_ERROR_MSG.value(errorNum);
}