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

#include <QSharedPointer>
#include <QTime>
#include <QVariantMap>

namespace Kiran
{
struct DeviceEvent;

#define MAJOR_REQUEST_TYPE(reqType) ((reqType >> 16) & 0xffff)
#define MINOR_REQUEST_TYPE(reqType) (reqType 0xffff)

enum DeviceRequestPriority
{
    DEVICE_REQUEST_PRIORITY_LOW = 5,
    DEVICE_REQUEST_PRIORITY_NORMAL = 10,
    DEVICE_REQUEST_PRIORITY_HIGH = 20,
};

enum DeviceRequestType
{
    DEVICE_REQUEST_TYPE_NONE = 0,
    // FingerPrint Device
    DEVICE_REQUEST_TYPE_FP_START = 0x00010000,
    // 录入指纹请求
    DEVICE_REQUEST_TYPE_FP_ENROLL_START,
    DEVICE_REQUEST_TYPE_FP_ENROLL_STOP,
    // 认证指纹请求
    DEVICE_REQUEST_TYPE_FP_VERIFY_START,
    DEVICE_REQUEST_TYPE_FP_VERIFY_STOP,
    DEVICE_REQUEST_TYPE_FP_IDENTIFY_START,
    DEVICE_REQUEST_TYPE_FP_IDENTIFY_STOP,
    DEVICE_REQUEST_TYPE_FP_END = 0x0001FFFF,

    // Face Device
    DEVICE_REQUEST_TYPE_FACE_START = 0x00020000,
    DEVICE_REQUEST_TYPE_FACE_END = 0x0002FFFF,
};

struct DeviceRequest;
class DeviceRequestSource
{
public:
    // 调度优先级
    virtual int32_t getPriority() = 0;
    // 使用设备的上层应用的进程ID
    virtual int64_t getPID() = 0;
    /* 如果source希望所有操作只针对与某个用户，则需要指定。例如指纹认证时，希望只识别A用户的指纹，
       则需要指定为A用户，否则如果是B用户按下指纹且指纹合法，认证也会通过 */
    virtual QString getSpecifiedUser() = 0;

    // 已经加入请求队列
    virtual void start(QSharedPointer<DeviceRequest> request) = 0;
    // 操作被中断，可能是有更高优先级的请求或者设备不可用等原因导致。任务还在处理队列中
    virtual void interrupt() = 0;
    // 操作被取消, 可能是切换会话或其他原因导致，操作被取消应返回错误，但不应记录失败，任务将会被删除
    virtual void cancel() = 0;
    // 结束操作，任务队列中该任务已处理完成
    virtual void end() = 0;
    // 录入状态
    virtual void onEnrollStatus(const QString &bid, int progress, int result,const QString& message) = 0;
    // 认证状态
    virtual void onIdentifyStatus(const QString &bid, int result,const QString& message) = 0;
};

struct DeviceRequest
{
    // 请求ID
    int64_t reqID;
    // 请求时间
    QTime time;
    // 请求源
    DeviceRequestSource *source;
    // 开始请求
    std::function<void(void)> start;
    // 停止请求
    std::function<void(void)> stop;
};

#define DEVICE_REQUEST_ARGS_BID "bid"
#define DEVICE_REQUEST_ARGS_BIDS "bids"
#define DEVICE_REQUEST_ARGS_REQUEST_ID "request_id"

class DeviceRequestTarget
{
public:
    // 开始进入设备请求队列
    virtual void start() = 0;
    // 设备被其他receiver抢占
    virtual void interrupt() = 0;
    // 请求开始被执行
    virtual void schedule() = 0;
    // 结束设备操作
    virtual void end() = 0;
};

// enum DeviceEventType
// {
//     // Common
//     // 请求已经进入被设备接受
//     DEVICE_EVENT_TYPE_START = 1,
//     // 请求被中断
//     DEVICE_EVENT_TYPE_INTERRUPT,
//     // 请求结束
//     DEVICE_EVENT_TYPE_END,
//     // FingerPrint Device
//     DEVICE_EVENT_TYPE_FP_START = 0x00010000,
//     DEVICE_EVENT_TYPE_FP_ENROLL_STATUS,
//     DEVICE_EVENT_TYPE_FP_VERIFY_STATUS,
//     DEVICE_EVENT_TYPE_FP_IDENTIFY_STATUS,
//     DEVICE_EVENT_TYPE_FP_END = 0x0001FFFF,

//     // Face Device
//     DEVICE_EVENT_TYPE_FACE_START = 0x00020000,
//     DEVICE_EVENT_TYPE_FACE_END = 0x0002FFFF,
// };

// #define DEVICE_EVENT_ARGS_BID "bid"
// #define DEVICE_EVENT_ARGS_RESULT "result"
// #define DEVICE_EVENT_ARGS_PROGRESS "progress"

// struct DeviceEvent
// {
//     // 请求类型：主类型(2字节）+次类型（2字节）
//     int32_t eventType;
//     // 事件绑定的请求
//     QSharedPointer<DeviceRequest> request;
//     // 携带的数据
//     QVariantMap args;
// };

}  // namespace Kiran