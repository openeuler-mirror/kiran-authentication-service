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

#include <functional>
#include <QSharedPointer>
#include <QTime>
#include <QVariantMap>

#include "lib/feature-data.h"

namespace Kiran
{
struct DeviceEvent;

/** @brief 从请求类型中提取主类型（高 16 位） */
#define MAJOR_REQUEST_TYPE(reqType) ((reqType >> 16) & 0xffff)

/** @brief 从请求类型中提取次类型（低 16 位） */
#define MINOR_REQUEST_TYPE(reqType) ((reqType) & 0xffff)

/**
 * @brief 设备请求调度优先级
 */
enum DeviceRequestPriority
{
    /** 低优先级 */
    DEVICE_REQUEST_PRIORITY_LOW = 5,
    /** 普通优先级 */
    DEVICE_REQUEST_PRIORITY_NORMAL = 10,
    /** 高优先级 */
    DEVICE_REQUEST_PRIORITY_HIGH = 20,
};

/**
 * @brief 设备请求类型
 *
 * 主类型由高 16 位区段标识设备类别（指纹/人脸等），
 * 次类型由低 16 位标识具体操作（录入开始/停止、认证开始/停止等）。
 */
enum DeviceRequestType
{
    /** 无操作 */
    DEVICE_REQUEST_TYPE_NONE = 0,

    // ---------- 指纹设备（0x0001xxxx）----------
    /** 指纹请求区段起始 */
    DEVICE_REQUEST_TYPE_FP_START = 0x00010000,
    /** 指纹录入开始 */
    DEVICE_REQUEST_TYPE_FP_ENROLL_START,
    /** 指纹录入停止 */
    DEVICE_REQUEST_TYPE_FP_ENROLL_STOP,
    /** 指纹验证开始 */
    DEVICE_REQUEST_TYPE_FP_VERIFY_START,
    /** 指纹验证停止 */
    DEVICE_REQUEST_TYPE_FP_VERIFY_STOP,
    /** 指纹识别开始 */
    DEVICE_REQUEST_TYPE_FP_IDENTIFY_START,
    /** 指纹识别停止 */
    DEVICE_REQUEST_TYPE_FP_IDENTIFY_STOP,
    /** 指纹请求区段结束 */
    DEVICE_REQUEST_TYPE_FP_END = 0x0001FFFF,

    // ---------- 人脸设备（0x0002xxxx）----------
    /** 人脸请求区段起始 */
    DEVICE_REQUEST_TYPE_FACE_START = 0x00020000,
    /** 人脸请求区段结束 */
    DEVICE_REQUEST_TYPE_FACE_END = 0x0002FFFF,
};

struct DeviceRequest;
class DeviceRequestSource
{
public:
    /**
     * @brief 获取调度优先级
     * @return 优先级数值，值越大优先级越高
     */
    virtual int32_t getPriority() = 0;

    /**
     * @brief 获取请求来源进程的 PID
     * @return 进程 ID
     */
    virtual int64_t getPID() = 0;

    /**
     * @brief 获取需要限定的目标用户
     *
     * 如果 source 希望所有操作只针对某个用户，则需要指定。
     * 例如指纹认证时，希望只识别 A 用户的指纹，则返回 A 用户名；
     * 否则若 B 用户按下指纹且合法，认证也会通过。
     *
     * @return 目标用户名，空字符串表示不限定
     */
    virtual QString getSpecifiedUser() = 0;

    /**
     * @brief 回调：请求已进入调度队列
     * @param request 已入队的请求对象
     */
    virtual void queued(QSharedPointer<DeviceRequest> request) = 0;

    /**
     * @brief 回调：操作被中断
     *
     * 可能由更高优先级请求抢占或设备不可用等原因导致。
     * 任务仍保留在调度队列中。
     */
    virtual void interrupt() = 0;

    /**
     * @brief 回调：操作被取消
     *
     * 可能由切换会话等原因导致。取消时应返回错误，
     * 但不应记录为认证失败。任务将被移出队列。
     */
    virtual void cancel() = 0;

    /**
     * @brief 回调：操作结束，任务已从队列中移除
     */
    virtual void end() = 0;

    /**
     * @brief 回调：录入状态变化
     * @param data 特征数据（JSON 格式）
     * @param progress 进度百分比（0-100）
     * @param result 录入结果，参见 EnrollStatus 枚举
     * @param message 提示消息
     */
    virtual void onEnrollStatus(const QString &data, int progress, int result, const QString &message) = 0;

    /**
     * @brief 回调：认证（识别）状态变化
     * @param bid 特征 ID
     * @param result 识别结果，参见 IdentifyStatus 枚举
     * @param message 提示消息
     */
    virtual void onIdentifyStatus(const QString &bid, int result, const QString &message) = 0;
};

struct DeviceRequest
{
    /** 请求 ID（全局唯一） */
    int64_t reqID;
    /** 请求发起时间 */
    QTime time;
    /** 请求来源（Session 或 User） */
    DeviceRequestSource *source;
    /** 启动回调 */
    std::function<void(void)> start;
    /** 停止回调 */
    std::function<void(void)> stop;
};

/** D-Bus 请求参数键：特征 ID */
#define DEVICE_REQUEST_ARGS_BID "bid"
/** D-Bus 请求参数键：特征 ID 列表 */
#define DEVICE_REQUEST_ARGS_BIDS "bids"
/** D-Bus 请求参数键：请求 ID */
#define DEVICE_REQUEST_ARGS_REQUEST_ID "request_id"

class DeviceRequestTarget
{
public:
    /**
     * @brief 开始进入设备请求队列
     */
    virtual void start() = 0;

    /**
     * @brief 设备被其他 receiver 抢占
     */
    virtual void interrupt() = 0;

    /**
     * @brief 请求开始被执行
     */
    virtual void schedule() = 0;

    /**
     * @brief 结束设备操作
     */
    virtual void end() = 0;
};

}  // namespace Kiran
