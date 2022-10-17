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

#include <QMap>
#include <QSharedPointer>
#include "src/daemon/device/device-protocol.h"

namespace Kiran
{
// class DeviceRequestSource
// {
// public:
//     // 开始进入设备请求队列
//     virtual void start() = 0;
//     // 设备被其他receiver抢占
//     virtual void interrupt() = 0;
//     // 请求开始被执行
//     virtual void schedule() = 0;
//     // 结束设备操作
//     virtual void end() = 0;
//     // 调度优先级
//     virtual int32_t priority() = 0;
//     // 使用设备的上层应用的进程ID
//     virtual int64_t pid() = 0;
//     /* 如果receiver希望所有操作只针对与某个用户，则需要指定。例如指纹认证时，希望只识别A用户的指纹，
//        则需要指定为A用户，否则如果是B用户按下指纹且指纹合法，认证也会通过 */
//     virtual QString specifiedUser() = 0;
// };

class Login1SessionItem;

class DeviceRequestController : public QObject
{
    Q_OBJECT
public:
    struct DeviceRequestCombo
    {
        QSharedPointer<DeviceRequest> request;
        QSharedPointer<DeviceRequestTarget> target;
    };

    DeviceRequestController(QObject *parent = nullptr);
    virtual ~DeviceRequestController(){};

    // 将请求添加到队列
    void pushRequest(QSharedPointer<DeviceRequest> request,
                     QSharedPointer<DeviceRequestTarget> target);

    // 移除请求
    void removeRequest(int64_t requestID);
    // 中断当前请求
    void interruptRequest();
    // 当前请求完成
    void finishRequest();
    // 重新调度
    void schedule();
    // 获取当前正在处理的请求
    QSharedPointer<DeviceRequestCombo> getCurrentRequestCombo() { return this->m_currentRequestCombo; }

private:
    // 唤醒一个请求
    void wakeRequest(QSharedPointer<DeviceRequestCombo> request);
    // 生成一个唯一的请求ID
    int64_t generateRequestID();
    // 判断进程是否是活跃会话
    bool isActiveSession(uint32_t pid);

private Q_SLOTS:
    void onActiveSessionChanged(const Login1SessionItem &sessionItem);

private:
    QMap<int64_t, QSharedPointer<DeviceRequestCombo>> m_requestCombos;
    QSharedPointer<DeviceRequestCombo> m_currentRequestCombo;
};

}  // namespace  Kiran
