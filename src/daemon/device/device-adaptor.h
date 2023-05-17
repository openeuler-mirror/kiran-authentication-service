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
#include <QTime>
#include <functional>
#include "src/daemon/device/device-protocol.h"
#include "src/daemon/auth_device_proxy.h"

namespace Kiran
{
class DeviceRequestController;
struct Login1SessionItem;

/* 该装饰类主要是为了让一个指纹设备可以被多个会话和用户进行共享，
   所有指纹设备的操作都会放入到一个请求队列中，按照一定的调度策略响应请求 */
class DeviceAdaptor : public QObject
{
    Q_OBJECT
public:
    DeviceAdaptor(QSharedPointer<AuthDeviceProxy> dbusDeviceProxy);
    virtual ~DeviceAdaptor(){};

    QString getDeviceID() { return m_deviceID; }

    void enroll(DeviceRequestSource *source,const QString& extraInfo);
    void identify(DeviceRequestSource *source,const QString& extraInfo);
    void stop(int64_t requestID);

    // 取消/清空 所有的认证请求
    void removeAllRequest();

    // 更新设备代理
    void updateDBusDeviceProxy(QSharedPointer<AuthDeviceProxy> dbusDeviceProxy);

private:
    // 将请求添加到队列
    void pushRequest(QSharedPointer<DeviceRequest> request);
    // 唤醒一个请求
    void wakeRequest(QSharedPointer<DeviceRequest> request);
    // 取消该请求，并从队列中移出
    void removeRequest(int64_t requestID);
    // 中断当前请求
    void interruptRequest();
    // 当前请求完成
    void finishRequest();
    // 重新调度
    void schedule();

    // 生成一个唯一的请求ID
    int64_t generateRequestID();

    void enrollStart(const QString& extraInfo);
    void enrollStop();
    void identifyStart(const QString& extraInfo);
    void identifyStop();

    // 判断进程是否是活跃会话
    bool isActiveSession(uint32_t pid);
    void startDeviceOccupyTimer(int ms);
    void stopDeviceOccupyTimer();

private Q_SLOTS:
    void onEnrollStatus(const QString &featureID, int result, int progress,const QString& message);
    void onIdentifyStatus(const QString &featureID, int result,const QString& message);
    void onActiveSessionChanged(const Login1SessionItem &sessionItem);
    void onDeviceOccupyTimeout();

private:
    QSharedPointer<AuthDeviceProxy> m_dbusDeviceProxy;
    QMap<int64_t, QSharedPointer<DeviceRequest>> m_requests;
    QSharedPointer<DeviceRequest> m_currentRequest;
    int64_t m_requestIDCount;
    QString m_deviceID;
    QTimer m_deviceOccupyTimer;
};

}  // namespace Kiran
