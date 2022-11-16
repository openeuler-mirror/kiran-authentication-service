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
#include "src/daemon/device_proxy.h"

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
    DeviceAdaptor(QSharedPointer<DeviceProxy> dbusDeviceProxy);
    virtual ~DeviceAdaptor(){};

    QString getDeviceID() { return this->m_dbusDeviceProxy->deviceID(); }

    void enroll(DeviceRequestSource *source);
    void verify(DeviceRequestSource *source);
    void identify(DeviceRequestSource *source);
    void stop(int64_t requestID);

    void updateDBusDeviceProxy(QSharedPointer<DeviceProxy> dbusDeviceProxy);

private:
    // 将请求添加到队列
    void pushRequest(QSharedPointer<DeviceRequest> request);
    // 唤醒一个请求
    void wakeRequest(QSharedPointer<DeviceRequest> request);
    // 移除请求
    void removeRequest(int64_t requestID);
    // 中断当前请求
    void interruptRequest();
    // 当前请求完成
    void finishRequest();
    // 重新调度
    void schedule();

    // 生成一个唯一的请求ID
    int64_t generateRequestID();

    void enrollStart();
    void enrollStop();
    void verifyStart(const QString &bid);
    void verifyStop();
    void identifyStart(const QStringList &bids);
    void identifyStop();

    // 判断进程是否是活跃会话
    bool isActiveSession(uint32_t pid);

private Q_SLOTS:
    void onEnrollStatus(const QString &bid, int result, int progress);
    void onVerifyStatus(int result);
    void onIdentifyStatus(const QString &bid, int result);
    void onActiveSessionChanged(const Login1SessionItem &sessionItem);

private:
    static QSharedPointer<DeviceAdaptor> m_instance;
    QSharedPointer<DeviceProxy> m_dbusDeviceProxy;
    QMap<int64_t, QSharedPointer<DeviceRequest>> m_requests;
    QSharedPointer<DeviceRequest> m_currentRequest;
    int64_t m_requestIDCount;
};

}  // namespace Kiran
