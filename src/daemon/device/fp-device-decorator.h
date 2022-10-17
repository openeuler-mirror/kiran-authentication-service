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
#include "src/daemon/device/device-decorator.h"
#include "src/daemon/device/device-request-dispatcher.h"

class BiometricsProxy;
class FPDeviceProxy;

namespace Kiran
{
class DeviceRequestController;

/* 该装饰类主要是为了让一个指纹设备可以被多个会话和用户进行共享，
   所有指纹设备的操作都会放入到一个请求队列中，按照一定的调度策略响应请求 */
class FPDeviceDecorator : public DeviceDecorator,
                          public DeviceRequestListener
{
    Q_OBJECT
public:
    FPDeviceDecorator();
    virtual ~FPDeviceDecorator(){};

    class FPDeviceRequestTarget : public DeviceRequestTarget
    {
    public:
        FPDeviceRequestTarget(FPDeviceDecorator *fpDeviceDecorator) : m_fpDeviceDecorator(fpDeviceDecorator) {}
        // 开始进入设备请求队列
        virtual void start();
        // 设备被其他receiver抢占
        virtual void interrupt();
        // 请求开始被执行
        virtual void schedule();
        // 结束设备操作
        virtual void end();

        void setRequestStart(std::function<void(void)> requestStart) { this->m_requestStart = requestStart; }
        void setRequestStop(std::function<void(void)> requestStop) { this->m_requestStop = requestStop; }
        void setRequest(QSharedPointer<DeviceRequest> request) { this->m_request = request; }

    private:
        std::function<void(void)> m_requestStart;
        std::function<void(void)> m_requestStop;
        QSharedPointer<DeviceRequest> m_request;
        FPDeviceDecorator *m_fpDeviceDecorator;
    };

private:
    virtual QString getListenerName() { return QStringLiteral("FPDeviceDecorator"); };
    // 处理请求
    virtual void process(QSharedPointer<DeviceRequest> request);

    void initDevice();

    void enrollStart();
    void enrollStop();
    void verifyStart(const QString &bid);
    void verifyStop();
    void identifyStart(const QStringList &bids);
    void identifyStop();

private Q_SLOTS:
    void onFPDeviceIDChanged(const QString &fpDeviceID);
    void onEnrollStatus(const QString &bid, int result, int progress);
    void onVerifyStatus(int result);
    void onIdentifyStatus(const QString &bid, int result);

private:
    static QSharedPointer<FPDeviceDecorator> m_instance;
    DeviceRequestController *m_requestController;
    BiometricsProxy *m_biometricsProxy;
    FPDeviceProxy *m_fpDeviceProxy;
};

}  // namespace Kiran
