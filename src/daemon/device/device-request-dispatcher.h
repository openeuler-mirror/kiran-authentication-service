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
class DeviceRequestListener
{
public:
    virtual QString getListenerName() = 0;
    // 处理分发的请求
    virtual void process(QSharedPointer<DeviceRequest> request) = 0;
};

class DeviceRequestDispatcher : public QObject
{
    Q_OBJECT
public:
    DeviceRequestDispatcher();
    virtual ~DeviceRequestDispatcher(){};

    static QSharedPointer<DeviceRequestDispatcher> getDefault();

    // 注册请求监听器，用于处理请求
    bool registerListener(uint16_t majorReqType, QSharedPointer<DeviceRequestListener> processor);
    // 发送请求，让调度器进行调度，返回一个请求ID，这个请求ID可以用于请求的取消
    void deliveryRequest(QSharedPointer<DeviceRequest> request);

private:
    static QSharedPointer<DeviceRequestDispatcher> m_instance;
    QMap<uint16_t, QSharedPointer<DeviceRequestListener>> m_listeners;
    int64_t m_reqIDCount;
};

}  // namespace Kiran
