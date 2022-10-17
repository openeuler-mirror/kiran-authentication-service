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

#include "src/daemon/device/device-request-dispatcher.h"
#include <auxiliary.h>
#include <qt5-log-i.h>
#include <climits>

namespace Kiran
{
DeviceRequestDispatcher::DeviceRequestDispatcher() : m_reqIDCount(0)
{
}

QSharedPointer<DeviceRequestDispatcher> DeviceRequestDispatcher::m_instance = nullptr;
QSharedPointer<DeviceRequestDispatcher> DeviceRequestDispatcher::getDefault()
{
    if (!m_instance)
    {
        m_instance = QSharedPointer<DeviceRequestDispatcher>::create();
    }
    return m_instance;
}

bool DeviceRequestDispatcher::registerListener(uint16_t majorReqType,
                                               QSharedPointer<DeviceRequestListener> processor)
{
    if (this->m_listeners.contains(majorReqType))
    {
        KLOG_WARNING("The majorReqType is already registered.");
        return false;
    }
    this->m_listeners.insert(majorReqType, processor);
    return true;
}

void DeviceRequestDispatcher::deliveryRequest(QSharedPointer<DeviceRequest> request)
{
    RETURN_IF_FALSE(request);

    if (this->m_reqIDCount >= LLONG_MAX)
    {
        this->m_reqIDCount = 0;
    }
    request->reqID = ++this->m_reqIDCount;

    auto majorReqType = MAJOR_REQUEST_TYPE(request->reqType);
    auto processor = this->m_listeners.value(majorReqType);
    if (processor)
    {
        KLOG_DEBUG() << "delivery request(reqID: "
                     << request->reqID
                     << ", reqType: "
                     << request->reqType
                     << ") to listener "
                     << processor->getListenerName();
        processor->process(request);
    }
    else
    {
        KLOG_DEBUG() << "Not found listners for reqType " << request->reqType;
    }
}
}  // namespace Kiran
