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

#include "src/daemon/device/device-request-controller.h"
#include <auxiliary.h>
#include "src/daemon/proxy/login1-manager-proxy.h"
#include "src/daemon/proxy/login1-seat-proxy.h"
#include "src/daemon/proxy/login1-session-proxy.h"

namespace Kiran
{
DeviceRequestController::DeviceRequestController(QObject *parent) : QObject(parent),
                                                                    m_currentRequestCombo(nullptr)
{
    auto defaultSeat = Login1SeatProxy::getDefault();
    connect(defaultSeat.get(), SIGNAL(activeSessionChanged(const Login1SessionItem &)), this, SLOT(onActiveSessionChanged(const Login1SessionItem &)));
}

void DeviceRequestController::pushRequest(QSharedPointer<DeviceRequest> request,
                                          QSharedPointer<DeviceRequestTarget> target)
{
    // TODO:需要判断请求ID是否存在
    auto requestCombo = QSharedPointer<DeviceRequestCombo>::create(DeviceRequestCombo{.request = request, .target = target});
    this->m_requestCombos.insert(request->reqID, requestCombo);

    // 如果当前插入的请求优先级比正在执行请求的优先级高，则进行抢占
    auto pushPriority = request->source->getPriority();
    if (!this->m_currentRequestCombo ||
        (pushPriority > this->m_currentRequestCombo->request->source->getPriority()))
    {
        this->wakeRequest(requestCombo);
    }
}

void DeviceRequestController::removeRequest(int64_t requestID)
{
    auto requestCombo = this->m_requestCombos.value(requestID, nullptr);
    RETURN_IF_FALSE(requestCombo);

    if (requestID == this->m_currentRequestCombo->request->reqID)
    {
        this->interruptRequest();
    }

    requestCombo->target->end();
    this->m_requestCombos.remove(requestID);

    if (!this->m_currentRequestCombo && this->m_requestCombos.size() > 0)
    {
        this->schedule();
    }
}

void DeviceRequestController::interruptRequest()
{
    if (this->m_currentRequestCombo)
    {
        this->m_currentRequestCombo->target->interrupt();
        this->m_currentRequestCombo = nullptr;
    }
}

void DeviceRequestController::finishRequest()
{
    if (this->m_currentRequestCombo)
    {
        // this->m_currentRequest->receiver->event(Event{
        //     .base = EventBase{.type = EventType::EVENT_TYPE_END}});
        this->m_currentRequestCombo->target->end();
        this->m_requestCombos.remove(this->m_currentRequestCombo->request->reqID);
        this->m_currentRequestCombo = nullptr;
    }
    this->schedule();
}

void DeviceRequestController::schedule()
{
    RETURN_IF_TRUE(this->m_requestCombos.size() == 0);

    QSharedPointer<DeviceRequestCombo> newRequestComb;

    for (auto &requestCombo : this->m_requestCombos)
    {
        auto requestSource = requestCombo->request->source;
        // 非激活会话不会被调度
        CONTINUE_IF_TRUE(!this->isActiveSession(requestSource->getPID()));

        // 选择优先级较高的请求进行调度，如果优先级相同，则按照请求事件顺序进行调度
        if (!newRequestComb ||
            (requestSource->getPriority() > newRequestComb->request->source->getPriority()) ||
            (requestSource->getPriority() == newRequestComb->request->source->getPriority() &&
             requestCombo->request->time < newRequestComb->request->time))
        {
            newRequestComb = requestCombo;
        }
    }
    if (newRequestComb)
    {
        this->wakeRequest(newRequestComb);
    }
}

void DeviceRequestController::wakeRequest(QSharedPointer<DeviceRequestCombo> requestComb)
{
    RETURN_IF_FALSE(requestComb);
    // 请求未变化，直接返回
    RETURN_IF_TRUE(this->m_currentRequestCombo && this->m_currentRequestCombo->request.get() == requestComb->request.get());
    // 中断当前的请求
    this->interruptRequest();

    this->m_currentRequestCombo = requestComb;
    this->m_currentRequestCombo->target->schedule();
}

bool DeviceRequestController::isActiveSession(uint32_t pid)
{
    auto sessionObjectPath = Login1ManagerProxy::getDefault()->getSessionByPID(pid);
    auto session = QSharedPointer<Login1SessionProxy>::create(sessionObjectPath);
    return session->activate();
}

void DeviceRequestController::onActiveSessionChanged(const Login1SessionItem &sessionItem)
{
    // 如果当前请求的会话从活跃变为不活跃，则停止当前请求进行重新调度
    if (this->m_currentRequestCombo && !this->isActiveSession(this->m_currentRequestCombo->request->source->getPID()))
    {
        this->interruptRequest();
    }

    // 这个if语句正常应该是一定成立的，这里只是避免信号误报而增加一个判断
    if (!this->m_currentRequestCombo)
    {
        this->schedule();
    }
}

}  // namespace Kiran
