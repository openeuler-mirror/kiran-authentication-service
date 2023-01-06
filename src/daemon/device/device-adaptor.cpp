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

#include "src/daemon/device/device-adaptor.h"
#include <auxiliary.h>
#include <biometrics-i.h>
#include <QJsonDocument>
#include <climits>
#include "src/daemon/auth-manager.h"
#include "src/daemon/config-daemon.h"
#include "src/daemon/device/device-protocol.h"
#include "src/daemon/proxy/login1-manager-proxy.h"
#include "src/daemon/proxy/login1-seat-proxy.h"
#include "src/daemon/proxy/login1-session-proxy.h"

namespace Kiran
{
DeviceAdaptor::DeviceAdaptor(QSharedPointer<DeviceProxy> dbusDeviceProxy) : m_dbusDeviceProxy(nullptr),
                                                                            m_requestIDCount(-1)
{
    auto defaultSeat = Login1SeatProxy::getDefault();
    connect(defaultSeat.get(), SIGNAL(activeSessionChanged(const Login1SessionItem &)), this, SLOT(onActiveSessionChanged(const Login1SessionItem &)));

    this->updateDBusDeviceProxy(dbusDeviceProxy);
}

void DeviceAdaptor::enroll(DeviceRequestSource *source)
{
    auto deviceRequst = QSharedPointer<DeviceRequest>::create(DeviceRequest{
        .reqID = this->generateRequestID(),
        .time = QTime::currentTime(),
        .source = source,
        .start = std::bind(&DeviceAdaptor::enrollStart, this),
        .stop = std::bind(&DeviceAdaptor::enrollStop, this)});
    this->pushRequest(deviceRequst);
}

void DeviceAdaptor::verify(const QString &bid, DeviceRequestSource *source)
{
    auto deviceRequst = QSharedPointer<DeviceRequest>::create(DeviceRequest{
        .reqID = this->generateRequestID(),
        .time = QTime::currentTime(),
        .source = source,
        .start = std::bind(&DeviceAdaptor::verifyStart, this, bid),
        .stop = std::bind(&DeviceAdaptor::verifyStop, this)});
    this->pushRequest(deviceRequst);
}

void DeviceAdaptor::identify(const QStringList &bids, DeviceRequestSource *source)
{
    auto deviceRequst = QSharedPointer<DeviceRequest>::create(DeviceRequest{
        .reqID = this->generateRequestID(),
        .time = QTime::currentTime(),
        .source = source,
        .start = std::bind(&DeviceAdaptor::identifyStart, this, bids),
        .stop = std::bind(&DeviceAdaptor::identifyStop, this)});
    this->pushRequest(deviceRequst);
}

void DeviceAdaptor::stop(int64_t requestID)
{
    // 停止操作需要立即执行，因为source会变为不可用。
    this->removeRequest(requestID);
}

void DeviceAdaptor::updateDBusDeviceProxy(QSharedPointer<DeviceProxy> dbusDeviceProxy)
{
    RETURN_IF_FALSE(dbusDeviceProxy);

    if (!this->m_dbusDeviceProxy ||
        this->m_dbusDeviceProxy->deviceID() != dbusDeviceProxy->deviceID())
    {
        if (this->m_dbusDeviceProxy)
        {
            this->m_dbusDeviceProxy->disconnect();
            this->m_dbusDeviceProxy = nullptr;
        }

        this->interruptRequest();

        connect(this->m_dbusDeviceProxy.get(), &DeviceProxy::EnrollStatus, this, &DeviceAdaptor::onEnrollStatus);
        connect(this->m_dbusDeviceProxy.get(), &DeviceProxy::IdentifyStatus, this, &DeviceAdaptor::onIdentifyStatus);
        connect(this->m_dbusDeviceProxy.get(), &DeviceProxy::VerifyStatus, this, &DeviceAdaptor::onVerifyStatus);

        this->schedule();
    }
}

void DeviceAdaptor::pushRequest(QSharedPointer<DeviceRequest> request)
{
    this->m_requests.insert(request->reqID, request);

    // 如果当前插入的请求优先级比正在执行请求的优先级高，则进行抢占
    auto pushPriority = request->source->getPriority();
    if (!this->m_currentRequest ||
        (pushPriority > this->m_currentRequest->source->getPriority()))
    {
        this->wakeRequest(request);
    }
}

void DeviceAdaptor::wakeRequest(QSharedPointer<DeviceRequest> request)
{
    RETURN_IF_FALSE(request);
    // 请求未变化，直接返回
    RETURN_IF_TRUE(this->m_currentRequest && this->m_currentRequest.get() == request.get());
    // 中断当前的请求
    this->interruptRequest();

    this->m_currentRequest = request;
    this->m_currentRequest->start();
}

void DeviceAdaptor::removeRequest(int64_t requestID)
{
    auto request = this->m_requests.value(requestID, nullptr);
    RETURN_IF_FALSE(request);

    if (requestID == this->m_currentRequest->reqID)
    {
        this->interruptRequest();
    }
    request->source->end();
    this->m_requests.remove(requestID);

    if (!this->m_currentRequest && this->m_requests.size() > 0)
    {
        this->schedule();
    }
}

void DeviceAdaptor::interruptRequest()
{
    if (this->m_currentRequest)
    {
        this->m_currentRequest->source->interrupt();
        this->m_currentRequest = nullptr;
    }
}

void DeviceAdaptor::finishRequest()
{
    if (this->m_currentRequest)
    {
        this->m_currentRequest->source->end();
        this->m_requests.remove(this->m_currentRequest->reqID);
        this->m_currentRequest = nullptr;
    }
    this->schedule();
}

void DeviceAdaptor::schedule()
{
    RETURN_IF_TRUE(this->m_requests.size() == 0);

    QSharedPointer<DeviceRequest> newRequest;
    for (auto &request : this->m_requests)
    {
        // 非激活会话不会被调度
        CONTINUE_IF_TRUE(!this->isActiveSession(request->source->getPID()));

        // 选择优先级较高的请求进行调度，如果优先级相同，则按照请求事件顺序进行调度
        if (!newRequest ||
            (request->source->getPriority() > newRequest->source->getPriority()) ||
            (request->source->getPriority() == newRequest->source->getPriority() &&
             request->time < newRequest->time))
        {
            newRequest = request;
        }
    }
    if (newRequest)
    {
        this->wakeRequest(newRequest);
    }
}

int64_t DeviceAdaptor::generateRequestID()
{
    if (this->m_requestIDCount >= LONG_LONG_MAX)
    {
        this->m_requestIDCount = 0;
    }
    ++this->m_requestIDCount;

    // 如果存在冲突，则删除掉之前的请求，因为停留太久了
    auto request = this->m_requests.value(this->m_requestIDCount);
    if (request)
    {
        this->removeRequest(this->m_requestIDCount);
    }
    return this->m_requestIDCount;
}

void DeviceAdaptor::enrollStart()
{
    if (this->m_dbusDeviceProxy)
    {
        this->m_dbusDeviceProxy->EnrollStart();
    }
    else
    {
        KLOG_DEBUG("Not found fingerprint device, enroll failed.");
        this->onEnrollStatus(QString(), FPEnrollResult::FP_ENROLL_RESULT_FAIL, 0);
    }
}

void DeviceAdaptor::enrollStop()
{
    if (this->m_dbusDeviceProxy)
    {
        this->m_dbusDeviceProxy->EnrollStop();
    }
}

void DeviceAdaptor::verifyStart(const QString &bid)
{
    if (this->m_dbusDeviceProxy)
    {
        this->m_dbusDeviceProxy->VerifyStart(bid);
    }
    else
    {
        KLOG_DEBUG("Not found fingerprint device, verify failed.");
        this->onVerifyStatus(FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH);
    }
}

void DeviceAdaptor::verifyStop()
{
    if (this->m_dbusDeviceProxy)
    {
        this->m_dbusDeviceProxy->VerifyStop();
    }
}

void DeviceAdaptor::identifyStart(const QStringList &bids)
{
    if (this->m_dbusDeviceProxy)
    {
        this->m_dbusDeviceProxy->IdentifyStart(bids);
    }
    else
    {
        KLOG_DEBUG("Not found fingerprint device, identify failed.");
        this->onIdentifyStatus(QString(), FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH);
    }
}

void DeviceAdaptor::identifyStop()
{
    if (this->m_dbusDeviceProxy)
    {
        this->m_dbusDeviceProxy->IdentifyStop();
    }
}

bool DeviceAdaptor::isActiveSession(uint32_t pid)
{
    auto sessionObjectPath = Login1ManagerProxy::getDefault()->getSessionByPID(pid);
    auto session = QSharedPointer<Login1SessionProxy>::create(sessionObjectPath);
    return session->activate();
}

void DeviceAdaptor::onEnrollStatus(const QString &bid, int result, int progress)
{
    if (this->m_currentRequest)
    {
        this->m_currentRequest->source->onEnrollStatus(bid, result, progress);
    }
    else
    {
        KLOG_WARNING("Not found current request.");
    }

    if (result == FPEnrollResult::FP_ENROLL_RESULT_COMPLETE ||
        result == FPEnrollResult::FP_ENROLL_RESULT_FAIL)
    {
        this->finishRequest();
    }
}

void DeviceAdaptor::onVerifyStatus(int result)
{
    if (this->m_currentRequest)
    {
        this->m_currentRequest->source->onVerifyStatus(result);
    }
    else
    {
        KLOG_WARNING("Not found current request.");
    }

    if (result == FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH ||
        result == FPVerifyResult::FP_VERIFY_RESULT_MATCH)
    {
        this->finishRequest();
    }
}

void DeviceAdaptor::onIdentifyStatus(const QString &bid, int result)
{
    if (this->m_currentRequest)
    {
        this->m_currentRequest->source->onIdentifyStatus(bid, result);
    }
    else
    {
        KLOG_WARNING("Not found current request.");
    }

    if (result == FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH ||
        result == FPVerifyResult::FP_VERIFY_RESULT_MATCH)
    {
        this->finishRequest();
    }
}

void DeviceAdaptor::onActiveSessionChanged(const Login1SessionItem &sessionItem)
{
    // 如果当前请求的会话从活跃变为不活跃，则停止当前请求进行重新调度
    if (this->m_currentRequest && !this->isActiveSession(this->m_currentRequest->source->getPID()))
    {
        this->interruptRequest();
    }

    // 这个if语句正常应该是一定成立的，这里只是避免信号误报而增加一个判断
    if (!this->m_currentRequest)
    {
        this->schedule();
    }
}

}  // namespace Kiran
