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
#include <kiran-authentication-devices/kiran-auth-device-i.h>
#include <QJsonDocument>
#include <climits>
#include "logging-category.h"
#include "src/daemon/auth-manager.h"
#include "src/daemon/config-daemon.h"
#include "src/daemon/device/device-protocol.h"
#include "src/daemon/proxy/login1-manager-proxy.h"
#include "src/daemon/proxy/login1-seat-proxy.h"
#include "src/daemon/proxy/login1-session-proxy.h"


#define ENROLL_TIMEOUT_MS   300000
#define IDENTIFY_TIMEOUT_MS 60000 

#define DEVICE_DEBUG() KLOG_DEBUG() << this->m_deviceID

namespace Kiran
{
DeviceAdaptor::DeviceAdaptor(QSharedPointer<AuthDeviceProxy> dbusDeviceProxy)
    : m_dbusDeviceProxy(nullptr),
      m_requestIDCount(-1)
{
    m_deviceOccupyTimer.setSingleShot(true);
    connect(&m_deviceOccupyTimer,&QTimer::timeout,this,&DeviceAdaptor::onDeviceOccupyTimeout);

    auto defaultSeat = Login1SeatProxy::getDefault();
    connect(defaultSeat.get(), SIGNAL(activeSessionChanged(const Login1SessionItem &)), this, SLOT(onActiveSessionChanged(const Login1SessionItem &)));

    this->updateDBusDeviceProxy(dbusDeviceProxy);
}

void DeviceAdaptor::enroll(DeviceRequestSource *source, const QString &extraInfo)
{
    auto deviceRequst = QSharedPointer<DeviceRequest>::create(DeviceRequest{
        .reqID = this->generateRequestID(),
        .time = QTime::currentTime(),
        .source = source,
        .start = std::bind(&DeviceAdaptor::enrollStart, this, extraInfo),
        .stop = std::bind(&DeviceAdaptor::enrollStop, this)});
    this->pushRequest(deviceRequst);
}

void DeviceAdaptor::identify(DeviceRequestSource *source, const QString &extraInfo)
{
    auto deviceRequst = QSharedPointer<DeviceRequest>::create(DeviceRequest{
        .reqID = this->generateRequestID(),
        .time = QTime::currentTime(),
        .source = source,
        .start = std::bind(&DeviceAdaptor::identifyStart, this, extraInfo),
        .stop = std::bind(&DeviceAdaptor::identifyStop, this)});
    this->pushRequest(deviceRequst);
}

void DeviceAdaptor::removeAllRequest()
{
    // 中断当前认证
    this->interruptRequest();

    // 清空/结束所有认证，不再参与调度
    for (auto iter = this->m_requests.begin(); iter != this->m_requests.end();)
    {
        iter->get()->source->cancel();
        iter->get()->source->end();
        iter = this->m_requests.erase(iter);
    }
}

void DeviceAdaptor::stop(int64_t requestID)
{
    // 停止操作需要立即执行，因为source会变为不可用。
    this->removeRequest(requestID);
}

void DeviceAdaptor::updateDBusDeviceProxy(QSharedPointer<AuthDeviceProxy> dbusDeviceProxy)
{
    RETURN_IF_FALSE(dbusDeviceProxy);

    DEVICE_DEBUG() << "update auth device";
    if (!this->m_dbusDeviceProxy ||
        this->m_dbusDeviceProxy->deviceID() != dbusDeviceProxy->deviceID())
    {
        if (this->m_dbusDeviceProxy)
        {
            this->m_dbusDeviceProxy->disconnect(this);
            this->m_dbusDeviceProxy.clear();
        }

        this->m_dbusDeviceProxy = dbusDeviceProxy;
        this->m_deviceID = dbusDeviceProxy->deviceID();

        this->interruptRequest();

        connect(this->m_dbusDeviceProxy.get(), &AuthDeviceProxy::EnrollStatus, this, &DeviceAdaptor::onEnrollStatus);
        connect(this->m_dbusDeviceProxy.get(), &AuthDeviceProxy::IdentifyStatus, this, &DeviceAdaptor::onIdentifyStatus);

        DEVICE_DEBUG() << "update auth device finished";
        this->schedule();
    }
}

void DeviceAdaptor::pushRequest(QSharedPointer<DeviceRequest> request)
{
    this->m_requests.insert(request->reqID, request);
    request->source->queued(request);
    
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

    if (this->m_currentRequest && (requestID == this->m_currentRequest->reqID))
    {
        this->interruptRequest();
    }

    request->source->cancel();

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
        this->m_currentRequest->stop();
        this->m_currentRequest->source->interrupt();
        this->m_currentRequest = nullptr;
    }
}

void DeviceAdaptor::finishRequest()
{
    if (this->m_currentRequest)
    {
        stopDeviceOccupyTimer();
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
#if 0
        // NOTE:
        //  由于部分认证进程关联不上systemd login会话，这将导致其永远不会被调度
        //  后修改逻辑，切换会话时，清空/中断所有认证请求
        
        // 非激活会话不会被调度
        bool isActive = this->isActiveSession(request->source->getPID());
        if (!isActive)
        {
            KLOG_DEBUG("request(%d) isn't active,ignore", request->reqID);
            continue;
        }
#endif
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

void DeviceAdaptor::enrollStart(const QString &extraInfo)
{
    if (this->m_dbusDeviceProxy)
    {
        startDeviceOccupyTimer(ENROLL_TIMEOUT_MS);
        this->m_dbusDeviceProxy->EnrollStart(extraInfo);
    }
    else
    {
        DEVICE_DEBUG() << "Not found fingerprint device, enroll failed.";
        this->onEnrollStatus(QString(), EnrollStatus::ENROLL_STATUS_FAIL, 0, "");
    }
}

void DeviceAdaptor::enrollStop()
{
    if (this->m_dbusDeviceProxy)
    {
        stopDeviceOccupyTimer();
        this->m_dbusDeviceProxy->EnrollStop();
    }
}

void DeviceAdaptor::identifyStart(const QString &extraInfo)
{
    if (this->m_dbusDeviceProxy)
    {
        DEVICE_DEBUG() << "device proxy identify start";
        startDeviceOccupyTimer(IDENTIFY_TIMEOUT_MS);
        this->m_dbusDeviceProxy->IdentifyStart(extraInfo);
    }
    else
    {
        DEVICE_DEBUG() << "Not found fingerprint device, identify failed.";
        this->onIdentifyStatus(QString(), IdentifyStatus::IDENTIFY_STATUS_NOT_MATCH, "");
    }
}

void DeviceAdaptor::identifyStop()
{
    if (this->m_dbusDeviceProxy)
    {
        stopDeviceOccupyTimer();
        this->m_dbusDeviceProxy->IdentifyStop();
        DEVICE_DEBUG() << "device proxy identify stop";
    }
}

bool DeviceAdaptor::isActiveSession(uint32_t pid)
{
    auto sessionObjectPath = Login1ManagerProxy::getDefault()->getSessionByPID(pid);
    auto session = QSharedPointer<Login1SessionProxy>::create(sessionObjectPath);
    DEVICE_DEBUG() << pid << sessionObjectPath.path() << session->activate();
    return session->activate();
}

void DeviceAdaptor::startDeviceOccupyTimer(int ms)
{
    DEVICE_DEBUG() << "start device occupy timer" << ms << "ms" << "for request:" << this->m_currentRequest->reqID;
    m_deviceOccupyTimer.start(ms);
}

void DeviceAdaptor::stopDeviceOccupyTimer()
{
    DEVICE_DEBUG() << "stop device occupy timer for request:" << this->m_currentRequest->reqID;
    m_deviceOccupyTimer.stop();
}

void DeviceAdaptor::onEnrollStatus(const QString &featureID, int progress, int result, const QString &message)
{
    DEVICE_DEBUG() << "enroll status:" << featureID << result << progress << message;

    if (this->m_currentRequest)
    {
        this->m_currentRequest->source->onEnrollStatus(featureID, progress,result, message);
    }
    else
    {
        KLOG_WARNING("Not found current request.");
    }

    if (result == EnrollStatus::ENROLL_STATUS_COMPLETE ||
        result == EnrollStatus::ENROLL_STATUS_FAIL)
    {
        this->finishRequest();
    }
}

void DeviceAdaptor::onIdentifyStatus(const QString &featureID, int result, const QString &message)
{
    DEVICE_DEBUG() << "identify status:" << featureID << result << message;

    if (this->m_currentRequest)
    {
        this->m_currentRequest->source->onIdentifyStatus(featureID, result, message);
    }
    else
    {
        KLOG_WARNING("Not found current request.");
    }

    if (result == IdentifyStatus::IDENTIFY_STATUS_NOT_MATCH ||
        result == IdentifyStatus::IDENTIFY_STATUS_MATCH)
    {
        this->finishRequest();
    }
}

// NOTE:
//  之前处理逻辑为活跃会话改变时，中断/不调度非活跃会话
//  但是由于通过 DBus调用者->pid->logind session->session active
//  这条关系链，通过pid拿到logind会话，部分情况进程可能关联不上会话(例如lightdm fork出用于提供给Greeter做认证的子进程)
//
//  现更改逻辑为会话活跃状态改变时，结束/清空认证请求
//  认证队列里只存当前会话里的认证请求
void DeviceAdaptor::onActiveSessionChanged(const Login1SessionItem &sessionItem)
{
    DEVICE_DEBUG() << "active session changed:" << sessionItem.sessionID << sessionItem.sessionObjectPath.path();

    // 清空之前会话里的所有认证请求
    removeAllRequest();

    // 重新调度设备认证请求
    this->schedule();
}

void DeviceAdaptor::onDeviceOccupyTimeout()
{
    DEVICE_DEBUG() << QString("request: %1 occupy timeout,cancel!").arg(m_currentRequest->reqID);
    this->removeRequest(m_currentRequest->reqID);
}

}  // namespace Kiran
