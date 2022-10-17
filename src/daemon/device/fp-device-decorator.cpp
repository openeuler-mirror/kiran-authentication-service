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

#include "src/daemon/device/fp-device-decorator.h"
#include <auxiliary.h>
#include <biometrics-i.h>
#include <QJsonDocument>
#include <climits>
#include "src/daemon/auth-manager.h"
#include "src/daemon/biometrics_proxy.h"
#include "src/daemon/config-daemon.h"
#include "src/daemon/device/device-protocol.h"
#include "src/daemon/device/device-request-controller.h"
#include "src/daemon/fp_device_proxy.h"

namespace Kiran
{
void FPDeviceDecorator::FPDeviceRequestTarget::start()
{
    this->m_request->source->event(DeviceEvent{.eventType = DeviceEventType::DEVICE_EVENT_TYPE_START,
                                               .request = this->m_request});
}

void FPDeviceDecorator::FPDeviceRequestTarget::interrupt()
{
    this->m_requestStop();
    this->m_request->source->event(DeviceEvent{.eventType = DeviceEventType::DEVICE_EVENT_TYPE_INTERRUPT,
                                               .request = this->m_request});
}

void FPDeviceDecorator::FPDeviceRequestTarget::schedule()
{
    this->m_requestStart();
}

void FPDeviceDecorator::FPDeviceRequestTarget::end()
{
    this->m_request->source->event(DeviceEvent{.eventType = DeviceEventType::DEVICE_EVENT_TYPE_END,
                                               .request = this->m_request});
}

FPDeviceDecorator::FPDeviceDecorator() : m_fpDeviceProxy(nullptr)
{
    this->m_biometricsProxy = new BiometricsProxy(BIOMETRICS_DBUS_NAME,
                                                  BIOMETRICS_DBUS_OBJECT_PATH,
                                                  QDBusConnection::systemBus(),
                                                  this);
    this->m_requestController = new DeviceRequestController(this);

    this->initDevice();
    connect(AuthManager::getInstance(), SIGNAL(fpDeviceIDChanged(const QString &)), this, SLOT(onFPDeviceIDChanged(const QString &)));
}

void FPDeviceDecorator::process(QSharedPointer<DeviceRequest> request)
{
    auto requestTarget = QSharedPointer<FPDeviceRequestTarget>::create(this);
    requestTarget->setRequest(request);

    switch (request->reqType)
    {
    case DeviceRequestType::DEVICE_REQUEST_TYPE_FP_ENROLL_START:
    {
        requestTarget->setRequestStart(std::bind(&FPDeviceDecorator::enrollStart, this));
        requestTarget->setRequestStop(std::bind(&FPDeviceDecorator::enrollStop, this));
        this->m_requestController->pushRequest(request, requestTarget);
        break;
    }
    case DeviceRequestType::DEVICE_REQUEST_TYPE_FP_VERIFY_START:
    {
        auto bid = request->args.value(DEVICE_REQUEST_ARGS_BID).toString();
        requestTarget->setRequestStart(std::bind(&FPDeviceDecorator::verifyStart, this, bid));
        requestTarget->setRequestStop(std::bind(&FPDeviceDecorator::enrollStop, this));
        this->m_requestController->pushRequest(request, requestTarget);
        break;
    }
    case DeviceRequestType::DEVICE_REQUEST_TYPE_FP_IDENTIFY_START:
    {
        auto bids = request->args.value(DEVICE_REQUEST_ARGS_BIDS).toStringList();
        requestTarget->setRequestStart(std::bind(&FPDeviceDecorator::identifyStart, this, bids));
        requestTarget->setRequestStop(std::bind(&FPDeviceDecorator::enrollStop, this));
        this->m_requestController->pushRequest(request, requestTarget);
        break;
    }
    case DeviceRequestType::DEVICE_REQUEST_TYPE_FP_ENROLL_STOP:
    case DeviceRequestType::DEVICE_REQUEST_TYPE_FP_VERIFY_STOP:
    case DeviceRequestType::DEVICE_REQUEST_TYPE_FP_IDENTIFY_STOP:
    {
        auto requestID = request->args.value(DEVICE_REQUEST_ARGS_REQUEST_ID).toLongLong();
        this->m_requestController->removeRequest(requestID);
        break;
    }
    default:
        KLOG_WARNING() << "Unknown request type: " << request->reqType;
        return;
    }
}

void FPDeviceDecorator::initDevice()
{
    if (!this->m_biometricsProxy)
    {
        KLOG_WARNING() << "The biometrics proxy is null.";
        return;
    }

    auto defaultDeviceID = AuthManager::getInstance()->getFPDeviceID();
    auto defaultDeviceReply = this->m_biometricsProxy->GetDevice(BiometricsDeviceType::BIOMETRICS_DEVICE_TYPE_FINGERPRINT, defaultDeviceID);
    auto deviceObjectPath = defaultDeviceReply.value();

    if (defaultDeviceReply.isError())
    {
        KLOG_DEBUG() << "Not found default fingerprint device: " << defaultDeviceReply.error().message();
    }

    // 如果未找到默认设备，则随机选择一个
    if (defaultDeviceReply.isError() || deviceObjectPath.path().isEmpty())
    {
        KLOG_DEBUG("Prepare to randomly select a fingerprint device.");

        auto devicesReply = this->m_biometricsProxy->GetDevicesByType(BiometricsDeviceType::BIOMETRICS_DEVICE_TYPE_FINGERPRINT);
        auto devicesJson = devicesReply.value();
        auto jsonDoc = QJsonDocument::fromJson(devicesJson.toUtf8());
        auto jsonArr = jsonDoc.array();
        if (jsonArr.size() > 0)
        {
            auto deviceID = jsonArr[0].toObject().value(QStringLiteral(BIOMETRICS_DJK_KEY_ID)).toString();
            auto deviceReply = this->m_biometricsProxy->GetDevice(BiometricsDeviceType::BIOMETRICS_DEVICE_TYPE_FINGERPRINT, deviceID);
            deviceObjectPath = deviceReply.value();
        }
        else
        {
            KLOG_DEBUG() << "Not found available fingerprint device.";
        }
    }

    if (!deviceObjectPath.path().isEmpty())
    {
        this->m_fpDeviceProxy = new FPDeviceProxy(BIOMETRICS_DBUS_NAME,
                                                  defaultDeviceReply.value().path(),
                                                  QDBusConnection::systemBus(),
                                                  this);

        KLOG_DEBUG() << "Use fingerprint device " << this->m_fpDeviceProxy->deviceID() << " as active device.";

        connect(this->m_fpDeviceProxy, &FPDeviceProxy::EnrollStatus, this, &FPDeviceDecorator::onEnrollStatus);
        connect(this->m_fpDeviceProxy, &FPDeviceProxy::IdentifyStatus, this, &FPDeviceDecorator::onIdentifyStatus);
        connect(this->m_fpDeviceProxy, &FPDeviceProxy::VerifyStatus, this, &FPDeviceDecorator::onVerifyStatus);
    }
    else
    {
        KLOG_WARNING("Not found fingerprint device.");
    }
}

void FPDeviceDecorator::enrollStart()
{
    if (this->m_fpDeviceProxy)
    {
        this->m_fpDeviceProxy->EnrollStart();
    }
    else
    {
        KLOG_DEBUG("Not found fingerprint device, enroll failed.");
        this->onEnrollStatus(QString(), FPEnrollResult::FP_ENROLL_RESULT_FAIL, 0);
    }
}

void FPDeviceDecorator::enrollStop()
{
    if (this->m_fpDeviceProxy)
    {
        this->m_fpDeviceProxy->EnrollStop();
    }
}

void FPDeviceDecorator::verifyStart(const QString &bid)
{
    if (this->m_fpDeviceProxy)
    {
        this->m_fpDeviceProxy->VerifyStart(bid);
    }
    else
    {
        KLOG_DEBUG("Not found fingerprint device, verify failed.");
        this->onVerifyStatus(FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH);
    }
}

void FPDeviceDecorator::verifyStop()
{
    if (this->m_fpDeviceProxy)
    {
        this->m_fpDeviceProxy->VerifyStop();
    }
}

void FPDeviceDecorator::identifyStart(const QStringList &bids)
{
    if (this->m_fpDeviceProxy)
    {
        this->m_fpDeviceProxy->IdentifyStart(bids);
    }
    else
    {
        KLOG_DEBUG("Not found fingerprint device, identify failed.");
        this->onIdentifyStatus(QString(), FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH);
    }
}

void FPDeviceDecorator::identifyStop()
{
    if (this->m_fpDeviceProxy)
    {
        this->m_fpDeviceProxy->IdentifyStop();
    }
}

void FPDeviceDecorator::onFPDeviceIDChanged(const QString &fpDeviceID)
{
    if (this->m_fpDeviceProxy)
    {
        this->m_fpDeviceProxy->disconnect();
        this->m_fpDeviceProxy = nullptr;
    }

    this->m_requestController->interruptRequest();
    this->initDevice();
    this->m_requestController->schedule();
}

void FPDeviceDecorator::onEnrollStatus(const QString &bid, int result, int progress)
{
    auto requestCombo = this->m_requestController->getCurrentRequestCombo();
    if (requestCombo)
    {
        auto deviceEvent = DeviceEvent{.eventType = DeviceEventType::DEVICE_EVENT_TYPE_FP_ENROLL_STATUS,
                                       .request = requestCombo->request};
        deviceEvent.args.insert(DEVICE_EVENT_ARGS_BID, bid);
        deviceEvent.args.insert(DEVICE_EVENT_ARGS_RESULT, result);
        deviceEvent.args.insert(DEVICE_EVENT_ARGS_PROGRESS, progress);
        requestCombo->request->source->event(deviceEvent);
    }
    else
    {
        KLOG_WARNING("Not found current request.");
    }

    if (result == FPEnrollResult::FP_ENROLL_RESULT_COMPLETE ||
        result == FPEnrollResult::FP_ENROLL_RESULT_FAIL)
    {
        this->m_requestController->finishRequest();
    }
}

void FPDeviceDecorator::onVerifyStatus(int result)
{
    auto requestCombo = this->m_requestController->getCurrentRequestCombo();
    if (requestCombo)
    {
        auto deviceEvent = DeviceEvent{.eventType = DeviceEventType::DEVICE_EVENT_TYPE_FP_VERIFY_STATUS,
                                       .request = requestCombo->request};
        deviceEvent.args.insert(DEVICE_EVENT_ARGS_RESULT, result);
        requestCombo->request->source->event(deviceEvent);
    }
    else
    {
        KLOG_WARNING("Not found current request.");
    }

    if (result == FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH ||
        result == FPVerifyResult::FP_VERIFY_RESULT_MATCH)
    {
        this->m_requestController->finishRequest();
    }
}

void FPDeviceDecorator::onIdentifyStatus(const QString &bid, int result)
{
    auto requestCombo = this->m_requestController->getCurrentRequestCombo();
    if (requestCombo)
    {
        auto deviceEvent = DeviceEvent{.eventType = DeviceEventType::DEVICE_EVENT_TYPE_FP_IDENTIFY_STATUS,
                                       .request = requestCombo->request};
        deviceEvent.args.insert(DEVICE_EVENT_ARGS_BID, bid);
        deviceEvent.args.insert(DEVICE_EVENT_ARGS_RESULT, result);
        requestCombo->request->source->event(deviceEvent);
    }
    else
    {
        KLOG_WARNING("Not found current request.");
    }

    if (result == FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH ||
        result == FPVerifyResult::FP_VERIFY_RESULT_MATCH)
    {
        this->m_requestController->finishRequest();
    }
}

}  // namespace Kiran
