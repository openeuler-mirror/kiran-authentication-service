/**
 * Copyright (c) 2025 ~ 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     yangfeng <yangfeng@kylinsec.com.cn>
 */

#include <qt5-log-i.h>
#include <QtConcurrent/QtConcurrent>

#include "auth_device_adaptor.h"
#include "soft-face-device.h"

namespace Kiran
{
SoftFaceDevice::SoftFaceDevice(DriverPtr driver, QObject* parent) : Device(driver, parent)
{
    m_driver = std::static_pointer_cast<SoftFaceDriver>(driver);
    connect(&m_identifyWatcher, &QFutureWatcher<int>::finished, this, [this]()
            {
        const int ret = m_identifyWatcher.result();
        const bool stopped = m_identifyStopRequested;
        m_identifyStopRequested = false;
        m_status = DEVICE_STATUS_IDLE;

        KLOG_INFO() << "SoftFaceDevice: Identify finished"
                    << "ret=" << ret
                    << "stopRequested=" << stopped
                    << "deviceID=" << m_devId;

        if (stopped)
        {
            KLOG_INFO() << "SoftFaceDevice Identify finished but stop requested, ignore result";
            return;
        }

        if (0 != ret)
        {
            QString msg = QString::fromStdString(m_driver->getErrorMsg(ret));
            KLOG_ERROR() << "SoftFaceDevice identify fail:"
                         << "code=" << ret
                         << "msg=" << msg
                         << "deviceID=" << m_devId;
            Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, msg);
        }
        else
        {
            KLOG_INFO() << "SoftFaceDevice identify success, deviceID=" << m_devId;
            Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_MATCH, tr("identify success"));
        } });
}

SoftFaceDevice::~SoftFaceDevice()
{
}

DeviceType SoftFaceDevice::deviceType()
{
    return DEVICE_TYPE_SOFT;
}

SoftDeviceType SoftFaceDevice::softDeviceType()
{
    return SOFT_DEVICE_TYPE_FACE;
}

void SoftFaceDevice::doEnrollStart(const QString& extraInfo)
{
    return;  // 软设备在管理后台注册
}

void SoftFaceDevice::EnrollStop()
{
    return;  // 软设备在管理后台注册
}

void SoftFaceDevice::doIdentifyStart(const QString& extraInfo)
{
    KLOG_INFO() << "SoftFaceDevice IdentifyStart"
                << "driver=" << QString::fromStdString(m_driver->getDriverName())
                << "deviceID=" << m_devId
                << "status=" << deviceStatus()
                << "extraInfo=" << extraInfo;

    if (DEVICE_STATUS_IDLE != deviceStatus())
    {
        QString message = tr("Device Busy");
        KLOG_WARNING() << "SoftFaceDevice IdentifyStart rejected: device busy"
                       << "deviceID=" << m_devId
                       << "status=" << deviceStatus();
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        KLOG_INFO() << QString("%1, deviceID:%2").arg("Device Busy").arg(m_devId);
        return;
    }

    m_status = DEVICE_STATUS_DOING_IDENTIFY;
    m_identifyStopRequested = false;
    auto driver = m_driver;
    auto info = extraInfo;
    KLOG_INFO() << "SoftFaceDevice: launching identify thread, deviceID=" << m_devId;
    m_identifyWatcher.setFuture(QtConcurrent::run([driver, info]() -> int
                                                  { return driver->identify(info.toStdString()); }));
}

void SoftFaceDevice::IdentifyStop()
{
    KLOG_INFO() << "SoftFaceDevice IdentifyStop"
                << "deviceID=" << m_devId
                << "status=" << deviceStatus()
                << "stopRequestedBefore=" << m_identifyStopRequested;
    if (DEVICE_STATUS_DOING_IDENTIFY == deviceStatus())
    {
        // driver 接口当前不支持真正的中断，这里只标记停止并让 DBus 调用立即返回；
        // 识别线程完成后会丢弃结果，避免阻塞切换到密码的 prompt。
        m_identifyStopRequested = true;
        KLOG_INFO() << "SoftFaceDevice IdentifyStop: marked stop requested, deviceID=" << m_devId;
    }
}

QStringList SoftFaceDevice::GetFeatureIDList()
{
    return QStringList();
}

void SoftFaceDevice::IdentifyResultPostProcess(const QString& extraInfo)
{
    KLOG_INFO() << "SoftFaceDevice identifyResultPostProcess, extraInfo:" << extraInfo;
    // 识别结果后处理（如上报日志、开启人走监测等）
    m_driver->identifyResultPostProcess(extraInfo.toStdString());
}

}  // namespace Kiran
