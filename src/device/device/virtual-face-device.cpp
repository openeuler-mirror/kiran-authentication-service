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
#include "virtual-face-device.h"

namespace Kiran
{
VirtualFaceDevice::VirtualFaceDevice(DriverPtr driver, QObject* parent) : Device(driver, parent)
{
    m_driver = driver.staticCast<VirtualFaceDriver>();
    connect(&m_identifyWatcher, &QFutureWatcher<int>::finished, this, [this]() {
        const int ret = m_identifyWatcher.result();
        const bool stopped = m_identifyStopRequested;
        m_identifyStopRequested = false;
        m_status = DEVICE_STATUS_IDLE;

        if (stopped)
        {
            KLOG_INFO() << "VirtualFaceDevice Identify finished but stop requested, ignore result";
            return;
        }

        if (0 != ret)
        {
            QString msg = m_driver->getErrorMsg(ret);
            KLOG_ERROR() << "identify fail:" << msg;
            Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, msg);
        }
        else
        {
            KLOG_INFO() << "identify success";
            Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_MATCH, tr("identify success"));
        }
    });
}

VirtualFaceDevice::~VirtualFaceDevice()
{
}

DeviceType VirtualFaceDevice::deviceType()
{
    return DEVICE_TYPE_Virtual_Face;
}

void VirtualFaceDevice::EnrollStart(const QString& extraInfo)
{
    return;  // 虚拟设备在管理后台注册
}

void VirtualFaceDevice::EnrollStop()
{
    return;  // 虚拟设备在管理后台注册
}

void VirtualFaceDevice::IdentifyStart(const QString& extraInfo)
{
    KLOG_INFO() << "VirtualFaceDevice IdentifyStart, " << m_driver->getDriverName();
    KLOG_INFO() << "extraInfo:" << extraInfo;

    if (DEVICE_STATUS_IDLE != deviceStatus())
    {
        QString message = tr("Device Busy");
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        KLOG_INFO() << QString("%1, deviceID:%2").arg("Device Busy").arg(m_devId);
        return;
    }

    m_status = DEVICE_STATUS_DOING_IDENTIFY;
    m_identifyStopRequested = false;
    auto driver = m_driver;
    auto info = extraInfo;
    m_identifyWatcher.setFuture(QtConcurrent::run([driver, info]() -> int {
        return driver->identify(info);
    }));
}

void VirtualFaceDevice::IdentifyStop()
{
    if (DEVICE_STATUS_DOING_IDENTIFY == deviceStatus())
    {
        // driver 接口当前不支持真正的中断，这里只标记停止并让 DBus 调用立即返回；
        // 识别线程完成后会丢弃结果，避免阻塞切换到密码的 prompt。
        m_identifyStopRequested = true;
    }
}

QStringList VirtualFaceDevice::GetFeatureIDList()
{
    return QStringList();
}

void VirtualFaceDevice::IdentifyResultPostProcess(const QString& extraInfo)
{
    KLOG_INFO() << "VirtualFaceDevice identifyResultPostProcess, extraInfo:" << extraInfo;
    // 识别结果后处理（如上报日志、开启人走监测等）
    m_driver->identifyResultPostProcess(extraInfo);
}

}  // namespace Kiran
