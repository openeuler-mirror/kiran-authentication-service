#include <qt5-log-i.h>

#include "auth_device_adaptor.h"
#include "virtual-face-device.h"

namespace Kiran
{
VirtualFaceDevice::VirtualFaceDevice(DriverPtr driver, QObject* parent) : Device(driver, parent)
{
    m_driver = driver.staticCast<VirtualFaceDriver>();
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
    KLOG_INFO() << "VirtualFaceDevice IdentifyStart";
    KLOG_INFO() << "extraInfo:" << extraInfo;

    if (DEVICE_STATUS_IDLE != deviceStatus())
    {
        QString message = tr("Device Busy");
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        KLOG_INFO() << QString("%1, deviceID:%2").arg("Device Busy").arg(m_devId);
        return;
    }

    int ret = m_driver->identify(extraInfo);
    if (0 != ret)
    {
        QString msg = m_driver->getErrorMsg(ret);
        KLOG_ERROR() << "identify fail:" << m_driver->getErrorMsg(ret);
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, msg);
    }
    else
    {
        KLOG_INFO() << "identify success";
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_MATCH, tr("identify success"));
    }
}

void VirtualFaceDevice::IdentifyStop()
{
    if (DEVICE_STATUS_DOING_IDENTIFY == deviceStatus())
    {
        m_status = DEVICE_STATUS_IDLE;
    }
}

QStringList VirtualFaceDevice::GetFeatureIDList()
{
    return QStringList();
}

void VirtualFaceDevice::IdentifySuccessedPostProcess(const QString& extraInfo)
{
    KLOG_INFO() << "VirtualFaceDevice onIdentifySuccessed, extraInfo:" << extraInfo;
    // 认证成功后处理（如开启人走监测等）
    m_driver->identifySuccessedPostProcess(extraInfo);
}

}  // namespace Kiran
