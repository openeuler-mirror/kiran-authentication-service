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

#pragma once

#include "device.h"
#include "driver/virtual-face-driver.h"

namespace Kiran
{
class VirtualFaceDevice : public Device
{
    Q_OBJECT
public:
    VirtualFaceDevice(DriverPtr driver, QObject *parent = nullptr);
    ~VirtualFaceDevice();

    DeviceType deviceType() override;
    void EnrollStart(const QString &extraInfo) override;
    void EnrollStop() override;
    void IdentifyStart(const QString &extraInfo) override;
    void IdentifyStop() override;
    QStringList GetFeatureIDList() override;

    void IdentifyResultPostProcess(const QString &extraInfo) override;

private:
    VirtualFaceDriverPtr m_driver;
};
typedef QSharedPointer<VirtualFaceDevice> VirtualFaceDevicePtr;

}  // namespace Kiran