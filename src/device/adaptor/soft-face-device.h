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

#include <QFutureWatcher>
#include "device.h"
#include "driver-i.h"

namespace Kiran
{
class SoftFaceDevice : public Device
{
    Q_OBJECT
public:
    SoftFaceDevice(DriverPtr driver, QObject *parent = nullptr);
    ~SoftFaceDevice();

    DeviceType deviceType() override;
    SoftDeviceType softDeviceType() override;
    void doEnrollStart(const QString &extraInfo) override;
    void EnrollStop() override;
    void doIdentifyStart(const QString &extraInfo) override;
    void IdentifyStop() override;
    QStringList GetFeatureIDList() override;

    void IdentifyResultPostProcess(const QString &extraInfo) override;

private:
    SoftFaceDriverPtr m_driver;
    QFutureWatcher<int> m_identifyWatcher;
    bool m_identifyStopRequested{false};
};
typedef QSharedPointer<SoftFaceDevice> SoftFaceDevicePtr;

}  // namespace Kiran