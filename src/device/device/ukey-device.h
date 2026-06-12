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
#include "driver/ukey-driver.h"
#include "lib/feature-data.h"

namespace Kiran
{
class UkeyDevice : public Device
{
    Q_OBJECT
public:
    UkeyDevice(const QString &vid, const QString &pid, DriverPtr driver, QObject *parent = nullptr);
    ~UkeyDevice();

    DeviceType deviceType() override;
    void EnrollStart(const QString &extraInfo) override;
    void EnrollStop() override;
    void IdentifyStart(const QString &extraInfo) override;
    void IdentifyStop() override;
    QStringList GetFeatureIDList() override;

    void notifyEnrollProcess(EnrollProcess process, int error = 0, const FeatureData &fatureData = {});
    void notifyIdentifyProcess(IdentifyProcess process, int error = 0, const QString &featureID = QString());

    QString getPinErrorReson(int error);
    bool isExistBinding(const QString &serialNumber);

public:
    QString m_idVendor;
    QString m_idProduct;

    UKeyDriverPtr m_driver;

    int m_retryCount = 10;
};
typedef QSharedPointer<UkeyDevice> UkeyDevicePtr;
}  // namespace Kiran