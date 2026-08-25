/**
 * Copyright (c) 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author:     yangfeng <yangfeng@kylinsec.com.cn>
 */

#pragma once

#include <QFutureWatcher>
#include "device.h"
#include "driver-i.h"

namespace Kiran
{
// 驱动调用结果:由工作线程经 QFuture 返回,不在工作线程中直写设备成员
struct FaceEnrollResult
{
    int ret = -1;
    std::vector<uint8_t> feature;
    std::string featureID;
};

struct FaceIdentifyResult
{
    int ret = -1;
    std::string featureID;
};

// 本地人脸识别设备(DEVICE_TYPE_FACE)
// 区别于软人脸(SoftFaceDevice,ks-authhub 远端比对方案)
class FaceDevice : public Device
{
    Q_OBJECT
public:
    FaceDevice(DriverPtr driver, QObject *parent = nullptr);
    ~FaceDevice();

    DeviceType deviceType() override;
    void doEnrollStart(const QString &extraInfo) override;
    void EnrollStop() override;
    void doIdentifyStart(const QString &extraInfo) override;
    void IdentifyStop() override;
    QStringList GetFeatureIDList() override;
    void IdentifyResultPostProcess(const QString &extraInfo) override;

private:
    FaceDriverPtr m_driver;
    QFutureWatcher<FaceEnrollResult> m_enrollWatcher;
    QFutureWatcher<FaceIdentifyResult> m_identifyWatcher;
    bool m_enrollStopRequested{false};
    bool m_identifyStopRequested{false};
};

typedef QSharedPointer<FaceDevice> FaceDevicePtr;

}  // namespace Kiran
