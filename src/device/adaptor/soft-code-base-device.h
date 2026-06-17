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
class SoftCodeBaseDevice : public Device
{
    Q_OBJECT
public:
    /**
     * @brief 构造软验证码设备
     * @param driver 底层 SoftCodeDriver 智能指针
     * @param parent 父 QObject，可为空
     */
    SoftCodeBaseDevice(DriverPtr driver, QObject *parent = nullptr);

    ~SoftCodeBaseDevice();

    /**
     * @brief 启动录入流程
     * @param extraInfo 附加信息（JSON 字符串）
     */
    void doEnrollStart(const QString &extraInfo) override;

    /**
     * @brief 停止录入流程
     */
    void EnrollStop() override;

    /**
     * @brief 启动识别（认证）流程
     * @param extraInfo 附加信息（JSON 字符串）
     */
    void doIdentifyStart(const QString &extraInfo) override;

    /**
     * @brief 停止识别流程
     */
    void IdentifyStop() override;

    /**
     * @brief 获取已录入的特征 ID 列表
     * @return 特征 ID 字符串列表
     */
    QStringList GetFeatureIDList() override;

    /**
     * @brief 识别结果后处理（无论成功失败）
     * @param extraInfo 附加信息（JSON 字符串）
     */
    void IdentifyResultPostProcess(const QString &extraInfo) override;

    /**
     * @brief 获取设备类型
     *
     * 子类需返回 DRIVER_TYPE_SOFT(deviceType()) + SoftDeviceType(softDeviceType())
     * 来区分具体类型。
     *
     * @return DeviceType 枚举值
     */
    virtual DeviceType deviceType() = 0;

protected:
    /** 软验证码驱动智能指针 */
    SoftCodeDriverPtr m_driver;
    /** 异步识别 FutureWatcher */
    QFutureWatcher<int> m_identifyWatcher;
    /** 识别是否被请求停止 */
    bool m_identifyStopRequested{false};
};

}  // namespace Kiran
