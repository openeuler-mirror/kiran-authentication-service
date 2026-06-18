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

#include "soft-code-device.h"

namespace Kiran
{
SoftCodeDevice::SoftCodeDevice(DriverPtr driver, QObject *parent)
    : SoftCodeBaseDevice(driver, parent)
{
}

SoftCodeDevice::~SoftCodeDevice() {}

DeviceType SoftCodeDevice::deviceType()
{
    return DEVICE_TYPE_SOFT;
}

SoftDeviceType SoftCodeDevice::softDeviceType()
{
    return SOFT_DEVICE_TYPE_CODE;
}

}  // namespace Kiran
