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

#include "virtual-code-no-camera-device.h"

namespace Kiran
{
VirtualCodeNoCameraDevice::VirtualCodeNoCameraDevice(DriverPtr driver, QObject *parent)
    : VirtualCodeBaseDevice(driver, parent)
{
}

VirtualCodeNoCameraDevice::~VirtualCodeNoCameraDevice() {}

DeviceType VirtualCodeNoCameraDevice::deviceType()
{
    return DEVICE_TYPE_Virtual_Code_No_Camera;
}

}  // namespace Kiran
