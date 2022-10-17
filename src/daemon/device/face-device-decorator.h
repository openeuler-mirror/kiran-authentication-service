/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd. 
 * kiran-session-manager is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2. 
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2 
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, 
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, 
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.  
 * See the Mulan PSL v2 for more details.  
 * 
 * Author:     tangjie02 <tangjie02@kylinos.com.cn>
 */

#pragma once

#include "src/daemon/device/device-decorator.h"
#include "src/daemon/device/device-request-dispatcher.h"

namespace Kiran
{
class FaceDeviceDecorator : public DeviceDecorator,
                            public DeviceRequestListener
{
public:
    virtual QString getListenerName() { return QStringLiteral("FaceDeviceDecorator"); };
    // 处理请求
    virtual void process(QSharedPointer<DeviceRequest> request);
};

}  // namespace Kiran
