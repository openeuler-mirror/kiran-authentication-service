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

#include "physical-driver.h"

class UKeyDriver : public PhysicalDriver
{
public:
    UKeyDriver(QObject *parent = nullptr) : PhysicalDriver(parent) {};
    virtual ~UKeyDriver() = default;

    // 获取在线设备序列号。由于私钥存储在设备内，所以调用接口必须指定序列号。
    // 或者每次接口调用都遍历当前连接的所有设备，每个都尝试调用
    // 如果插入多个相同设备，用户不知道是用的是哪个设备
    virtual QStringList getOnlineSerials() = 0;
    virtual int enroll(const QString &pin, QByteArray &pubKey, const QString &serialNumber) = 0;
    virtual int identify(const QString &pin, const QByteArray &pubKey, const QString &serialNumber) = 0;
};
typedef QSharedPointer<UKeyDriver> UKeyDriverPtr;
