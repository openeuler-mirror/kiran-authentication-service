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

#include <QObject>
#include <QSharedPointer>

#include "czht-driver-base.h"
#include "src/device-manager/driver/virtual-code-driver.h"

class CZHTCodeNoCameraDriver : public VirtualCodeDriver, public CZHTDriverBase
{
    Q_OBJECT
public:
    explicit CZHTCodeNoCameraDriver(QObject *parent = nullptr);
    ~CZHTCodeNoCameraDriver();

    QString getDriverName() override;
    DriverType getType() override;
    QString getErrorMsg(int errorNum) override;

    int identify(const QString &extraInfo) override;
    void identifyResultPostProcess(const QString &extraInfo) override;

private:
    int verifyAuthorizationCode(const QString &extraInfo);
};
typedef QSharedPointer<CZHTCodeNoCameraDriver> CZHTCodeNoCameraDriverPtr;
extern "C" Driver *
createDriver();
