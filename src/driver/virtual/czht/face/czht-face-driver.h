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
#include "src/device-manager/driver/virtual-face-driver.h"

class CZHTFaceDriver : public VirtualFaceDriver, public CZHTDriverBase
{
    Q_OBJECT
public:
    explicit CZHTFaceDriver(QObject *parent = nullptr);
    ~CZHTFaceDriver();

    QString getDriverName() override;
    QString getErrorMsg(int errorNum) override;
    DriverType getType() override;

    int identify(const QString &extraInfo) override;
    void identifyResultPostProcess(const QString &extraInfo) override;

private:
    int startSearch(const QString &extraInfo);
};
typedef QSharedPointer<CZHTFaceDriver> CZHTFaceDriverPtr;
extern "C" Driver *
createDriver();
