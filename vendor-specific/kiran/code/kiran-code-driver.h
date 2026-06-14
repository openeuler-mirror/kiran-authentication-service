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
 *
 * Author:     licheng <licheng@kylinsec.com.cn>
 */

#pragma once

#include <QObject>
#include <QProcess>
#include <QSharedPointer>

#include "kiran-driver-base.h"
#include "driver-i.h"

class KiranCodeDriver : public QObject, public VirtualCodeDriver, public KiranDriverBase
{
    Q_OBJECT
public:
    explicit KiranCodeDriver(QObject *parent = nullptr);
    ~KiranCodeDriver();

    std::string getDriverName() override;
    std::string getErrorMsg(int errorNum) override;
    DriverType getType() override;

    int identify(const std::string &extraInfo) override;
    void identifyResultPostProcess(const std::string &extraInfo) override;

    std::vector<int> getSupportedAuthTypes() override;

    int verifyAuthorizationCode(const QString &extraInfo);

private:
    bool m_enableScreenRecorder;
};
typedef QSharedPointer<KiranCodeDriver> KiranCodeDriverPtr;
extern "C" Driver *
createDriver();
