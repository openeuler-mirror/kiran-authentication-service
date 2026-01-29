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
#include <QProcess>
#include <QSharedPointer>

#include "src/device-manager/driver/virtual-code-driver.h"

class QDBusInterface;
class CZHTCodeDriver : public VirtualCodeDriver
{
    Q_OBJECT
public:
    explicit CZHTCodeDriver(QObject *parent = nullptr);
    ~CZHTCodeDriver();

    QString getDriverName() override;
    QString getErrorMsg(int errorNum) override;
    DriverType getType() override;

    int identify(const QString &extraInfo) override;
    void identifySuccessedPostProcess(const QString &extraInfo) override;

private:
    QString dbusCall(QString method, QString args);

    int verifyAuthorizationCode(const QString &extraInfo);
    int startLeaveDetect(const QString &extraInfo);

private:
    QDBusInterface *m_iface;

    // 人走监测超时时间
    int m_detectTimeOut;
    // 记录上一次识别的人名
    int m_personIDLast;
};
typedef QSharedPointer<CZHTCodeDriver> CZHTCodeDriverPtr;
extern "C" Driver *
createDriver();
