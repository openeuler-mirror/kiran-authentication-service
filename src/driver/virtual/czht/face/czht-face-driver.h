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

#include "src/device-manager/driver/virtual-face-driver.h"

class QDBusInterface;
class CZHTFaceDriver : public VirtualFaceDriver
{
    Q_OBJECT
public:
    explicit CZHTFaceDriver(QObject *parent = nullptr);
    ~CZHTFaceDriver();

    QString getDriverName() override;
    QString getErrorMsg(int errorNum) override;
    DriverType getType() override;

    int identify(const QString &extraInfo) override;
    void identifySuccessedPostProcess(const QString &extraInfo) override;

private:
    QDBusInterface *getBusInterface();

    QString dbusCall(QString method, QString args);

    int startSearch(const QString &extraInfo);
    int startLeaveDetect(const QString &extraInfo);
    int stopLeaveDetect();

    // 处理锁屏信号连接与否
    void handleScreenLockSignal(bool connect = true);

private slots:
    void leaveDetected(QString info);
    void screenLockChanged(bool active);

private:
    QDBusInterface *m_iface;

    // 业务ID
    QString m_businessID;
    // 人脸搜索超时时间
    int m_searchTimeOut;
    // 人走监测超时时间
    int m_detectTimeOut;
    // 记录上一次识别的人名
    int m_personIDLast;
};
typedef QSharedPointer<CZHTFaceDriver> CZHTFaceDriverPtr;
extern "C" Driver *
createDriver();
