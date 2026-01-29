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

class QDBusInterface;

class LeaveDetecter : public QObject
{
    Q_OBJECT
public:
    explicit LeaveDetecter(QObject *parent = nullptr);
    ~LeaveDetecter();

private slots:
    void onLeaveDetected(QString info);
    void onScreenLockChanged(bool active);

private:
    void lockScreen();
    void stopLeaveDetect();
    QDBusInterface *getBusInterface();
    QString dbusCall(QString method, QString args);

    QDBusInterface *m_iface;
};
