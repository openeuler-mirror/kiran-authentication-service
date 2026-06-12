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
#include <QTimer>

class QDBusInterface;

/**
 * @brief Kiran 人走检测守护进程
 *
 * 订阅 com.kiran.face.service 的 LeaveDetected 信号，
 * 收到后执行锁屏操作；同时监听 ScreenSaver ActiveChanged 信号，
 * 锁屏后停止人走检测。
 */
class LeaveDetecter : public QObject
{
    Q_OBJECT
public:
    explicit LeaveDetecter(QObject *parent = nullptr);
    ~LeaveDetecter();

private slots:
    void onLeaveDetected(QString info);
    void onScreenLockChanged(bool active);
    void onCheckGreeterTimer();

private:
    void lockScreen();
    void stopLeaveDetect();
    QDBusInterface *getBusInterface();
    QString dbusCall(QString method, QString args);

    QDBusInterface *m_iface;
    QTimer *m_greeterTimer;
};
