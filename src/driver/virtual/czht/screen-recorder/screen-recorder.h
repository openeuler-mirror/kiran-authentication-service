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
#include <QHash>
#include <QString>

class ScreenRecorder : public QObject
{
    Q_OBJECT
public:
    explicit ScreenRecorder(QObject *parent = nullptr);
    ~ScreenRecorder();

    void start(const QString &fileName);
    void stop();

private:
    void ensureSessionBusConnected(const QString &fileName);
    void startUserLockMonitor(const QString &userName, const QString &busAddress);

    // 尝试使用指定的编码器进行录屏
    bool tryCodec(const QString &codec, const QStringList &extraArgs, 
                  const QString &resolution, const QString &display,
                  const QString &outputFile);
    
    QProcess m_process;
    QHash<QString, QProcess *> m_lockMonitors;
};