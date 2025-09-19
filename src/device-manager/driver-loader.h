

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

#include "driver/driver.h"

namespace Kiran
{
struct PhysicalDriverInfo
{
    // 驱动
    QString driverPath;
    // 驱动名称
    QString name;
    // 驱动类型
    int type;
    // 支持的设备信息
    QVector<QPair<QString, QString>> vidPids;
};

class DriverLoader : public QObject
{
    Q_OBJECT
public:
    DriverLoader(QObject *parent = nullptr);
    ~DriverLoader();

    void init();

    DriverPtr loadDriver(const QString &driverName);

    QMap<QString, QVector<QPair<QString, QString>>> getPhysicalSupportDevices() { return m_physicalSupportDevices; };  // 获取物理设备支持信息
    QStringList getVirualDrivers() { return m_virtualDrivers; };                                                       // 获取虚拟设备驱动信息
    QMap<QString, PhysicalDriverInfo> getPhysicalDriverInfos() { return m_physicalDriverInfos; };                      // 获取物理设备驱动信息

    QStringList m_virtualDrivers;
    QMap<QString, QVector<QPair<QString, QString>>> m_physicalSupportDevices;
    QMap<QString, PhysicalDriverInfo> m_physicalDriverInfos;
};
}  // namespace Kiran