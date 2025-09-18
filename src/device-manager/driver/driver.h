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

#include <QFutureWatcher>
#include <QObject>
#include <QSharedPointer>

// 设备类型
enum DriverType
{
    DRIVER_TYPE_FingerPrint,  // 指纹
    DRIVER_TYPE_Face,         // 人脸
    DRIVER_TYPE_FingerVein,   // 指静脉
    DRIVER_TYPE_Iris,         // 虹膜
    DRIVER_TYPE_VoicePrint,   // 声纹
    DRIVER_TYPE_UKey,         // ukey
    DRIVER_TYPE_Virtual
};

inline QString getDriverTypeStr(DriverType type)
{
    static const QMap<DriverType, QString> driverTypeMap = {
        {DRIVER_TYPE_FingerPrint, "FingerPrint"},
        {DRIVER_TYPE_Face, "Face"},
        {DRIVER_TYPE_FingerVein, "FingerVein"},
        {DRIVER_TYPE_Iris, "Iris"},
        {DRIVER_TYPE_VoicePrint, "VoicePrint"},
        {DRIVER_TYPE_UKey, "UKey"},
        {DRIVER_TYPE_Virtual, "Virtual"}};

    if (driverTypeMap.contains(type))
        return driverTypeMap.value(type);
    else
    {
        qWarning() << "Unknown driver type:" << static_cast<int>(type);
        return "Unknown";
    }
}

class Driver : public QObject
{
    Q_OBJECT
public:
    Driver(QObject* parent = nullptr) : QObject(parent) {};
    virtual ~Driver() = default;

    virtual QString getDriverName() = 0;
    virtual QString getErrorMsg(int errorNum) = 0;
    virtual DriverType getType() = 0;
};
typedef QSharedPointer<Driver> DriverPtr;
typedef Driver* (*CreateDriverFunc)();
