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
#include <QList>
#include <QObject>
#include <QSharedPointer>

// 设备类型
enum DriverType
{
    // 指纹
    DRIVER_TYPE_FINGERPRINT,
    // 人脸
    DRIVER_TYPE_FACE,
    // 指静脉
    DRIVER_TYPE_FINGERVEIN,
    // 虹膜
    DRIVER_TYPE_IRIS,
    // 声纹
    DRIVER_TYPE_VOICEPRINT,
    // ukey
    DRIVER_TYPE_UKEY,
    // 虚拟人脸
    DRIVER_TYPE_VIRTUAL_FACE,
    // 虚拟验证码
    DRIVER_TYPE_VIRTUAL_CODE,
    // 虚拟验证码（无摄像头）
    DRIVER_TYPE_VIRTUAL_CODE_NO_CAMERA,
};

inline QString getDriverTypeStr(DriverType type)
{
    static const QMap<DriverType, QString> driverTypeMap = {{DRIVER_TYPE_FINGERPRINT, "FingerPrint"},
                                                            {DRIVER_TYPE_FACE, "Face"},
                                                            {DRIVER_TYPE_FINGERVEIN, "FingerVein"},
                                                            {DRIVER_TYPE_IRIS, "Iris"},
                                                            {DRIVER_TYPE_VOICEPRINT, "VoicePrint"},
                                                            {DRIVER_TYPE_UKEY, "UKey"},
                                                            {DRIVER_TYPE_VIRTUAL_FACE, "VirtualFace"},
                                                            {DRIVER_TYPE_VIRTUAL_CODE, "VirtualCode"},
                                                            {DRIVER_TYPE_VIRTUAL_CODE_NO_CAMERA, "VirtualCodeNoCamera"}};

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
public:
    Driver(QObject* parent = nullptr) : QObject(parent){};
    virtual ~Driver() = default;

    virtual QString getDriverName() = 0;
    virtual QString getErrorMsg(int errorNum) = 0;
    virtual DriverType getType() = 0;

    /** 获取驱动支持的外部认证类型列表（KADAuthType 枚举值） */
    virtual QList<int> getSupportedAuthTypes() = 0;
};
typedef QSharedPointer<Driver> DriverPtr;
typedef Driver* (*CreateDriverFunc)();
