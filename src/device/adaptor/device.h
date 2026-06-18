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

#include <QDBusContext>
#include <QDBusObjectPath>
#include <QDBusServiceWatcher>
#include <QFutureWatcher>
#include <QObject>
#include <QSharedPointer>

#include "driver-i.h"
#include "kas-authentication-i.h"
#include "lib/feature-data.h"  // for dbus xml

class AuthDeviceAdaptor;

namespace Kiran
{
typedef void *Handle;

class Device : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_PROPERTY(QString DeviceID READ deviceID CONSTANT)
    Q_PROPERTY(QString DeviceDriver READ driverName CONSTANT)
    Q_PROPERTY(int DeviceType READ deviceType)
    Q_PROPERTY(int SoftDeviceType READ softDeviceType)
    Q_PROPERTY(int DeviceStatus READ deviceStatus)
public:
    /**
     * @brief 构造设备对象
     * @param driver 底层驱动智能指针
     * @param parent 父 QObject，可为空
     */
    explicit Device(DriverPtr driver, QObject *parent = nullptr);

    virtual ~Device();

    /**
     * @brief 获取设备类型
     * @return DeviceType 枚举值
     */
    virtual DeviceType deviceType() = 0;

    /**
     * @brief 获取软设备子类型
     *
     * 仅当 deviceType() 返回 DEVICE_TYPE_SOFT 时有效。
     * 物理设备无需重写，默认返回 SOFT_DEVICE_TYPE_NONE。
     *
     * @return SoftDeviceType 枚举值
     */
    virtual SoftDeviceType softDeviceType()
    {
        return SOFT_DEVICE_TYPE_NONE;
    }

    /** @brief 获取驱动名称 */
    QString driverName() { return QString::fromStdString(m_driver->getDriverName()); }

    /** @brief 获取 DBus 对象路径 */
    QDBusObjectPath getObjectPath() { return m_objectPath; };

    /** @brief 获取设备唯一标识（UUID） */
    QString deviceID() { return m_devId; };

    /**
     * @brief 启动录入流程（D-Bus 入口）
     *
     * 自动监控调用方服务，异常断连时触发 Stop。
     *
     * @param extraInfo 附加信息（JSON 字符串）
     */
    void EnrollStart(const QString &extraInfo);

    /**
     * @brief 停止录入流程（D-Bus 入口）
     */
    virtual void EnrollStop() = 0;

    /**
     * @brief 启动识别/认证流程（D-Bus 入口）
     *
     * 自动监控调用方服务，异常断连时触发 Stop。
     *
     * @param extraInfo 附加信息（JSON 字符串）
     */
    void IdentifyStart(const QString &extraInfo);

    /**
     * @brief 停止识别流程（D-Bus 入口）
     */
    virtual void IdentifyStop() = 0;

    /**
     * @brief 获取已录入的特征 ID 列表
     * @return 特征 ID 字符串列表
     */
    virtual QStringList GetFeatureIDList() = 0;

protected:
    /**
     * @brief 启动录入流程（子类实现）
     * @param extraInfo 附加信息（JSON 字符串）
     */
    virtual void doEnrollStart(const QString &extraInfo) = 0;

    /**
     * @brief 启动识别/认证流程（子类实现）
     * @param extraInfo 附加信息（JSON 字符串）
     */
    virtual void doIdentifyStart(const QString &extraInfo) = 0;

public:
    /** @brief 获取当前设备状态 */
    int deviceStatus() { return m_status; };

    /**
     * @brief 识别结果后处理（无论成功失败）
     *
     * 子类可重写以实现日志上报、人走监测等后处理逻辑。
     *
     * @param extraInfo 附加信息（JSON 字符串）
     */
    virtual void IdentifyResultPostProcess(const QString &extraInfo) {};

    // signals:
    //     void identifyStatus(IdentifyStatus status, QString msg);
    //     void enrollStatus(EnrollStatus status, QString msg);

private:
    void registerDBusObject();
    void initServiceWatcher();
private Q_SLOTS:
    void onNameLost(const QString &serviceName);

public:
    /** 设备唯一标识（UUID） */
    QString m_devId;
    /** 底层驱动智能指针 */
    DriverPtr m_driver;
    /** 设备状态，参见 DeviceStatusx */
    int m_status;

    QSharedPointer<AuthDeviceAdaptor> m_dbusAdaptor;
    /** DBus 注册对象路径 */
    QDBusObjectPath m_objectPath;
    QSharedPointer<QDBusServiceWatcher> m_serviceWatcher;
};

/** 设备对象智能指针类型 */
typedef QSharedPointer<Device> DevicePtr;

}  // namespace Kiran