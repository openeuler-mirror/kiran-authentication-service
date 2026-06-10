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

#include <QDBusInterface>
#include <QJsonObject>
#include <QObject>
#include <QString>

/**
 * @brief Kiran 人脸驱动基类
 *
 * 与 CZHTDriverBase 功能对等，但 D-Bus 目标为 com.kiran.face.service。
 * startLeaveDetect() 不插入 detect_time_out 字段（C7），
 * 人走判定超时仅由 kiran-face-dbus-service 侧的 ini [leave_detect] 控制。
 */
class KiranDriverBase
{
public:
    KiranDriverBase(QObject *parent = nullptr);
    virtual ~KiranDriverBase() = default;

protected:
    QDBusInterface *m_iface;
    int m_searchTimeOut;
    int m_personIDLast = 0;

    /** D-Bus 调用（子类可覆盖） */
    virtual QString dbusCall(QString method, QString args);

    /**
     * @brief 启动人走监测
     * @param osUser 当前登录的系统用户名
     * @return 0 成功，非 0 失败
     * @note C7：不插入 detect_time_out 字段
     */
    int startLeaveDetect(const QString &osUser);

    /** 上报登录日志（子类可覆盖） */
    virtual int reportLoginLog(QJsonObject &jsonObj);

    /** 获取 D-Bus 接口（延迟初始化，子类可覆盖） */
    virtual QDBusInterface *getBusInterface();

    /** 加载翻译器 */
    void loadTranslator(const QString &translatorName);

private:
    /** 加载配置 */
    void loadConfig();

protected:
    QObject *m_parent;
    bool m_ifaceInitialized;
};
