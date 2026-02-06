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

#include <QDBusInterface>
#include <QJsonObject>
#include <QObject>
#include <QString>

class CZHTDriverBase
{
public:
    CZHTDriverBase(QObject *parent = nullptr);
    virtual ~CZHTDriverBase() = default;

protected:
    // 公共成员变量
    QDBusInterface *m_iface;
    int m_detectTimeOut;
    int m_searchTimeOut;
    int m_personIDLast;

    // D-Bus 调用（子类可覆盖）
    virtual QString dbusCall(QString method, QString args);

    // 启动人走监测（公共方法）
    int startLeaveDetect(const QString &osUser);

    // 上报登录日志（子类可覆盖）
    virtual int reportLoginLog(QJsonObject &jsonObj);

    // 获取 D-Bus 接口（延迟初始化，子类可覆盖）
    virtual QDBusInterface *getBusInterface();

    // 加载翻译器（辅助方法）
    void loadTranslator(const QString &translatorName);

private:
    // 加载配置（私有方法，构造函数中自动调用）
    void loadConfig();

protected:
    QObject *m_parent;        // 保存父对象指针，用于创建 QDBusInterface
    bool m_ifaceInitialized;  // 标记接口是否已初始化
};
