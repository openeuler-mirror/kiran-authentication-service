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

#include <qt5-log-i.h>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>

#include "config.h"
#include "czht-define.h"
#include "leave-detecter.h"

LeaveDetecter::LeaveDetecter(QObject *parent)
    : QObject(parent), m_iface(nullptr)
{
    // 连接系统总线上的 LeaveDetected 信号
    QDBusConnection systemBus = QDBusConnection::systemBus();
    bool ret = systemBus.connect(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE,
                                 "LeaveDetected", this, SLOT(onLeaveDetected(QString)));
    KLOG_INFO() << "Connect to systemBus signal com.czht.face.daemon.LeaveDetected:" << ret;

    // 连接会话总线上的 ActiveChanged 信号
    QDBusConnection sessionBus = QDBusConnection::sessionBus();
    ret = sessionBus.connect("com.kylinsec.Kiran.ScreenSaver",
                             "/com/kylinsec/Kiran/ScreenSaver",
                             "com.kylinsec.Kiran.ScreenSaver", "ActiveChanged",
                             this, SLOT(onScreenLockChanged(bool)));
    KLOG_INFO() << "Connect to sessionBus signal com.kylinsec.Kiran.ScreenSaver.ActiveChanged:" << ret;

    ret = sessionBus.connect("org.gnome.ScreenSaver",
                             "/org/gnome/ScreenSaver",
                             "org.gnome.ScreenSaver", "ActiveChanged",
                             this, SLOT(onScreenLockChanged(bool)));
    KLOG_INFO() << "Connect to sessionBus signal org.gnome.ScreenSaver.ActiveChanged:" << ret;
}

LeaveDetecter::~LeaveDetecter()
{
    // 程序退出前停止人走监测
    stopLeaveDetect();

    // 断开系统总线上的信号连接
    QDBusConnection::systemBus().disconnect(
        DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE, "LeaveDetected", this,
        SLOT(onLeaveDetected(QString)));

    // 断开会话总线上的信号连接
    QDBusConnection::sessionBus().disconnect(
        "com.kylinsec.Kiran.ScreenSaver", "/com/kylinsec/Kiran/ScreenSaver",
        "com.kylinsec.Kiran.ScreenSaver", "ActiveChanged", this,
        SLOT(onScreenLockChanged(bool)));
    QDBusConnection::sessionBus().disconnect(
        "org.gnome.ScreenSaver", "/org/gnome/ScreenSaver",
        "org.gnome.ScreenSaver", "ActiveChanged", this,
        SLOT(onScreenLockChanged(bool)));
}

void LeaveDetecter::onLeaveDetected(QString info)
{
    KLOG_INFO() << "Leave detected, locking screen. info:" << info;
    lockScreen();
}

void LeaveDetecter::onScreenLockChanged(bool active)
{
    KLOG_INFO() << "Screen lock changed, active:" << active;
    if (active)
    {
        stopLeaveDetect();
    }
}

/// @brief 检查命令是否存在（使用which命令）
/// @param commandName 要检查的命令名称
/// @return 如果命令存在返回true，否则返回false
static bool commandExists(const QString &commandName)
{
    QProcess process;
    process.start("which", QStringList() << commandName);

    if (!process.waitForFinished(3000))
    {
        return false;
    }

    // which命令成功时返回0，并输出命令的完整路径
    if (process.exitCode() == 0 && process.exitStatus() == QProcess::NormalExit)
    {
        QString output = process.readAllStandardOutput().trimmed();
        // 验证输出不为空且文件确实存在
        return !output.isEmpty();
    }

    return false;
}

/// @brief 尝试执行锁定屏幕命令
/// @param commandName 要执行的命令名称
/// @param arguments 命令参数列表
/// @return 如果成功返回true，否则返回false
static bool tryLockScreen(const QString &commandName, const QStringList &arguments)
{
    QProcess process;
    process.start(commandName, arguments);

    if (!process.waitForStarted(3000))
    {
        KLOG_DEBUG() << commandName << "failed to start";
        return false;
    }

    if (!process.waitForFinished(3000))
    {
        KLOG_WARNING() << commandName << "timeout, killing process";
        process.kill();
        process.waitForFinished(1000);
        return false;
    }

    if (process.exitCode() == 0)
    {
        KLOG_INFO() << "Lock screen using" << commandName << "succeeded";
        return true;
    }
    else
    {
        KLOG_WARNING() << commandName << "failed with exit code:" << process.exitCode();
        return false;
    }
}

void LeaveDetecter::lockScreen()
{
    // 定义锁定屏幕命令及其参数列表（按优先级排序）
    // 格式：{命令名, 参数列表}
    QList<QPair<QString, QStringList>> lockCommands = {
        {"kiran-screensaver-command", QStringList() << "-l"},
        {"gnome-screensaver-command", QStringList() << "-l"}
        // 未来可以添加其他命令，例如：
        // {"test", QStringList() << "-a"},
    };

    for (const auto &commandPair : lockCommands)
    {
        const QString &commandName = commandPair.first;
        const QStringList &arguments = commandPair.second;

        // 先检查命令是否存在，存在再尝试执行
        if (commandExists(commandName))
        {
            if (tryLockScreen(commandName, arguments))
            {
                return;  // 成功锁定，直接返回
            }
            // 命令存在但执行失败，继续尝试下一个
            KLOG_INFO() << commandName << "exists but failed, trying next command";
        }
        else
        {
            KLOG_DEBUG() << commandName << "not found, trying next command";
        }
    }

    // 所有命令都失败
    QStringList commandNames;
    for (const auto &commandPair : lockCommands)
    {
        commandNames << commandPair.first;
    }
    KLOG_ERROR() << "Failed to lock screen: all commands failed or not available ("
                 << commandNames.join(", ") << ")";
}

void LeaveDetecter::stopLeaveDetect()
{
    auto iface = getBusInterface();
    if (!iface->isValid())
    {
        KLOG_ERROR() << "D-Bus interface invalid, cannot stop leave detect";
        return;
    }

    QJsonObject jsonObj;
    jsonObj.insert("business_id", BUSINESS_ID);
    QJsonDocument jsonDoc(jsonObj);

    auto reply = dbusCall("StopLeaveDetect", jsonDoc.toJson());
    jsonDoc = QJsonDocument::fromJson(reply.toUtf8());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    if (error_code != CZHT_SUCCESS)
    {
        KLOG_ERROR() << "DBus call failed:" << error_code << jsonObj;
    }
    else
    {
        KLOG_INFO() << "Reply from service:" << error_code << jsonObj;
    }
}

QDBusInterface *LeaveDetecter::getBusInterface()
{
    if (!m_iface || !m_iface->isValid())
    {
        m_iface = new QDBusInterface(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE,
                                     QDBusConnection::systemBus(), this);
    }
    return m_iface;
}

QString LeaveDetecter::dbusCall(QString method, QString args)
{
    QDBusInterface *iface = getBusInterface();
    if (!iface->isValid())
    {
        QJsonObject jsonObj;
        jsonObj.insert("code", CZHT_ERROR_DAEMON_NOT_RUNNING);
        QJsonDocument jsonDoc(jsonObj);
        KLOG_ERROR() << "D-Bus interface invalid";
        return jsonDoc.toJson();
    }

    KLOG_INFO() << "DBus call:" << method << args;
    QDBusReply<QString> reply = m_iface->call(method, args);
    if (reply.isValid())
    {
        return reply.value();
    }
    else
    {
        KLOG_INFO() << "Call failed:" << reply.error().message().toLocal8Bit();
        return "";
    }
}