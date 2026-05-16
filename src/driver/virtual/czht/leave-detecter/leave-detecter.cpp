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
#include <QCoreApplication>
#include <QProcess>

#include "config.h"
#include "czht-define.h"
#include "leave-detecter.h"

/// @brief 检查指定进程是否正在运行
/// @param processName 要检查的进程名称
/// @return 如果进程存在返回true，否则返回false
static bool isProcessRunning(const QString &processName)
{
    QProcess process;
    process.start("pgrep", QStringList() << "-f" << processName);

    if (!process.waitForFinished(3000))
    {
        return false;
    }

    // pgrep找到进程时返回0，输出匹配的进程ID
    return (process.exitCode() == 0);
}

LeaveDetecter::LeaveDetecter(QObject *parent)
    : QObject(parent), m_iface(nullptr), m_greeterTimer(new QTimer(this))
{
    // 启动定时器定期检测 lightdm-kiran-greeter
    // 用于处理切换用户时，人走检测仍在运行导致的摄像头不可用情况
    // FIXME: 如果两个tty图形，一个锁屏、一个登陆，从锁屏界面进入系统后，人走检测退出
    // 需要调研是否有其他更好的方式来判断切换至登录界面这个动作，而不是通过判断lightdm-kiran-greeter进程是否存在的方式来实现，后续再调研方案，比如给lightdm增加SwtichToGreeter的信号。

    // 现在在lightdm中去掉了切换用户功能
    // 此方案不完善，后续考虑新方案，暂时注释掉
    // m_greeterTimer->setInterval(1000);  // 每秒检测一次
    // connect(m_greeterTimer, &QTimer::timeout, this, &LeaveDetecter::onCheckGreeterTimer);
    // m_greeterTimer->start();
    // KLOG_INFO() << "Start greeter detect timer";

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

    KLOG_INFO() << "LeaveDetecter destroyed";
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

void LeaveDetecter::onCheckGreeterTimer()
{
    // 分为注销、切换用户 两种情况
    // 注销：LeaveDetecter 退出
    // 切换用户：停止人走检测
    //         再次进入当前用户：不会重新拉起之前会话中存在的进程，因此不要停止当前进程，需要重新start m_greeterTimer
    //         进入其他用户：LeaveDetecter 存在两个实例
    //         切换到锁屏界面进入：LeaveDetecter 重新拉起
    
    // 方案不完善，调用已注释，后续考虑新方案
    if (isProcessRunning("lightdm-kiran-greeter"))
    {
        KLOG_INFO() << "lightdm-kiran-greeter is running, stopping leave detect and exiting";
        // 当lightdm-kiran-greeter正在运行，需要停止m_greeterTimer，不然会持续调用stopLeaveDetect
        m_greeterTimer->stop();
        stopLeaveDetect();
    }
    else 
    {
        if (!m_greeterTimer->isActive())
        {
            KLOG_INFO() << "lightdm-kiran-greeter is not running, starting leave detect";
            m_greeterTimer->start();
        }
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
    KLOG_INFO() << "StopLeaveDetect reply:" << reply;
    jsonDoc = QJsonDocument::fromJson(reply.toLatin1());
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