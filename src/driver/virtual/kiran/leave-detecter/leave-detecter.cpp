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

#include <qt5-log-i.h>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCoreApplication>
#include <QProcess>

#include "config.h"
#include "kiran-define.h"
#include "leave-detecter.h"

static bool isProcessRunning(const QString &processName)
{
    QProcess process;
    process.start("pgrep", QStringList() << "-f" << processName);

    if (!process.waitForFinished(3000))
    {
        return false;
    }

    return (process.exitCode() == 0);
}

LeaveDetecter::LeaveDetecter(QObject *parent)
    : QObject(parent), m_iface(nullptr), m_greeterTimer(new QTimer(this))
{
    // 连接系统总线上的 Kiran LeaveDetected 信号
    QDBusConnection systemBus = QDBusConnection::systemBus();
    bool ret = systemBus.connect(KIRAN_DBUS_INTERFACE, KIRAN_DBUS_PATH, KIRAN_DBUS_INTERFACE,
                                 "LeaveDetected", this, SLOT(onLeaveDetected(QString)));
    KLOG_INFO() << "Connect to systemBus signal com.kiran.face.service.LeaveDetected:" << ret;

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
    stopLeaveDetect();

    QDBusConnection::systemBus().disconnect(
        KIRAN_DBUS_INTERFACE, KIRAN_DBUS_PATH, KIRAN_DBUS_INTERFACE, "LeaveDetected", this,
        SLOT(onLeaveDetected(QString)));

    QDBusConnection::sessionBus().disconnect(
        "com.kylinsec.Kiran.ScreenSaver", "/com/kylinsec/Kiran/ScreenSaver",
        "com.kylinsec.Kiran.ScreenSaver", "ActiveChanged", this,
        SLOT(onScreenLockChanged(bool)));
    QDBusConnection::sessionBus().disconnect(
        "org.gnome.ScreenSaver", "/org/gnome/ScreenSaver",
        "org.gnome.ScreenSaver", "ActiveChanged", this,
        SLOT(onScreenLockChanged(bool)));

    KLOG_INFO() << "Kiran LeaveDetecter destroyed";
}

void LeaveDetecter::onLeaveDetected(QString info)
{
    KLOG_INFO() << "Kiran leave detected, locking screen. info:" << info;
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
    if (isProcessRunning("lightdm-kiran-greeter"))
    {
        KLOG_INFO() << "lightdm-kiran-greeter is running, stopping leave detect and exiting";
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

static bool commandExists(const QString &commandName)
{
    QProcess process;
    process.start("which", QStringList() << commandName);

    if (!process.waitForFinished(3000))
    {
        return false;
    }

    if (process.exitCode() == 0 && process.exitStatus() == QProcess::NormalExit)
    {
        QString output = process.readAllStandardOutput().trimmed();
        return !output.isEmpty();
    }

    return false;
}

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
    QList<QPair<QString, QStringList>> lockCommands = {
        {"kiran-screensaver-command", QStringList() << "-l"},
        {"gnome-screensaver-command", QStringList() << "-l"}
    };

    for (const auto &commandPair : lockCommands)
    {
        const QString &commandName = commandPair.first;
        const QStringList &arguments = commandPair.second;

        if (commandExists(commandName))
        {
            if (tryLockScreen(commandName, arguments))
            {
                return;
            }
            KLOG_INFO() << commandName << "exists but failed, trying next command";
        }
        else
        {
            KLOG_DEBUG() << commandName << "not found, trying next command";
        }
    }

    QStringList commandNames;
    for (const auto &commandPair : lockCommands)
    {
        commandNames << commandPair.first;
    }
    KLOG_ERROR() << "Kiran leave-detecter: Failed to lock screen: all commands failed or not available ("
                 << commandNames.join(", ") << ")";
}

void LeaveDetecter::stopLeaveDetect()
{
    auto iface = getBusInterface();
    if (!iface->isValid())
    {
        KLOG_ERROR() << "Kiran D-Bus interface invalid, cannot stop leave detect";
        return;
    }

    QJsonObject jsonObj;
    jsonObj.insert("business_id", KIRAN_BUSINESS_ID);
    QJsonDocument jsonDoc(jsonObj);

    auto reply = dbusCall("StopLeaveDetect", jsonDoc.toJson());
    KLOG_INFO() << "Kiran StopLeaveDetect reply:" << reply;
    jsonDoc = QJsonDocument::fromJson(reply.toLatin1());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    if (error_code != KIRAN_SUCCESS)
    {
        KLOG_ERROR() << "Kiran StopLeaveDetect failed:" << error_code << jsonObj;
    }
    else
    {
        KLOG_INFO() << "Kiran StopLeaveDetect success:" << jsonObj;
    }
}

QDBusInterface *LeaveDetecter::getBusInterface()
{
    if (!m_iface || !m_iface->isValid())
    {
        m_iface = new QDBusInterface(KIRAN_DBUS_INTERFACE, KIRAN_DBUS_PATH, KIRAN_DBUS_INTERFACE,
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
        jsonObj.insert("code", KIRAN_ERROR_SERVER_RETURN_ERROR);
        QJsonDocument jsonDoc(jsonObj);
        KLOG_ERROR() << "Kiran D-Bus interface invalid";
        return jsonDoc.toJson();
    }

    KLOG_INFO() << "Kiran DBus call:" << method << args;
    QDBusReply<QString> reply = m_iface->call(method, args);
    if (reply.isValid())
    {
        return reply.value();
    }
    else
    {
        KLOG_INFO() << "Kiran D-Bus call failed:" << reply.error().message().toLocal8Bit();
        return "";
    }
}
