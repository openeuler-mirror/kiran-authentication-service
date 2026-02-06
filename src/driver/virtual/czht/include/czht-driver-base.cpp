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
#include <QCoreApplication>
#include <QDBusInterface>
#include <QDBusReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QSettings>
#include <QTranslator>

#include "config.h"
#include "czht-define.h"
#include "czht-driver-base.h"

CZHTDriverBase::CZHTDriverBase(QObject *parent)
    : m_parent(parent), m_iface(nullptr), m_detectTimeOut(0), m_searchTimeOut(0), m_personIDLast(0), m_ifaceInitialized(false)
{
    // 自动加载配置
    loadConfig();
}

QString CZHTDriverBase::dbusCall(QString method, QString args)
{
    QDBusInterface *iface = getBusInterface();
    if (!iface || !iface->isValid())
    {
        QJsonObject jsonObj;
        jsonObj.insert("code", CZHT_ERROR_DAEMON_NOT_RUNNING);
        QJsonDocument jsonDoc(jsonObj);
        KLOG_ERROR() << "D-Bus interface invalid";
        return jsonDoc.toJson();
    }

    KLOG_INFO() << "DBus call:" << method << args;
    QDBusReply<QString> reply = iface->call(method, args);
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

int CZHTDriverBase::startLeaveDetect(const QString &osUser)
{
    QJsonObject jsonObj;
    jsonObj.insert("business_id", BUSINESS_ID);
    jsonObj.insert("person_id", m_personIDLast);
    jsonObj.insert("os_user", osUser);
    jsonObj.insert("detect_time_out", m_detectTimeOut);
    QJsonDocument jsonDoc(jsonObj);

    auto reply = dbusCall("StartLeaveDetect", jsonDoc.toJson());
    jsonDoc = QJsonDocument::fromJson(reply.toUtf8());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    if (error_code != CZHT_SUCCESS)
    {
        KLOG_ERROR() << "DBus call failed:" << error_code << jsonObj;
        return error_code;
    }
    else
    {
        QString error_msg = jsonObj.value("error_msg").toString();
        KLOG_INFO() << "Reply from service:" << error_code << error_msg << jsonObj;
        return error_code;
    }
}

int CZHTDriverBase::reportLoginLog(QJsonObject &jsonObj)
{
    jsonObj.insert("business_id", BUSINESS_ID);
    jsonObj.insert("person_id", m_personIDLast);

    QJsonDocument jsonDoc(jsonObj);
    QString reply = dbusCall("ReportLoginLog", jsonDoc.toJson());

    if (reply.isEmpty())
    {
        KLOG_ERROR() << "ReportLoginLog D-Bus call failed";
        return -1;
    }

    QJsonDocument replyDoc = QJsonDocument::fromJson(reply.toUtf8());
    QJsonObject replyObj = replyDoc.object();
    int error_code = replyObj.value("code").toInt();

    if (error_code != CZHT_SUCCESS)
    {
        QString error_msg = replyObj.value("error_msg").toString();
        KLOG_ERROR() << "ReportLoginLog failed:" << error_code << error_msg;
        return error_code;
    }
    else
    {
        KLOG_INFO() << "ReportLoginLog success:" << replyObj;
        return CZHT_SUCCESS;
    }
}

QDBusInterface *CZHTDriverBase::getBusInterface()
{
    if (!m_iface || !m_iface->isValid())
    {
        if (m_iface)
        {
            delete m_iface;
            m_iface = nullptr;
        }
        m_iface = new QDBusInterface(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE,
                                     QDBusConnection::systemBus(), m_parent);
        m_ifaceInitialized = true;
    }
    return m_iface;
}

void CZHTDriverBase::loadTranslator(const QString &translatorName)
{
    static QTranslator translator;
    if (!translator.load(QLocale(), translatorName, ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        KLOG_INFO() << "Load translator failed!";
    }
    else
    {
        QCoreApplication::installTranslator(&translator);
    }
}

void CZHTDriverBase::loadConfig()
{
    KLOG_INFO() << "CZHTDriver config file:" << VIRTUAL_CZHT_DRIVER_CONFIG_FILE;
    QSettings settings(VIRTUAL_CZHT_DRIVER_CONFIG_FILE, QSettings::IniFormat);
    m_detectTimeOut = settings.value(CZHT_CONFIG_KEY_DETECT_TIME_OUT).toInt();
    m_searchTimeOut = settings.value(CZHT_CONFIG_KEY_SEARCH_TIME_OUT).toInt();
    KLOG_INFO() << "CZHTDriver config: business_id:" << BUSINESS_ID << "search_time_out:" << m_searchTimeOut << "detect_time_out:" << m_detectTimeOut;
}
