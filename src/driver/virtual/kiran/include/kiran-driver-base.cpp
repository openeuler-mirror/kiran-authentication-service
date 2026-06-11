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
#include <QCoreApplication>
#include <QDBusInterface>
#include <QDBusReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QSettings>
#include <QTranslator>

#include "config.h"
#include "kiran-define.h"
#include "kiran-driver-base.h"

KiranDriverBase::KiranDriverBase(QObject *parent)
    : m_parent(parent), m_iface(nullptr), m_searchTimeOut(0), m_personIDLast(0), m_ifaceInitialized(false)
{
    loadConfig();
}

QString KiranDriverBase::dbusCall(QString method, QString args)
{
    QDBusInterface *iface = getBusInterface();
    if (!iface || !iface->isValid())
    {
        QJsonObject jsonObj;
        jsonObj.insert("code", KIRAN_ERROR_SERVER_RETURN_ERROR);
        QJsonDocument jsonDoc(jsonObj);
        KLOG_ERROR() << "Kiran D-Bus interface invalid";
        return jsonDoc.toJson();
    }

    KLOG_INFO() << "Kiran DBus call:" << method << args;
    QDBusReply<QString> reply = iface->call(method, args);
    if (reply.isValid())
    {
        return reply.value();
    }
    else
    {
        KLOG_ERROR() << "Kiran D-Bus call failed:" << reply.error().message().toLocal8Bit();
        QJsonObject jsonObj;
        jsonObj.insert("code", KIRAN_ERROR_SERVER_RETURN_ERROR);
        jsonObj.insert("error_msg", reply.error().message());
        QJsonDocument jsonDoc(jsonObj);
        return jsonDoc.toJson();
    }
}

int KiranDriverBase::startLeaveDetect(const QString &osUser)
{
    QJsonObject jsonObj;
    jsonObj.insert("business_id", KIRAN_BUSINESS_ID);
    jsonObj.insert("person_id", m_personIDLast);
    jsonObj.insert("os_user", osUser);
    // C7: 禁止插入 detect_time_out 字段
    QJsonDocument jsonDoc(jsonObj);

    auto reply = dbusCall("StartLeaveDetect", jsonDoc.toJson());
    KLOG_INFO() << "Kiran StartLeaveDetect reply:" << reply;
    jsonDoc = QJsonDocument::fromJson(reply.toLatin1());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    if (error_code != KIRAN_SUCCESS)
    {
        KLOG_ERROR() << "Kiran StartLeaveDetect failed:" << error_code << jsonObj;
        return error_code;
    }
    else
    {
        QString error_msg = jsonObj.value("error_msg").toString();
        KLOG_INFO() << "Kiran StartLeaveDetect success:" << error_code << error_msg << jsonObj;
        return error_code;
    }
}

int KiranDriverBase::reportLoginLog(QJsonObject &jsonObj)
{
    jsonObj.insert("business_id", KIRAN_BUSINESS_ID);
    jsonObj.insert("person_id", m_personIDLast);

    QJsonDocument jsonDoc(jsonObj);
    QString reply = dbusCall("ReportLoginLog", jsonDoc.toJson());
    KLOG_INFO() << "Kiran ReportLoginLog reply:" << reply;
    if (reply.isEmpty())
    {
        KLOG_ERROR() << "Kiran ReportLoginLog D-Bus call failed";
        return -1;
    }

    QJsonDocument replyDoc = QJsonDocument::fromJson(reply.toLatin1());
    QJsonObject replyObj = replyDoc.object();
    int error_code = replyObj.value("code").toInt();

    if (error_code != KIRAN_SUCCESS)
    {
        QString error_msg = replyObj.value("error_msg").toString();
        KLOG_ERROR() << "Kiran ReportLoginLog failed:" << error_code << error_msg;
        return error_code;
    }
    else
    {
        KLOG_INFO() << "Kiran ReportLoginLog success:" << replyObj;
        return KIRAN_SUCCESS;
    }
}

QDBusInterface *KiranDriverBase::getBusInterface()
{
    if (!m_iface || !m_iface->isValid())
    {
        if (m_iface)
        {
            delete m_iface;
            m_iface = nullptr;
        }
        m_iface = new QDBusInterface(KIRAN_DBUS_INTERFACE, KIRAN_DBUS_PATH, KIRAN_DBUS_INTERFACE,
                                     QDBusConnection::systemBus(), m_parent);
        m_ifaceInitialized = true;
    }
    return m_iface;
}

void KiranDriverBase::loadTranslator(const QString &translatorName)
{
    static QTranslator translator;
    if (!translator.load(QLocale(), translatorName, ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        KLOG_INFO() << "Kiran: Load translator failed:" << translatorName;
    }
    else
    {
        QCoreApplication::installTranslator(&translator);
    }
}

void KiranDriverBase::loadConfig()
{
    KLOG_INFO() << "KiranDriver config file:" << VIRTUAL_KIRAN_DRIVER_CONFIG_FILE;
    QSettings settings(VIRTUAL_KIRAN_DRIVER_CONFIG_FILE, QSettings::IniFormat);
    m_searchTimeOut = settings.value(KIRAN_CONFIG_KEY_SEARCH_TIME_OUT).toInt();
    KLOG_INFO() << "KiranDriver config: business_id:" << KIRAN_BUSINESS_ID << "search_time_out:" << m_searchTimeOut;
}
