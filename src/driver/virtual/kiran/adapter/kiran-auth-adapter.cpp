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

#include "kiran-auth-adapter.h"

#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusMessage>
#include <QDBusReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

#include "auth-manager.h"
#include "src/driver/virtual/kiran/include/kiran-define.h"
#include "kas-authentication-i.h"
#include "qt5-log-i.h"

bool KiranAuthAdapter::isAvailable()
{
    // 仅检查 VIRTUAL_FACE 和 VIRTUAL_CODE（不支持 VIRTUAL_CODE_NO_CAMERA）
    auto *mgr = Kiran::AuthManager::getInstance();
    if (!mgr)
    {
        return false;
    }

    QString virtualFaceDevices = mgr->GetDevicesForType(KAD_AUTH_TYPE_VIRTUAL_FACE);
    QString virtualCodeDevices = mgr->GetDevicesForType(KAD_AUTH_TYPE_VIRTUAL_CODE);

    bool hasVirtualFaceDevice = !virtualFaceDevices.isEmpty();
    bool hasVirtualCodeDevice = !virtualCodeDevices.isEmpty();

    if (!hasVirtualFaceDevice && !hasVirtualCodeDevice)
    {
        return false;
    }

    // 检查 Kiran D-Bus 服务是否存在
    static const QString KIRAN_DBUS_SERVICE = QStringLiteral(KIRAN_DBUS_INTERFACE);
    if (!QDBusConnection::systemBus().interface()->isServiceRegistered(KIRAN_DBUS_SERVICE))
    {
        return false;
    }

    return true;
}

QList<int> KiranAuthAdapter::getAuthTypes()
{
    QList<int> authTypes;

    static const QString KIRAN_DBUS_SERVICE = QStringLiteral(KIRAN_DBUS_INTERFACE);
    static const QString KIRAN_DBUS_OBJ_PATH = QStringLiteral(KIRAN_DBUS_PATH);
    static const QString KIRAN_METHOD_GET_WORK_MODE = QStringLiteral("GetWorkMode");

    QDBusMessage message = QDBusMessage::createMethodCall(KIRAN_DBUS_SERVICE,
                                                          KIRAN_DBUS_OBJ_PATH,
                                                          KIRAN_DBUS_SERVICE,
                                                          KIRAN_METHOD_GET_WORK_MODE);
    QDBusReply<QString> reply = QDBusConnection::systemBus().call(message);
    if (!reply.isValid())
    {
        KLOG_WARNING() << "Failed to call Kiran GetWorkMode:" << reply.error().message();
        return authTypes;
    }
    KLOG_INFO() << "GetWorkMode from" << KIRAN_DBUS_SERVICE << ", reply:" << reply.value();

    QString jsonStr = reply.value();
    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonStr.toUtf8(), &parseError);

    if (parseError.error != QJsonParseError::NoError)
    {
        KLOG_WARNING() << "Failed to parse Kiran GetWorkMode JSON:" << parseError.errorString();
        return authTypes;
    }

    QJsonObject jsonObj = jsonDoc.object();
    int code = jsonObj.value("code").toInt(-1);
    if (code != 0)
    {
        KLOG_WARNING() << "Kiran GetWorkMode returned error code:" << code;
        return authTypes;
    }

    int workMode = jsonObj.value("work_mode").toInt(-1);
    KLOG_INFO() << "Kiran GetWorkMode, work_mode:" << workMode;

    // 位判断映射（C5）
    if (workMode & KIRAN_WORK_MODE_FACE)
    {
        authTypes << KAD_AUTH_TYPE_VIRTUAL_FACE;
    }
    if (workMode & KIRAN_WORK_MODE_PASSWORD)
    {
        authTypes << KAD_AUTH_TYPE_PASSWORD;
    }
    if (workMode & KIRAN_WORK_MODE_SMS)
    {
        // SMS 认证类型 — 当前 KADAuthType 中无对应枚举值，记录日志
        KLOG_INFO() << "Kiran GetWorkMode: SMS mode present but no KADAuthType mapping";
    }
    if (workMode & KIRAN_WORK_MODE_CODE)
    {
        authTypes << KAD_AUTH_TYPE_VIRTUAL_CODE;
    }

    return authTypes;
}
