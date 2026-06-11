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

#include "czht-auth-adapter.h"

#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusMessage>
#include <QDBusReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

#include "auth-manager.h"
#include "kas-authentication-i.h"
#include "qt5-log-i.h"

bool CzhtAuthAdapter::isAvailable()
{
    // 检查三类虚拟设备是否存在
    auto *mgr = Kiran::AuthManager::getInstance();
    if (!mgr)
    {
        return false;
    }

    QString virtualFaceDevices = mgr->GetDevicesForType(KAD_AUTH_TYPE_VIRTUAL_FACE);
    QString virtualCodeDevices = mgr->GetDevicesForType(KAD_AUTH_TYPE_VIRTUAL_CODE);
    QString virtualCodeNoCameraDevices = mgr->GetDevicesForType(KAD_AUTH_TYPE_VIRTUAL_CODE_NO_CAMERA);

    bool hasVirtualFaceDevice = !virtualFaceDevices.isEmpty();
    bool hasVirtualCodeDevice = !virtualCodeDevices.isEmpty();
    bool hasVirtualCodeNoCameraDevice = !virtualCodeNoCameraDevices.isEmpty();

    if (!hasVirtualFaceDevice && !hasVirtualCodeDevice && !hasVirtualCodeNoCameraDevice)
    {
        return false;
    }

    // 检查 CZHT D-Bus 服务是否存在
    static const QString CZHT_DBUS_SERVICE = QStringLiteral("com.czht.face.daemon");
    if (!QDBusConnection::systemBus().interface()->isServiceRegistered(CZHT_DBUS_SERVICE))
    {
        return false;
    }

    return true;
}

QList<int> CzhtAuthAdapter::getAuthTypes()
{
    QList<int> authTypes;

    static const QString CZHT_DBUS_SERVICE = QStringLiteral("com.czht.face.daemon");
    static const QString CZHT_DBUS_PATH = QStringLiteral("/com/czht/face/daemon");
    static const QString CZHT_DBUS_INTERFACE = QStringLiteral("com.czht.face.daemon");
    static const QString CZHT_METHOD_GET_WORK_MODE = QStringLiteral("GetWorkMode");

    QDBusMessage message = QDBusMessage::createMethodCall(CZHT_DBUS_SERVICE,
                                                          CZHT_DBUS_PATH,
                                                          CZHT_DBUS_INTERFACE,
                                                          CZHT_METHOD_GET_WORK_MODE);
    QDBusReply<QString> reply = QDBusConnection::systemBus().call(message);
    if (!reply.isValid())
    {
        KLOG_WARNING() << "Failed to call CZHT GetWorkMode:" << reply.error().message();
        return authTypes;
    }
    KLOG_INFO() << "GetWorkMode from" << CZHT_DBUS_SERVICE << ", reply:" << reply.value();

    QString jsonStr = reply.value();
    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonStr.toUtf8(), &parseError);

    if (parseError.error != QJsonParseError::NoError)
    {
        KLOG_WARNING() << "Failed to parse CZHT GetWorkMode JSON:" << parseError.errorString();
        return authTypes;
    }

    QJsonObject jsonObj = jsonDoc.object();
    int code = jsonObj.value("code").toInt(-1);
    if (code != 0)
    {
        KLOG_WARNING() << "CZHT GetWorkMode returned error code:" << code;
        return authTypes;
    }

    int workMode = jsonObj.value("work_mode").toInt(-1);
    KLOG_INFO() << "CZHT GetWorkMode, work_mode:" << workMode;

    // switch-case 1-6 映射（含 case 6 无摄像头授权码）
    switch (workMode)
    {
    case 1:  // 人脸
        authTypes << KAD_AUTH_TYPE_VIRTUAL_FACE;
        break;
    case 2:  // 人脸+密码
        authTypes << KAD_AUTH_TYPE_VIRTUAL_FACE << KAD_AUTH_TYPE_PASSWORD;
        break;
    case 3:  // 人脸+授权码
        authTypes << KAD_AUTH_TYPE_VIRTUAL_FACE << KAD_AUTH_TYPE_VIRTUAL_CODE;
        break;
    case 4:  // 人脸+密码+授权码
        authTypes << KAD_AUTH_TYPE_VIRTUAL_FACE << KAD_AUTH_TYPE_VIRTUAL_CODE << KAD_AUTH_TYPE_PASSWORD;
        break;
    case 5:  // 密码
        authTypes << KAD_AUTH_TYPE_PASSWORD;
        break;
    case 6:  // 无摄像头授权码
        authTypes << KAD_AUTH_TYPE_VIRTUAL_CODE_NO_CAMERA;
        break;
    default:
        KLOG_WARNING() << "Unknown CZHT work_mode:" << workMode;
        break;
    }

    return authTypes;
}
