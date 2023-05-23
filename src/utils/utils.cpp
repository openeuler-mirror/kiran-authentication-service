/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-session-manager is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     tangjie02 <tangjie02@kylinos.com.cn>
 */

#include "src/utils/utils.h"
#include <auxiliary.h>
#include <kas-authentication-i.h>
#include <kiran-authentication-devices/kiran-auth-device-i.h>
#include <qt5-log-i.h>
#include <QCryptographicHash>
#include <QCoreApplication>

namespace Kiran
{
template <typename T>
static QList<T> converIntListToEnum(QList<int> list)
{
    QList<T> ret;
    auto iter = list.begin();
    while (iter != list.end())
    {
        ret << *iter;
        iter++;
    }
    return ret;
}

template <typename T>
QList<int> converEnumListToInt(QList<T> list)
{
    QList<int> ret;
    auto iter = list.begin();
    while (iter != list.end())
    {
        ret << *iter;
        iter++;
    }
    return ret;
}

QString Utils::GenerateIID(int32_t authType, const QString& dataID)
{
    QCryptographicHash hash(QCryptographicHash::Md5);
    hash.addData(QString("%1").arg(authType).toUtf8());
    hash.addData(dataID.toUtf8());
    return QString(hash.result().toHex());
}

QString Utils::authModeEnum2Str(int authMode)
{
    switch (authMode)
    {
    case KADAuthMode::KAD_AUTH_MODE_AND:
        return QStringLiteral(KAD_AUTH_MODE_STR_AND);
    case KADAuthMode::KAD_AUTH_MODE_OR:
        return QStringLiteral(KAD_AUTH_MODE_STR_OR);
    default:
        KLOG_WARNING() << "Unknown authMode: " << authMode;
    }
    return QString();
}

int Utils::authModeStr2Enum(const QString& authMode)
{
    switch (shash(authMode.toStdString().c_str()))
    {
    case CONNECT(KAD_AUTH_MODE_STR_AND, _hash):
        return KADAuthMode::KAD_AUTH_MODE_AND;
    case CONNECT(KAD_AUTH_MODE_STR_OR, _hash):
        return KADAuthMode::KAD_AUTH_MODE_OR;
    default:
        KLOG_WARNING() << "Unknown authMode: " << authMode;
    }
    return KADAuthMode::KAD_AUTH_MODE_NONE;
}

QString Utils::authTypeEnum2Str(int authType)
{
    switch (authType)
    {
    case KADAuthType::KAD_AUTH_TYPE_PASSWORD:
        return QStringLiteral(AUTH_TYPE_STR_PASSWORD);
    case KADAuthType::KAD_AUTH_TYPE_FINGERPRINT:
        return QStringLiteral(AUTH_TYPE_STR_FINGERPRINT);
    case KADAuthType::KAD_AUTH_TYPE_FACE:
        return QStringLiteral(AUTH_TYPE_STR_FACE);
    case KADAuthType::KAD_AUTH_TYPE_UKEY:
        return QStringLiteral(AUTH_TYPE_STR_UKEY);
    case KADAuthType::KAD_AUTH_TYPE_FINGERVEIN:
        return QStringLiteral(AUTH_TYPE_STR_FINGERVEIN);
    case KADAuthType::KAD_AUTH_TYPE_IRIS:
        return QStringLiteral(AUTH_TYPE_STR_IRIS);
    default:
        KLOG_WARNING() << "Unknown authType: " << authType;
    }
    return QString();
}

int Utils::authTypeStr2Enum(const QString& authType)
{
    switch (shash(authType.toStdString().c_str()))
    {
    case CONNECT(AUTH_TYPE_STR_PASSWORD, _hash):
        return KADAuthType::KAD_AUTH_TYPE_PASSWORD;
    case CONNECT(AUTH_TYPE_STR_FINGERPRINT, _hash):
        return KADAuthType::KAD_AUTH_TYPE_FINGERPRINT;
    case CONNECT(AUTH_TYPE_STR_FACE, _hash):
        return KADAuthType::KAD_AUTH_TYPE_FACE;
    case CONNECT(AUTH_TYPE_STR_UKEY, _hash):
        return KADAuthType::KAD_AUTH_TYPE_UKEY;
    case CONNECT(AUTH_TYPE_STR_FINGERVEIN, _hash):
        return KADAuthType::KAD_AUTH_TYPE_FINGERVEIN;
    case CONNECT(AUTH_TYPE_STR_IRIS, _hash):
        return KADAuthType::KAD_AUTH_TYPE_IRIS;
    default:
        KLOG_WARNING() << "Unknown authType: " << authType;
    }
    return KADAuthType::KAD_AUTH_TYPE_NONE;
}

int32_t Utils::authType2DeviceType(int32_t authType)
{
    switch (authType)
    {
    case KADAuthType::KAD_AUTH_TYPE_FINGERPRINT:
        return DeviceType::DEVICE_TYPE_FingerPrint;
    case KADAuthType::KAD_AUTH_TYPE_FACE:
        return DeviceType::DEVICE_TYPE_Face;
    case KADAuthType::KAD_AUTH_TYPE_FINGERVEIN:
        return DeviceType::DEVICE_TYPE_FingerVein;
    case KADAuthType::KAD_AUTH_TYPE_UKEY:
        return DeviceType::DEVICE_TYPE_UKey;
    case KAD_AUTH_TYPE_IRIS:
        return DeviceType::DEVICE_TYPE_Iris;
    default:
        KLOG_WARNING() << "Unsupported authType: " << authType;
    }
    return -1;
}

int32_t Utils::deviceType2AuthType(int32_t deviceType)
{
    switch (deviceType)
    {
    case DeviceType::DEVICE_TYPE_FingerPrint:
        return KADAuthType::KAD_AUTH_TYPE_FINGERPRINT;
    case DeviceType::DEVICE_TYPE_Face:
        return KADAuthType::KAD_AUTH_TYPE_FACE;
    case DeviceType::DEVICE_TYPE_FingerVein:
        return KADAuthType::KAD_AUTH_TYPE_FINGERVEIN;
    case DeviceType::DEVICE_TYPE_UKey:
        return KADAuthType::KAD_AUTH_TYPE_UKEY;
    case DeviceType::DEVICE_TYPE_Iris:
        return KADAuthType::KAD_AUTH_TYPE_IRIS;
    default:
        KLOG_WARNING() << "Unsupported deviceType: " << deviceType;
    }
    return KADAuthType::KAD_AUTH_TYPE_NONE;
}

QStringList Utils::authOrderEnum2Str(const QList<int>& authOrder)
{
    QStringList retval;
    for (auto& authType : authOrder)
    {
        retval.push_back(Utils::authTypeEnum2Str(authType));
    }
    return retval;
}

QList<int> Utils::authOrderStr2Enum(const QStringList& authOrder)
{
    QList<int> retval;
    for (auto& authType : authOrder)
    {
        retval.push_back(Utils::authTypeStr2Enum(authType));
    }
    return retval;
}

QString Utils::authTypeEnum2LocaleStr(int authType)
{
    QMap<int,QString> localeAuthTypeMap = {
        {KAD_AUTH_TYPE_PASSWORD,QCoreApplication::tr("password")},
        {KAD_AUTH_TYPE_FINGERPRINT,QCoreApplication::tr("fingerprint")},
        {KAD_AUTH_TYPE_FACE,QCoreApplication::tr("face")},
        {KAD_AUTH_TYPE_FINGERVEIN,QCoreApplication::tr("fingervein")},
        {KAD_AUTH_TYPE_IRIS,QCoreApplication::tr("iris")},
        {KAD_AUTH_TYPE_UKEY,QCoreApplication::tr("ukey")}
    };

    auto iter = localeAuthTypeMap.find(authType);
    if( iter == localeAuthTypeMap.end() )
    {
        KLOG_WARNING("convert %d to locale string faield!",authType);
        return "";
    }

    return iter.value();
}

QString Utils::identifyResultEnum2Str(int32_t identifyResult)
{
    switch (identifyResult)
    {
    case IdentifyStatus::IDENTIFY_STATUS_NOT_MATCH:
        return QObject::tr("Feature not match.");
    case IdentifyStatus::IDENTIFY_STATUS_MATCH:
        return QObject::tr("Feature matching successed.");
    case IdentifyStatus::IDENTIFY_STATUS_RETRY:
        return QObject::tr("Feature not match, please retry it.");
        break;
    case IdentifyStatus::IDENTIFY_STATUS_NORMAL:
        return "";
    default:
        return QObject::tr("Unknown verfication error.");
    }
}
}  // namespace Kiran