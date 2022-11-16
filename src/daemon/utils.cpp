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

#include "src/daemon/utils.h"
#include <auxiliary.h>
#include <biometrics-i.h>
#include <kas-authentication-i.h>
#include <qt5-log-i.h>
#include <QCryptographicHash>

namespace Kiran
{
QString Utils::GenerateIID(int32_t authType, const QString& dataID)
{
    QCryptographicHash hash(QCryptographicHash::Md5);
    hash.addData(QString("%1").arg(authType).toUtf8());
    hash.addData(dataID.toUtf8());
    return QString(hash.result());
}

QString Utils::authModeEnum2Str(int32_t authMode)
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

int32_t Utils::authModeStr2Enum(const QString& authMode)
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

QString Utils::authTypeEnum2Str(int32_t authType)
{
    switch (authType)
    {
    case KADAuthType::KAD_AUTH_TYPE_FINGERPRINT:
        return QStringLiteral(AUTH_TYPE_STR_FINGERPRINT);
    case KADAuthType::KAD_AUTH_TYPE_FACE:
        return QStringLiteral(AUTH_TYPE_STR_FACE);
    case KADAuthType::KAD_AUTH_TYPE_UKEY:
        return QStringLiteral(AUTH_TYPE_STR_UKEY);
    default:
        KLOG_WARNING() << "Unknown authType: " << authType;
    }
    return QString();
}

int32_t Utils::authTypeStr2Enum(const QString& authType)
{
    switch (shash(authType.toStdString().c_str()))
    {
    case CONNECT(AUTH_TYPE_STR_FINGERPRINT, _hash):
        return KADAuthType::KAD_AUTH_TYPE_FINGERPRINT;
    case CONNECT(AUTH_TYPE_STR_FACE, _hash):
        return KADAuthType::KAD_AUTH_TYPE_FACE;
    case CONNECT(AUTH_TYPE_STR_UKEY, _hash):
        return KADAuthType::KAD_AUTH_TYPE_UKEY;
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
        return BiometricsDeviceType::BIOMETRICS_DEVICE_TYPE_FINGERPRINT;
    case KADAuthType::KAD_AUTH_TYPE_FACE:
        return BiometricsDeviceType::BIOMETRICS_DEVICE_TYPE_FACE;
    default:
        KLOG_WARNING() << "Unsupported authType: " << authType;
    }
    return BiometricsDeviceType::BIOMETRICS_DEVICE_TYPE_NONE;
}

int32_t Utils::deviceType2AuthType(int32_t deviceType)
{
    switch (deviceType)
    {
    case BiometricsDeviceType::BIOMETRICS_DEVICE_TYPE_FINGERPRINT:
        return KADAuthType::KAD_AUTH_TYPE_FINGERPRINT;
    case BiometricsDeviceType::BIOMETRICS_DEVICE_TYPE_FACE:
        return KADAuthType::KAD_AUTH_TYPE_FACE;
    default:
        KLOG_WARNING() << "Unsupported deviceType: " << deviceType;
    }
    return KADAuthType::KAD_AUTH_TYPE_NONE;
}

QStringList Utils::authOrderEnum2Str(const QList<int32_t>& authOrder)
{
    QStringList retval;
    for (auto& authType : authOrder)
    {
        retval.push_back(Utils::authTypeEnum2Str(authType));
    }
    return retval;
}

QList<int32_t> Utils::authOrderStr2Enum(const QStringList& authOrder)
{
    QList<int32_t> retval;
    for (auto& authType : authOrder)
    {
        retval.push_back(Utils::authTypeStr2Enum(authType));
    }
    return retval;
}

QString Utils::fpEnrollResultEnum2Str(int32_t fpEnrollResult)
{
    switch (fpEnrollResult)
    {
    case FPEnrollResult::FP_ENROLL_RESULT_COMPLETE:
        return QObject::tr("Enrollment completed successfully.");
    case FPEnrollResult::FP_ENROLL_RESULT_FAIL:
        return QObject::tr("Enrollment failed.");
    case FPEnrollResult::FP_ENROLL_RESULT_PASS:
        return QObject::tr("Enroll stage passed.");
    case FPEnrollResult::FP_ENROLL_RESULT_RETRY:
    case FPEnrollResult::FP_ENROLL_RESULT_RETRY_REMOVE_FINGER:
        return QObject::tr("The enrollment scan did not succeed, please retry it.");
    case FPEnrollResult::FP_ENROLL_RESULT_RETRY_TOO_SHORT:
        return QObject::tr("The finger swipe was too short, please retry it.");
    case FPEnrollResult::FP_ENROLL_RESULT_RETRY_CENTER_FINGER:
        return QObject::tr("The finger was not centered on the scanner, please retry it.");
    default:
        return QObject::tr("Unknown enrollment error.");
    }
}

QString Utils::fpVerifyResultEnum2Str(int32_t fpVerifyResult)
{
    switch (fpVerifyResult)
    {
    case FPVerifyResult::FP_VERIFY_RESULT_NOT_MATCH:
        return QObject::tr("Fingerprint not match.");
    case FPVerifyResult::FP_VERIFY_RESULT_MATCH:
        return QObject::tr("Fingerprint matching successed.");
    case FPVerifyResult::FP_VERIFY_RESULT_RETRY:
    case FPVerifyResult::FP_VERIFY_RESULT_RETRY_REMOVE_FINGER:
        return QObject::tr("Fingerprint not match, please retry it.");
    case FPVerifyResult::FP_VERIFY_RESULT_RETRY_TOO_SHORT:
        return QObject::tr("The finger swipe was too short, please retry it.");
    case FPVerifyResult::FP_VERIFY_RESULT_RETRY_CENTER_FINGER:
        return QObject::tr("The finger was not centered on the scanner, please retry it.");
    default:
        return QObject::tr("Unknown verfication error.");
    }
}
}  // namespace Kiran