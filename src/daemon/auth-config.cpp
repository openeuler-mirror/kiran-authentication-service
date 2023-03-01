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
 * Author:     liuxinhao <liuxinhao@kylinsec.com.cn>
 */

#include "auth-config.h"
#include "src/daemon/config-daemon.h"
#include "src/daemon/utils.h"

#include <QSettings>
#include <qt5-log-i.h>
#include <QDebug>

using namespace Kiran;

#define KAD_MAIN_CONFIG_PATH KAS_INSTALL_SYSCONFDIR "/kad.ini"

#define INIFILE_GENERAL_GROUP_NAME       "General"
#define INIFILE_GENERAL_KEY_AUTH_MODE    "AuthMode"
#define INIFILE_GENERAL_KEY_AUTH_ORDER   "AuthOrder"
#define INIFILE_GENERAL_KEY_MAX_FAILURES "MaxFailures"


#define INIFILE_FP_AUTHTYPE_GROUP_NAME      "FingerPrint"
#define INIFILE_UKEY_AUTHTYPE_GROUP_NAME    "Ukey"

#define INIFILE_AUTHTYPE_KEY_DEFAULT_DEVICE "DefaultDeviceID"
#define INIFILE_AUTHTYPE_KEY_ENABLE         "Enable"
#define INIFILE_AUTHTYPE_KEY_LOGIN_ENABLE   "LoginEnable"
#define INIFILE_AUHTTYPE_KEY_UNLOCK_ENABLE  "UnlockEnable"
#define INIFILE_AUTHTYPE_KEY_EMPOWERMENT    "EmpowermentEnable"

static const QMap<KADAuthType, QString> AuthTypeGroupMap = {
    {
        KAD_AUTH_TYPE_FINGERPRINT,
        "FingerPrint"
    },
    {
        KAD_AUTH_TYPE_FACE,
        "Face"
    },
    {
        KAD_AUTH_TYPE_UKEY,
        "Ukey"
    },
    {
        KAD_AUTH_TYPE_FINGERVEIN,
        "FingerVein"
    }
};

static const QMap<KADAuthApplication, QString> AuthAppKeyMap = {
    {
        KAD_AUTH_APPLICATION_LOGIN,
        INIFILE_AUTHTYPE_KEY_LOGIN_ENABLE
    },
    {
        KAD_AUTH_APPLICATION_UNLOCK,
        INIFILE_AUHTTYPE_KEY_UNLOCK_ENABLE
    },
    {
        KAD_AUTH_APPLICATION_EMPOWERMENT,
        INIFILE_AUTHTYPE_KEY_EMPOWERMENT
    }
};

AuthConfig::AuthConfig(QObject* parent)
    : QObject(parent)
{
}

AuthConfig* AuthConfig::m_instance = nullptr;
void AuthConfig::globalInit()
{
    m_instance = new AuthConfig();
    m_instance->init();
}

AuthConfig::~AuthConfig()
{
}

bool AuthConfig::init()
{
    m_settings = new QSettings(KAD_MAIN_CONFIG_PATH, QSettings::IniFormat, this);
    return load();
}

bool AuthConfig::load()
{
    m_settings->beginGroup(INIFILE_GENERAL_GROUP_NAME);
    auto autoMode = m_settings->value(INIFILE_GENERAL_KEY_AUTH_MODE, KAD_AUTH_MODE_STR_OR).toString();
    m_authMode = Utils::authModeStr2Enum(autoMode);

    auto authOrder = m_settings->value(INIFILE_GENERAL_KEY_AUTH_ORDER, QStringList{AUTH_TYPE_STR_FINGERPRINT,AUTH_TYPE_STR_UKEY}).toStringList();
    this->m_authOrder = Utils::authOrderStr2Enum(authOrder);

    auto maxFailures = m_settings->value(INIFILE_GENERAL_KEY_MAX_FAILURES, 3).toInt();
    this->m_maxFailures = maxFailures;
    m_settings->endGroup();

    // 读取认证类型下设置项,认证类型开关默认都为关闭
    const bool authTypeDefaultEnable = false;
    auto iter = AuthTypeGroupMap.begin();
    while (iter != AuthTypeGroupMap.end())
    {
        KADAuthType authType = iter.key();
        QString groupName = iter.value();

        m_settings->beginGroup(groupName);
        auto defaultDevice = m_settings->value(INIFILE_AUTHTYPE_KEY_DEFAULT_DEVICE, "").toString();
        m_defaultDeviceMap[authType] = defaultDevice;

        auto enabled = m_settings->value(INIFILE_AUTHTYPE_KEY_ENABLE, authTypeDefaultEnable).toBool();
        m_authTypeEnableMap[authType] = enabled;

        QList<int> authApps;
        auto authAppIter = AuthAppKeyMap.begin();
        while (authAppIter != AuthAppKeyMap.end())
        {
            int authApp = authAppIter.key();
            QString enableKey = authAppIter.value();

            auto authTypeAppEnable = m_settings->value(enableKey, authTypeDefaultEnable).toBool();
            if( authTypeAppEnable )
            {
                authApps << authApp;
            }
            authAppIter++;
        }
        m_authTypeAppMap[authType] = authApps;
        m_settings->endGroup();

        iter++;
    }

    return true;
}

QString AuthConfig::authType2GroupName(KADAuthType authType)
{
    QString groupName;

    auto iter = AuthTypeGroupMap.find(authType);
    if( iter != AuthTypeGroupMap.end() )
    {
        groupName = iter.value();
    }

    return groupName;
}

int AuthConfig::getAuthMode()
{
    return m_authMode;
}

QList<int> AuthConfig::getAuthOrder()
{
    return m_authOrder;
}

int AuthConfig::getMaxFailures()
{
    return m_maxFailures;
}

QString AuthConfig::getDefaultDeviceID(KADAuthType authType)
{
    QString defaultDeviceID;
    
    auto iter = m_defaultDeviceMap.find(authType);
    if( iter != m_defaultDeviceMap.end() )
    {
        defaultDeviceID = iter.value();
    }
                                 
    return defaultDeviceID;
}

void AuthConfig::setDefaultDeviceID(KADAuthType authType, const QString& deviceID)
{
    QString groupName = authType2GroupName(authType);
    if( groupName.isEmpty() )
    {
        KLOG_ERROR() << "set default device id failed,no this auth type:" << authType;
        return;
    }

    auto oldDefaultDeviceIter = m_defaultDeviceMap.find(authType);
    if ( ( oldDefaultDeviceIter != m_defaultDeviceMap.end() ) &&
         ( oldDefaultDeviceIter.value() == deviceID ) )
    {
        KLOG_DEBUG() << "the default device ID has not changed," << authType << deviceID;
        return;
    }

    m_settings->beginGroup(groupName);
    m_settings->setValue(INIFILE_AUTHTYPE_KEY_DEFAULT_DEVICE, deviceID);
    m_settings->endGroup();

    m_defaultDeviceMap[authType] = deviceID;
    emit defaultDeviceChanged(authType, deviceID);
}

bool AuthConfig::getAuthTypeEnable(KADAuthType authType)
{
    bool enabled = false;

    auto iter = m_authTypeEnableMap.find(authType);
    if( iter != m_authTypeEnableMap.end() )
    {
        enabled = iter.value();
    }

    return enabled;
}

void AuthConfig::setAuthTypeEnable(KADAuthType authType, bool enable)
{
    QString groupName = authType2GroupName(authType);
    if( groupName.isEmpty() )
    {
        KLOG_ERROR() << "set auth type enable failed,no this auth type:" << authType;
        return; 
    }

    auto oldEnableIter = m_authTypeEnableMap.find(authType);
    if( oldEnableIter.value() == enable )
    {
        KLOG_DEBUG() << "the auth type enable has not changed," << authType << enable;
        return;
    }

    m_settings->beginGroup(groupName);
    m_settings->setValue(INIFILE_AUTHTYPE_KEY_ENABLE, enable);
    m_settings->endGroup();

    m_authTypeEnableMap[authType] = enable;
    emit authTypeEnableChanged(authType, enable);
}

bool AuthConfig::getAuthTypeEnabledForApp(KADAuthType authType, KADAuthApplication authApplication)
{
    QString groupName = authType2GroupName(authType);
    auto enabledAppIter = m_authTypeAppMap.find(authType);

    if( groupName.isEmpty() || enabledAppIter == m_authTypeAppMap.end() )
    {
        KLOG_ERROR() << "get auth type enable app failed,no this auth type:" << authType;
        return false; 
    }

    auto enableApps = enabledAppIter.value();
    return enableApps.contains(authApplication);
}

QList<int> AuthConfig::getAuthTypeByApp(int authApp)
{
    auto iter = m_authTypeAppMap.begin();

    QList<int> authTypes;
    while (iter != m_authTypeAppMap.end())
    {
        if( iter.value().contains(authApp) && m_authTypeEnableMap[iter.key()] )
        {
            authTypes << iter.key();
        }
        iter++;
    }
    return authTypes;
}

void AuthConfig::setAuthTypeEnabledForApp(KADAuthType authType, KADAuthApplication authApplication, bool enable)
{
    QString groupName = authType2GroupName(authType);
    auto enableAppIter = m_authTypeAppMap.find(authType);
    if( groupName.isEmpty() || enableAppIter == m_authTypeAppMap.end() )
    {
        KLOG_ERROR() << "set auth type enable app failed,no this auth type:" << authType;
        return;
    }

    auto enabledApps = enableAppIter.value();
    bool oldStatus = enabledApps.contains(authApplication);
    if( oldStatus == enable )
    {
        KLOG_DEBUG() << "the auth type application enable has not changed," << authType << authApplication << enable;
        return;
    }

    auto authAppKeyIter = AuthAppKeyMap.find(authApplication);
    if( authAppKeyIter == AuthAppKeyMap.end() )
    {
        KLOG_ERROR() << "set auth type application enable failed, can't find this auth application" << authType << authApplication << enable;
        return;
    }
    auto key = authAppKeyIter.value();

    m_settings->beginGroup(groupName);
    m_settings->setValue(key, enable);
    m_settings->endGroup();

    if( enable )
        enabledApps.append(authApplication);
    else
        enabledApps.removeAll(authApplication);

    m_authTypeAppMap[authType] = enabledApps;
    emit authTypeApplicationEnableChanged(authType);
}

namespace Kiran{
QDebug operator<<(QDebug argument, const AuthConfig* authInfo)
{
    argument << "auth mode:" << Utils::authModeEnum2Str(authInfo->m_authMode) << "\n";
    argument << "auth order:" << Utils::authOrderEnum2Str(authInfo->m_authOrder) << "\n";
    argument << "auth max failures:" << authInfo->m_maxFailures << "\n";

    auto authTypeEnableIter = authInfo->m_authTypeEnableMap.begin();
    while( authTypeEnableIter != authInfo->m_authTypeEnableMap.end() )
    {
        int authType = authTypeEnableIter.key();
        bool enabled = authTypeEnableIter.value();
        argument << "auth type:" << authType << Utils::authTypeEnum2Str(authType) << "enalbed: " << enabled << "\n";
        argument << "   default device:" << authInfo->m_defaultDeviceMap[authType] << "\n";
        argument << "   enabled apps:" << authInfo->m_authTypeAppMap[authType] << "\n";
        argument << "\n";
        authTypeEnableIter++;
    }

    return argument;
}
}
