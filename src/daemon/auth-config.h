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

#pragma once

#include "kas-authentication-i.h"
#include <QObject>
#include <QMap>
#include <QDebug>

class QSettings;
namespace Kiran
{
class AuthConfig : public QObject
{
    Q_OBJECT
    friend class AuthManager;

private:
    AuthConfig(QObject* parent = nullptr);

public:
    static AuthConfig *getInstance() { return m_instance; };
    static void globalInit();
    static void globalDeinit() { delete m_instance; };

    ~AuthConfig();

    int getAuthMode();
    QList<int> getAuthOrder();
    int getMaxFailures();
    
    QString getDefaultDeviceID(KADAuthType authType);
    bool getAuthTypeEnable(KADAuthType authType);
    bool getAuthTypeEnabledForApp(KADAuthType authType, KADAuthApplication authApplication);
    QList<int> getAuthTypeByApp(int authApp);
    friend QDebug operator<<(QDebug argument, const AuthConfig* authInfo);

private:
    bool init();
    bool load();
    QString authType2GroupName(KADAuthType authType);

    void setDefaultDeviceID(KADAuthType authType, const QString& deviceID);
    void setAuthTypeEnable(KADAuthType authType,bool enable);
    void setAuthTypeEnabledForApp(KADAuthType authType, KADAuthApplication authApplication, bool enable);

signals:
    void defaultDeviceChanged(int authType,const QString& deviceID);
    void authTypeEnableChanged(int authType,bool enabled);
    void authTypeApplicationEnableChanged(int authType);

private:
    static AuthConfig *m_instance;
    QSettings* m_settings;

    int m_authMode;
    QList<int> m_authOrder;
    int m_maxFailures;

    // QMap<认证类型,默认设备ID> - 缓存每个认证类型的默认设备ID
    QMap<int, QString> m_defaultDeviceMap;
    // QMap<认证类型,是否启用> - 缓存每个认证类型是否启用
    QMap<int, bool> m_authTypeEnableMap;
    // QMap<认证类型,QList<启用的认证应用>> - 缓存每个认证类型开启认证的应用
    QMap<int, QList<int>> m_authTypeAppMap;
};
}  // namespace Kiran