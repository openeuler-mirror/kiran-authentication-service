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

#pragma once

#include <QMap>
#include <QObject>
#include <QString>

class QSettings;
namespace Kiran
{
class UserConfig : public QObject
{
    friend class User;
    Q_OBJECT
public:
    UserConfig() = delete;
    explicit UserConfig(const QString& userName, QObject* parent = nullptr);
    ~UserConfig();

    int getFailures();

private:
    void init();
    void setFailures(int failures);

private:
    QString m_userName;
    int m_failures;
    QSettings* m_settings;
};
}  // namespace Kiran