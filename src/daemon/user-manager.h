/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
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

#pragma once

#include <QSharedPointer>

#include "user.h"

class AccountsProxy;

namespace Kiran
{
class UserManager : QObject
{
    Q_OBJECT
private:
    UserManager();

public:
    virtual ~UserManager() {};

    static UserManager *getInstance() { return m_instance; };
    static void globalInit();
    static void globalDeinit() { delete m_instance; };

    // 查找用户，缓存不存在则创建，如果系统没有这个用户则返回NULL
    QSharedPointer<User> findUser(const QString &userName);

private:
    void init();
    void initUsers();

    QSharedPointer<User> addUser(const QString &userName);
    void deleteUser(const QString &userName);
    void deleteIID(const QString &iid);

private Q_SLOTS:
    void onUserDeleted(const QDBusObjectPath &userObjectPath);

private:
    static UserManager *m_instance;

    AccountsProxy *m_accountsProxy;
    // <用户名，用户对象>
    QMap<QString, QSharedPointer<User>> m_users;
};
}  // namespace Kiran
