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

#pragma once

#include "src/daemon/user.h"
#include <QSharedPointer>

class AccountsProxy;

namespace Kiran
{
class UserManager : QObject
{
    Q_OBJECT
private:
    UserManager();
public:
    virtual ~UserManager(){};

    static UserManager *getInstance() { return m_instance; };
    static void globalInit();
    static void globalDeinit() { delete m_instance; };

    // 查找用户，缓存不存在则创建，如果系统没有这个用户则返回NULL
    QSharedPointer<User> findUser(const QString &userName);
    // 根据认证类型和数据ID查找用户
    QSharedPointer<User> getUserByIID(const QString &iid) { return this->m_iid2User.value(iid); };

private:
    void init();
    void initUsers();

    QSharedPointer<User> addUser(const QString &userName);
    void addIID(const QString &iid, QSharedPointer<User> user);
    void deleteUser(const QString &userName);
    void deleteIID(const QString &iid);

private Q_SLOTS:
    void onUserDeleted(const QDBusObjectPath &userObjectPath);

private:
    static UserManager *m_instance;

    AccountsProxy *m_accountsProxy;
    // <用户名，用户对象>
    QMap<QString, QSharedPointer<User>> m_users;
    // <iid，用户名>
    QMap<QString, QSharedPointer<User>> m_iid2User;
};
}  // namespace Kiran
