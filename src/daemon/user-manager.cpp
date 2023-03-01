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

#include "src/daemon/user-manager.h"
#include <auxiliary.h>
#include <kiran-system-daemon/accounts-i.h>
#include <pwd.h>
#include <QDir>
#include "src/daemon/accounts_proxy.h"
#include "src/daemon/config-daemon.h"

namespace Kiran
{
UserManager::UserManager()
{
    this->m_accountsProxy = new AccountsProxy(ACCOUNTS_DBUS_NAME,
                                              ACCOUNTS_OBJECT_PATH,
                                              QDBusConnection::systemBus(),
                                              this);
}

UserManager *UserManager::m_instance = nullptr;
void UserManager::globalInit()
{
    m_instance = new UserManager();
    m_instance->init();
}

QSharedPointer<User> UserManager::findUser(const QString &userName)
{
    auto user = this->m_users.value(userName, nullptr);
    RETURN_VAL_IF_TRUE(user, user);

    auto pwent = getpwnam(userName.toStdString().c_str());
    RETURN_VAL_IF_TRUE(pwent == NULL, NULL);

    user = addUser(userName);
    return user;
}

void UserManager::init()
{
    this->initUsers();
    connect(this->m_accountsProxy, SIGNAL(UserDeleted(const QDBusObjectPath &)), this, SLOT(onUserDeleted(const QDBusObjectPath &)));
}

void UserManager::initUsers()
{
    // 默认只加载有缓存数据的用户，因为需要根据认证ID查找匹配的用户
    QDir dir(KDA_UESR_DATA_DIR);
    for (const auto &entryInfo : dir.entryInfoList())
    {
        CONTINUE_IF_TRUE(!entryInfo.isFile());
        auto userName = entryInfo.fileName();
        this->addUser(userName);
    }
}

QSharedPointer<User> UserManager::addUser(const QString &userName)
{
    auto pwent = getpwnam(userName.toStdString().c_str());
    RETURN_VAL_IF_TRUE(pwent == NULL,QSharedPointer<User>());

    auto user = QSharedPointer<User>(new User(pwent, this));
    for (auto &iid : user->getIIDs())
    {
        this->addIID(iid, user);
    }

    connect(user.data(), &User::IdentificationAdded, std::bind(&UserManager::addIID, this, std::placeholders::_1, user));
    connect(user.data(), &User::IdentificationDeleted, std::bind(&UserManager::deleteIID, this, std::placeholders::_1));
    this->m_users.insert(userName, user);
    return user;
}

void UserManager::addIID(const QString &iid, QSharedPointer<User>user)
{
    if (this->m_iid2User.contains(iid))
    {
        // 正常逻辑是不会执行到这里
        KLOG_ERROR() << "The iid " << iid << " already exists.";
    }
    else
    {
        this->m_iid2User.insert(iid, user);
    }
}

void UserManager::deleteUser(const QString &userName)
{
    auto user = this->findUser(userName);
    RETURN_IF_TRUE(!user);

    for (auto &iid : user->getIIDs())
    {
        this->deleteIID(iid);
    }

    user->removeCache();
    this->m_users.remove(userName);
    return;
}

void UserManager::deleteIID(const QString &iid)
{
    this->m_iid2User.remove(iid);
}

void UserManager::onUserDeleted(const QDBusObjectPath &userObjectPath)
{
    QFileInfo fileInfo(userObjectPath.path());
    auto uid = fileInfo.baseName().toLongLong();
    auto pwent = getpwuid(uid);
    RETURN_IF_TRUE(pwent == NULL);
    this->deleteUser(pwent->pw_name);
}
}  // namespace Kiran
