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
#include <auxiliary.h>
#include <pwd.h>
#include <QDir>
#include <QFileSystemWatcher>

#include "config-daemon.h"
#include "lib/feature-db.h"
#include "user-manager.h"

#define ETC_PASSWD_FILE "/etc/passwd"

namespace Kiran
{
UserManager::UserManager()
{
    m_passwdWatcher = new QFileSystemWatcher(this);
    m_passwdWatcher->addPath(ETC_PASSWD_FILE);
    connect(m_passwdWatcher, SIGNAL(fileChanged(const QString &)), this, SLOT(onPasswdFileChanged(const QString &)));
}

UserManager *UserManager::m_instance = nullptr;
void UserManager::globalInit()
{
    m_instance = new UserManager();
    m_instance->init();
}

QSharedPointer<User> UserManager::findUser(const QString &userName)
{
    auto user = this->m_users.value(userName, QSharedPointer<User>());
    RETURN_VAL_IF_TRUE(user, user);

    auto pwent = getpwnam(userName.toStdString().c_str());
    RETURN_VAL_IF_TRUE(pwent == nullptr, QSharedPointer<User>());

    user = addUser(userName);
    return user;
}

void UserManager::init()
{
    this->initUsers();
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
    RETURN_VAL_IF_TRUE(pwent == NULL, QSharedPointer<User>());

    auto user = QSharedPointer<User>(new User(pwent, this));
    connect(user.data(), &User::IdentificationDeleted, std::bind(&UserManager::deleteIID, this, std::placeholders::_1));
    this->m_users.insert(userName, user);
    return user;
}

void UserManager::deleteUser(const QString &userName)
{
    auto user = this->findUser(userName);
    RETURN_IF_TRUE(!user);

    for (auto &iid : user->getIIDs())
    {
        this->deleteIID(iid);
    }

    FeatureDB::getInstance()->deleteFearureByUserName(userName);

    this->m_users.remove(userName);
    return;
}

void UserManager::deleteIID(const QString &iid)
{
    FeatureDB::getInstance()->deleteFearureByIID(iid);
}

void UserManager::onPasswdFileChanged(const QString &path)
{
    auto fp = fopen(ETC_PASSWD_FILE, "r");
    if (fp == NULL)
    {
        KLOG_WARNING() << "Unable to open" << ETC_PASSWD_FILE << ":" << strerror(errno);
        return;
    }

    // 从/etc/passwd文件中获取当前存在的用户列表
    // 将操作系统用户列表与m_users中用户列表进行比较，如果m_users中存在多余的用户，则删除该用户
    QStringList systemUserList;
    struct passwd *pwent;
    do
    {
        pwent = fgetpwent(fp);
        if (pwent != NULL)
        {
            auto passwd = QSharedPointer<Passwd>::create(pwent);
            systemUserList.append(passwd->pw_name);
        }
    } while (pwent != NULL);

    fclose(fp);

    for (const auto &userName : this->m_users.keys())
    {
        if (!systemUserList.contains(userName))
        {
            KLOG_INFO() << "delete user:" << userName << ", because it is not in the system passwd file";
            this->deleteUser(userName);
        }
    }

    m_passwdWatcher->addPath(ETC_PASSWD_FILE);
}

}  // namespace Kiran
