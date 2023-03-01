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

#include "src/pam/authentication-controller.h"
#include <auxiliary.h>
#include <pam_ext.h>
#include <pam_modules.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <QCommandLineParser>
#include <QFuture>
#include <QMutexLocker>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QFile>

#include "src/pam/authentication-graphical.h"
#include "src/pam/authentication-terminal.h"
#include "src/pam/pam-handle.h"

namespace Kiran
{
AuthenticationController::AuthenticationController(void* pamh,
                                                   const QStringList& arguments)
    : isRunning(false),
      m_result(PAM_SUCCESS)
{
    this->m_pamHandle = new PAMHandle(pamh, this, this);

    auto pamService = this->m_pamHandle->getItemDirect(PAM_SERVICE);
    m_isGraphical = this->isGraphical(pamService);
    if (m_isGraphical)
    {
        this->m_authentication = new AuthenticationGraphical(this->m_pamHandle, arguments);
    }
    else
    {
        this->m_authentication = new AuthenticationTerminal(this->m_pamHandle, arguments);
    }

    this->m_authentication->moveToThread(&this->m_workerThread);
    connect(this, &AuthenticationController::startAuthentication, this->m_authentication, &Authentication::start);
    this->m_workerThread.start();
}

AuthenticationController::~AuthenticationController()
{
    if (this->m_authentication)
    {
        delete this->m_authentication;
    }
}

int32_t AuthenticationController::run()
{
    //暂时只接管图形认证
    if( !m_isGraphical )
    {
        m_workerThread.quit();
        m_workerThread.wait();
        return PAM_IGNORE;
    }

    this->isRunning = true;

    Q_EMIT this->startAuthentication();

    while (this->isRunning)
    {
        QMutexLocker locker(&this->m_mutex);
        this->m_waitCondition.wait(&this->m_mutex);
        for (auto& task : this->m_tasks)
        {
            task();
        }
        this->m_tasks.clear();
    }
    auto pamh = this->m_pamHandle->getPamh();
    this->m_workerThread.wait();
    return this->m_result;
}

void AuthenticationController::stopTask(int result)
{
    this->m_result = result;
    this->isRunning = false;
    this->m_workerThread.quit();
}

void AuthenticationController::pushTask(std::function<void(void)> task)
{
    QMutexLocker locker(&this->m_mutex);
    this->m_tasks.push_back(task);
    this->m_waitCondition.wakeAll();
}

bool AuthenticationController::isGraphical(const QString& pamService)
{

    bool isGraphcal = false;

    //TODO: polkit通过服务名判断是否图形还是命令行登录方式
    
    if ( pamService == "lightdm" )
    {
        isGraphcal = true;
    }
    else if( pamService == "polkit-1" )
    {
        auto ppid = getppid();
        QFile file(QString("/proc/%1/cmdline").arg(ppid));
        if( file.open(QIODevice::ReadOnly) )
        {
            QString cmdline = file.readAll();
            this->m_pamHandle->syslogDirect(LOG_DEBUG, cmdline);
            isGraphcal = cmdline.contains("kiran-polkit-agent");
        }
    }else if( pamService == "kiran-screensaver" )
    {
        isGraphcal = true;
    }

    this->m_pamHandle->syslogDirect(LOG_DEBUG, QString("is graphical: service(%1) result=%4").arg(pamService).arg(isGraphcal));
    return isGraphcal;
}

}  // namespace Kiran
