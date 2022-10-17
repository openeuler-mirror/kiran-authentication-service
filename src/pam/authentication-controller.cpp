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
#include <QFuture>
#include <QMutexLocker>
#include "src/pam/authentication-graphical.h"
#include "src/pam/authentication-terminal.h"
#include "src/pam/pam-handle.h"

namespace Kiran
{
AuthenticationController::AuthenticationController(void* pamh) : isRunning(false),
                                                                 m_result(PAM_SUCCESS)
{
    this->m_pamHandle = new PAMHandle(pamh, this, this);

    auto pamService = this->m_pamHandle->getItemDirect(PAM_SERVICE);
    if (this->isGraphical(pamService))
    {
        this->m_authentication = new AuthenticationGraphical(this->m_pamHandle);
    }
    else
    {
        this->m_authentication = new AuthenticationTerminal(this->m_pamHandle);
    }

    this->m_authentication->moveToThread(&this->m_workerThread);
    connect(&this->m_workerThread, &QThread::finished, this->m_authentication, &QObject::deleteLater);
    connect(this, &AuthenticationController::startAuthentication, this->m_authentication, &Authentication::start);
    this->m_workerThread.start();
}

int32_t AuthenticationController::run()
{
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
    switch (shash(pamService.toStdString().c_str()))
    {
    case "lightdm"_hash:
        return true;
    default:
        break;
    }
    return false;
}

}  // namespace Kiran
