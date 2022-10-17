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

#include <QList>
#include <QMutex>
#include <QThread>
#include <QWaitCondition>
#include "src/pam/task-pool.h"

namespace Kiran
{
class Authentication;
class PAMHandle;

class AuthenticationController : public QObject,
                                 public TaskPool
{
    Q_OBJECT
public:
    AuthenticationController(void* pamh);
    virtual ~AuthenticationController(){};

    int32_t run();

    virtual void pushTask(std::function<void(void)> task);
    virtual void stopTask(int result);

Q_SIGNALS:
    void startAuthentication();

private:
    // 判断当前认证是否为图形模式
    bool isGraphical(const QString& pamService);

private:
    PAMHandle* m_pamHandle;
    QThread m_workerThread;
    Authentication* m_authentication;
    bool isRunning;
    int m_result;

    QMutex m_mutex;
    QWaitCondition m_waitCondition;
    QList<std::function<void(void)>> m_tasks;
};

}  // namespace Kiran
