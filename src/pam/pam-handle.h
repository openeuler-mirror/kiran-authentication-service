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

#include <QObject>

struct pam_message;
struct pam_response;

namespace Kiran
{
class TaskPool;

// 默认跨线程执行，如果不需要跨线程，则选择以Direct结尾的函数
class PAMHandle : QObject
{
    Q_OBJECT
public:
    PAMHandle(void *pamh, TaskPool *taskPool, QObject *parent = nullptr);
    virtual ~PAMHandle(){};

    void *getPamh() { return this->m_pamh; };

    QString getItemDirect(int itemType);
    QString getItem(int itemType);
    void setItem(int itemType, const QString &value);
    void syslogDirect(int priority, const QString& log);
    void syslog(int priority, const QString &log);
    // PAM结束
    void finish(int result);

    // 发送需要响应的消息
    int32_t sendSecretPrompt(const QString &request, QString &response);
    int32_t sendQuestionPrompt(const QString &request, QString &response);
    // 发送不需要响应的消息
    int32_t sendErrorMessage(const QString &message);
    int32_t sendTextMessage(const QString &message);

private:
    int32_t send(const QString &request, int32_t requestType, QString &response);
    int32_t send(const struct pam_message **request, struct pam_response **response);

private:
    void *m_pamh;
    TaskPool *m_taskPool;
};

}  // namespace Kiran
