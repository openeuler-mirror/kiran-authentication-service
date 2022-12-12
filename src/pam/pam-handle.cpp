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

#include "src/pam/pam-handle.h"
#include <auxiliary.h>
#include <pam_ext.h>
#include <pam_modules.h>
#include <QFuture>
#include <QFutureInterface>
#include <QPair>
#include <QTextCodec>
#include <functional>
#include "src/pam/task-pool.h"

typedef QPair<int, QString> QPairIS;

Q_DECLARE_METATYPE(QFutureInterface<int>);
Q_DECLARE_METATYPE(QFutureInterface<bool>);
Q_DECLARE_METATYPE(QFutureInterface<QString>);
Q_DECLARE_METATYPE(QFutureInterface<QPairIS>);

namespace Kiran
{
PAMHandle::PAMHandle(void *pamh,
                     TaskPool *taskPool,
                     QObject *parent) : QObject(parent),
                                        m_pamh(pamh),
                                        m_taskPool(taskPool)
{
    qRegisterMetaType<QFutureInterface<int>>();
    qRegisterMetaType<QFutureInterface<bool>>();
    qRegisterMetaType<QFutureInterface<QString>>();
    qRegisterMetaType<QFutureInterface<QPairIS>>();
}

QString PAMHandle::getItemDirect(int itemType)
{
    const char *value = NULL;
    pam_get_item((const pam_handle_t *)this->m_pamh, itemType, (const void **)&value);
    return QString(value);
}

QString PAMHandle::getItem(int itemType)
{
    QFutureInterface<QString> futureInterface;
    futureInterface.reportStarted();

    this->m_taskPool->pushTask([this, itemType, &futureInterface]()
                               {
                                   auto value = this->getItemDirect(itemType);
                                   futureInterface.reportFinished(&value);
                               });
    auto future = futureInterface.future();
    return future.result();
}

void PAMHandle::setItem(int itemType, const QString &value)
{
    QFutureInterface<bool> futureInterface;
    futureInterface.reportStarted();

    this->m_taskPool->pushTask([this, itemType, &value, &futureInterface]()
                               {
                                   pam_set_item((pam_handle_t *)this->getPamh(), itemType, value.toStdString().c_str());
                                   futureInterface.reportResult(true);
                                   futureInterface.reportFinished();
                               });
    futureInterface.future().result();
    return;
}

void PAMHandle::syslog(int priority, const QString &log)
{
    QFutureInterface<bool> futureInterface;
    futureInterface.reportStarted();

    this->m_taskPool->pushTask([this, priority, &log, &futureInterface]()
                               {
                                   pam_syslog((const pam_handle_t *)this->getPamh(), priority, log.toStdString().c_str());
                                   futureInterface.reportResult(true);
                                   futureInterface.reportFinished();
                               });
    futureInterface.future().result();
    return;
}

void PAMHandle::finish(int result)
{
    auto taskPool = this->m_taskPool;
    this->m_taskPool->pushTask([this, taskPool, result]()
                               { taskPool->stopTask(result); });
    return;
}

int32_t PAMHandle::sendSecretPrompt(const QString &request, QString &response)
{
    return this->send(request, PAM_PROMPT_ECHO_OFF, response);
}

int32_t PAMHandle::sendQuestionPrompt(const QString &request, QString &response)
{
    return this->send(request, PAM_PROMPT_ECHO_ON, response);
}

int32_t PAMHandle::sendErrorMessage(const QString &message)
{
    QString response;
    return this->send(message, PAM_ERROR_MSG, response);
}

int32_t PAMHandle::sendTextMessage(const QString &message)
{
    QString response;
    return this->send(message, PAM_TEXT_INFO, response);
}

int32_t PAMHandle::send(const QString &request, int32_t requestType, QString &response)
{
    QFutureInterface<QPairIS> futureInterface;
    futureInterface.reportStarted();

    // 跟locale的编码保持一致，以免出现乱码问题
    auto requestLocale = QTextCodec::codecForLocale()->fromUnicode(request);

    this->m_taskPool->pushTask(
        [this, &requestLocale, requestType, &futureInterface]()
        {
            pam_message *pamRequest = new pam_message{
                .msg_style = requestType,
                .msg = requestLocale.data()};

            SCOPE_EXIT(
                {
                    if (pamRequest)
                    {
                        delete pamRequest;
                    }
                });

            struct pam_response *pamResponse = NULL;
            auto retval = this->send((const struct pam_message **)&pamRequest, &pamResponse);
            if (retval != PAM_SUCCESS)
            {
                futureInterface.reportResult(qMakePair(int(retval), QString()));
            }
            else
            {
                futureInterface.reportResult(qMakePair(int(PAM_SUCCESS), QString(pamResponse->resp)));
            }
        });

    auto future = futureInterface.future();
    auto result = future.result();
    RETURN_VAL_IF_TRUE(result.first != PAM_SUCCESS, result.first);
    response = result.second;
    return PAM_SUCCESS;
}

int32_t PAMHandle::send(const struct pam_message **request, struct pam_response **response)
{
    struct pam_conv *conv;
    auto retval = pam_get_item((const pam_handle_t *)this->m_pamh, PAM_CONV, (const void **)&conv);
    RETURN_VAL_IF_TRUE(retval != PAM_SUCCESS, retval);
    return conv->conv(1, request, response, conv->appdata_ptr);
}

}  // namespace Kiran
