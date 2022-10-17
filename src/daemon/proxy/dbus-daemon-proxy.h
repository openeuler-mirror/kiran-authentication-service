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

#include <QDBusMessage>
#include <QObject>
#include <QSharedPointer>

namespace Kiran
{
class DBusDaemonProxy : public QObject
{
    Q_OBJECT
public:
    DBusDaemonProxy();
    virtual ~DBusDaemonProxy(){};

    static QSharedPointer<DBusDaemonProxy> getDefault();
    // 获取调用者的pid
    int64_t getConnectionUnixProcessID(const QDBusMessage& message);
    // 获取调用者的uid
    int64_t getConnectionUnixUser(const QDBusMessage& message);

private:
    static QSharedPointer<DBusDaemonProxy> m_instance;
};

}  // namespace Kiran
