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

#include <QStringList>

namespace Kiran
{
// 执行认证操作，认证失败则累计失败次数
#define KAP_ARG_ACTION_DO_AUTH "doauth"
// 表示认证已经通过，这里会清理失败次数
#define KAP_ARG_ACTION_AUTH_SUCC "authsucc"
struct PAMArgsInfo
{
    QString action;
};

class PAMArgsParser
{
public:
    PAMArgsParser();
    virtual ~PAMArgsParser(){};

    PAMArgsInfo parser(const QStringList &arguments);
};

}  // namespace Kiran
