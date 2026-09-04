/**
 * Copyright (c) 2026-2029 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     licheng <licheng@kylinsec.com.cn>
 */
#pragma once

#include <QString>

namespace Kiran
{
/**
 * @brief 从 PAM_RHOST 解析客户端 IP
 *
 * 仅信任 pam_get_item(PAM_RHOST)，不做 SSH 环境变量或 getpeername 等自研回落。
 * 对 RHOST 做去方括号 / 截断 %zone 规范化后，须为 IPv4/IPv6 字面量才返回。
 *
 * @param[in] rhost pam_get_item(PAM_RHOST) 结果，可为空
 * @return 客户端 IP；为空、主机名或非 IP 时返回空串
 */
QString sshClientIpFromRhost(const QString& rhost);

}  // namespace Kiran
