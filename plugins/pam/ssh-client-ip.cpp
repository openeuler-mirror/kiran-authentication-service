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

#include "ssh-client-ip.h"

#include <arpa/inet.h>
#include <netinet/in.h>

namespace Kiran
{
namespace
{
bool isIpLiteralCStr(const char* s)
{
    struct in_addr a4;
    struct in6_addr a6;

    if (s == nullptr || s[0] == '\0')
    {
        return false;
    }
    if (inet_pton(AF_INET, s, &a4) == 1)
    {
        return true;
    }
    if (inet_pton(AF_INET6, s, &a6) == 1)
    {
        return true;
    }
    return false;
}

QString normalizeRhost(const QString& rhost)
{
    QString value = rhost.trimmed();
    if (value.isEmpty())
    {
        return QString();
    }
    if (value.startsWith(QLatin1Char('[')))
    {
        const int rb = value.indexOf(QLatin1Char(']'));
        if (rb > 1)
        {
            value = value.mid(1, rb - 1);
        }
    }
    const int zone = value.indexOf(QLatin1Char('%'));
    if (zone >= 0)
    {
        value = value.left(zone);
    }
    return value.trimmed();
}

}  // namespace

QString sshClientIpFromRhost(const QString& rhost)
{
    const QString norm = normalizeRhost(rhost);
    if (norm.isEmpty())
    {
        return QString();
    }
    if (!isIpLiteralCStr(norm.toUtf8().constData()))
    {
        return QString();
    }
    return norm;
}

}  // namespace Kiran
