/**
 * Copyright (c) 2020 ~ 2021 KylinSec Co., Ltd. 
 * kiran-cc-daemon is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2. 
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2 
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, 
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, 
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.  
 * See the Mulan PSL v2 for more details.  
 * 
 * Author:     wangxiaoqing <wangxiaoqing@kylinos.com.cn>
 */

#include <glib.h>
#include <locale.h>
#ifdef ENABLE_ZLOG_EX
#include <zlog_ex.h>
#else
#include <zlog.h>
#endif
#include "config.h"
#include "kiran-auth-service.h"

int main(int argc, char *argv[])
{
    GMainLoop *loop;
    KiranAuthService *service;

    setlocale(LC_CTYPE, "");
    setlocale(LC_MESSAGES, "");
    setlocale(LC_ALL, "");
    bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
    textdomain(GETTEXT_PACKAGE);

#ifdef ENABLE_ZLOG_EX
    if (dzlog_init_ex(NULL, "kylinsec-system", "kiran-authentication-service", "kiran_authentication_service") < 0)
#else
    if (dzlog_init("/etc/zlog.conf", "kylinsec-system") < 0)
#endif
    {
        g_error("zlog init failed!");
        return -1;
    }

#if !GLIB_CHECK_VERSION(2, 36, 0)
    g_type_init();
#endif

    dzlog_info("Start kiran authentication service.");
    loop = g_main_loop_new(NULL, FALSE);
    service = kiran_auth_servie_new();

    g_main_loop_run(loop);

    g_main_loop_unref(loop);
    g_object_unref(service);
    zlog_fini();

    return 0;
}
