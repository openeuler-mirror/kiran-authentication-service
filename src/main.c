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
#include <zlog_ex.h>
#include "kiran-auth-service.h"

int main(int argc, char *argv[])
{
    GMainLoop *loop;
    KiranAuthService *service;

    setlocale(LC_CTYPE, "");
    setlocale(LC_MESSAGES, "");

    if (dzlog_init_ex(NULL,
                      "kylinsec-system-app",
                      "kiran-authentication",
                      "kiran_authentication_manager") < 0)
        return -1;

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
