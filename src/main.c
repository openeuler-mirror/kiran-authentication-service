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
