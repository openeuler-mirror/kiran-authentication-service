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
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include "authentication_i.h"
#include "kiran-authentication-gen.h"

typedef struct
{
    GMainLoop *loop;
    gchar *username;
    gboolean state;
    gchar *sid;
} verify_data;

static int
converse(pam_handle_t *pamh, int nargs,
         const struct pam_message **message,
         struct pam_response **response)
{
    struct pam_conv *conv;
    int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }
    return conv->conv(nargs, message, response, conv->appdata_ptr);
}

char *
request_respone(pam_handle_t *pamh, int echocode, const char *prompt)
{
    char *ret = NULL;
    const struct pam_message msg = {
        .msg_style = echocode,
        .msg = prompt,
    };
    const struct pam_message *msgs = &msg;
    struct pam_response *resp = NULL;

    int retval = converse(pamh, 1, &msgs, &resp);

    if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
        resp->resp[0] == '\0')
    {
        if (retval == PAM_SUCCESS && resp && resp->resp)
        {
            ret = resp->resp;
        }
    }
    else
    {
        ret = resp->resp;
    }

    if (resp)
    {
        if (!ret)
        {
            free(resp->resp);
        }
        free(resp);
    }

    return ret;
}

static void
auth_status_cb(KiranAuthenticationGen *object,
               const gchar *arg_username,
               gint arg_state,
               const gchar *arg_sid,
               gpointer user_data)
{
    verify_data *data = user_data;

    if (g_strcmp0(data->sid, arg_sid) == 0)
    {
        data->state = arg_state;
        data->username = g_strdup(arg_username);
        g_main_loop_quit(data->loop);
    }
}

static gboolean
verify_timeout_cb(gpointer user_data)
{
    verify_data *data = user_data;

    g_main_loop_quit(data->loop);

    return FALSE;
}

static gboolean
verify_user(pam_handle_t *pamh)
{
    GDBusConnection *connection;
    KiranAuthenticationGen *auth;
    verify_data *data;
    GError *error;
    gboolean ret;
    char *sid;
    GSource *source;

    error = NULL;
    connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (connection == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "Error with getting the bus: %s", error->message);
        g_error_free(error);
        return FALSE;
    }

    error = NULL;
    auth = kiran_authentication_gen_proxy_new_sync(connection,
                                                   G_BUS_NAME_WATCHER_FLAGS_NONE,
                                                   AUTH_SERVICE_DBUS_NAME,
                                                   AUTH_SERVICE_OBJECT_PATH,
                                                   NULL,
                                                   &error);
    if (auth == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "Error with getting the bus: %s", error->message);
        g_object_unref(connection);
        g_error_free(error);
        return FALSE;
    }


    data = g_new0(verify_data, 1);
    data->loop = g_main_loop_new(NULL, FALSE);
    data->state = SESSION_AUTH_FAIL;
    //请求开启认证
    data->sid = request_respone(pamh, PAM_PROMPT_ECHO_ON, ASK_AUTH_SID);
    if (!data->sid || (g_strcmp0(data->sid, "") == 0))
    {
        pam_syslog(pamh, LOG_ERR, "Request create auth failed!");
        goto end;
    }

    g_signal_connect(auth,
                     "auth-status",
                     G_CALLBACK(auth_status_cb),
                     data);

    source = g_timeout_source_new_seconds(120);
    g_source_attach(source, g_main_loop_get_context(data->loop));
    g_source_set_callback(source, verify_timeout_cb, data, NULL);

    g_main_loop_run(data->loop);
    g_source_destroy(source);
    g_source_unref(source);

end:
    //认证结果
    ret = (data->state == SESSION_AUTH_SUCCESS) ? TRUE : FALSE;
    if (ret)
    {
        //认证成功,设置用户
        pam_set_item(pamh, PAM_USER, data->username);
    }

    g_object_unref(connection);
    g_object_unref(auth);

    g_main_loop_unref(data->loop);

    g_free(data->sid);
    g_free(data->username);
    g_free(data);

    return ret;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *rhost = NULL;
    guint i;
    int ret;

#if !GLIB_CHECK_VERSION(2, 36, 0)
    g_type_init();
#endif
    pam_get_item(pamh, PAM_RHOST, (const void **)(const void *)&rhost);

    if (rhost != NULL &&
        *rhost != '\0' &&
        strcmp(rhost, "localhost") != 0)
    {
        return PAM_AUTHINFO_UNAVAIL;
    }

    ret = verify_user(pamh);

    return (ret == TRUE) ? PAM_SUCCESS : PAM_AUTH_ERR;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags,
                   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                     int argc, const char **argv)
{
    return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags,
                        int argc, const char **argv)
{
    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags,
                         int argc, const char **argv)
{
    return PAM_SUCCESS;
}
