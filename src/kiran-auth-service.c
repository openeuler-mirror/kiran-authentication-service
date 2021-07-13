/**
 *@file kiran-auth-service.c
 *@brief 实现DBus服务的认证接口
 *@author wangxiaoqing <wangxiaoqing@kylinos.com.cn>
 *@copyright(c) 2021 KylinSec.All rights reserved.
 */
#include "kiran-auth-service.h"
#include <json-glib/json-glib.h>
#include <security/pam_appl.h>
#include <zlog_ex.h>
#include <kiran-cc-daemon/kiran-system-daemon/accounts-i.h>
#include "authentication_i.h"
#include "kiran-accounts-gen.h"
#include "kiran-biometrics-gen.h"
#include "kiran-user-gen.h"

#define MAX_THREAD_NUM 50
#define CONF_FILE "/etc/kiran-authentication-service/custom.conf"
#define SERVICE "kiran-auth-service"

typedef struct _AuthSession AuthSession;

/*
 * 认证会话结构体，保存每个会话的
 * 状态信息
 *
 */
struct _AuthSession
{
    //会话ID
    char *sid;
    //认证的用户名称
    char *username;
    //用户认证模式
    int user_auth_mode;
    //会话认证方式
    int session_auth_type;
    //是否抢占设备
    gboolean occupy;
    //绑定指纹的id
    char *fprint_id;

    //是否已经开始认证
    gboolean is_start;
    gboolean have_fingerprint_auth;

    //调用者dbus连接
    char *sender;

    pam_handle_t *pam_handle;
    GCond prompt_cond;
    GMutex prompt_mutex;
    gchar *respons_msg;
    gboolean stop_auth;
    GCond stop_cond;
    GMutex stop_mutex;

    KiranAuthService *service;
};

struct _KiranAuthServicePrivate
{
    guint bus_name_id;

    //认证列表
    GList *auth_list;
    //认证线程池
    GThreadPool *auth_thread_pool;
    //默认的会话认证类型
    int default_session_auth_type;

    KiranBiometrics *biometrics;
    KiranAccounts *accounts;

    //当前进行指纹认证的会话
    AuthSession *cur_fprint_session;

    GDBusConnection *connection;
};

static void kiran_authentication_gen_init(KiranAuthenticationGenIface *iface);

#define KIRAN_AUTH_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE((o), \
                                                                       KIRAN_TYPE_AUTH_SERVICE, KiranAuthServicePrivate))

G_DEFINE_TYPE_WITH_CODE(KiranAuthService, kiran_auth_service, KIRAN_TYPE_AUTHENTICATION_GEN_SKELETON,
                        G_IMPLEMENT_INTERFACE(KIRAN_TYPE_AUTHENTICATION_GEN, kiran_authentication_gen_init))

static void do_session_passwd_auth(KiranAuthService *service,
                                   AuthSession *session);
static int
default_session_auth_setting(KiranAuthService *service)
{
    KiranAuthServicePrivate *priv = service->priv;
    GKeyFile *key_file = NULL;
    GError *error = NULL;
    int session_auth_type;
    gboolean ret;
    int value;

    key_file = g_key_file_new();

    ret = g_key_file_load_from_file(key_file,
                                    CONF_FILE,
                                    G_KEY_FILE_NONE,
                                    &error);
    if (!ret)
    {
        dzlog_error("Key file load fialed: %s", error->message);
        g_error_free(error);
        return session_auth_type;
    }

    error = NULL;

    /*
     *获取会话认证类型：
     * 1 标识串行
     * 2 标识并行
     * 3 标识并行,指定用户认证
     * 其它的不识别
     */
    value = g_key_file_get_integer(key_file,
                                   "daemon",
                                   "SessionAuthType",
                                   NULL);

    switch (value)
    {
    case 2:
        session_auth_type = SESSION_AUTH_TYPE_TOGETHER;
        break;

    case 3:
        session_auth_type = SESSION_AUTH_TYPE_TOGETHER_WITH_USER;
        break;

    default:
        session_auth_type = SESSION_AUTH_TYPE_ONE;
        break;
    }

    g_key_file_free(key_file);
    key_file = NULL;

    priv->default_session_auth_type = session_auth_type;
}

static void
auth_session_free(gpointer data)
{
    AuthSession *session = data;

    g_mutex_clear(&session->prompt_mutex);
    g_cond_clear(&session->prompt_cond);
    g_mutex_clear(&session->stop_mutex);
    g_cond_clear(&session->stop_cond);

    g_free(session->username);
    g_free(session->sender);
    g_free(session->fprint_id);
    g_free(session);
}

static void
kiran_auth_service_finalize(GObject *object)
{
    KiranAuthService *service = KIRAN_AUTH_SERVICE(object);
    KiranAuthServicePrivate *priv = service->priv;

    if (priv->bus_name_id > 0)
    {
        g_bus_unown_name(priv->bus_name_id);
        priv->bus_name_id = 0;
    }

    if (priv->biometrics)
    {
        g_object_unref(priv->biometrics);
        priv->biometrics = NULL;
    }

    if (priv->accounts)
    {
        g_object_unref(priv->accounts);
        priv->accounts = NULL;
    }

    g_list_free_full(priv->auth_list, auth_session_free);
    priv->auth_list = NULL;

    g_thread_pool_free(priv->auth_thread_pool,
                       TRUE,
                       TRUE);

    priv->auth_thread_pool = NULL;

    G_OBJECT_CLASS(kiran_auth_service_parent_class)->finalize(object);
}

static void
verify_fprint_status_cb(KiranBiometrics *object,
                        const gchar *arg_result,
                        gboolean arg_done,
                        gboolean arg_found,
                        const gchar *arg_id,
                        gpointer user_data)
{
    KiranAuthService *service = KIRAN_AUTH_SERVICE(user_data);
    KiranAuthServicePrivate *priv = service->priv;
    AuthSession *session = priv->cur_fprint_session;

    if (!session)
    {
        return;
    }

    dzlog_debug("verify_fprint_status: %s, %d, %d, %s\n",
                arg_result,
                arg_done,
                arg_found,
                arg_id);

    //发送认证消息
    kiran_authentication_gen_emit_auth_messages(KIRAN_AUTHENTICATION_GEN(service),
                                                arg_result,
                                                PAM_TEXT_INFO,
                                                session->sid);

    if (session->session_auth_type == SESSION_AUTH_TYPE_TOGETHER)
    {
        if (arg_found)
        {
            char *username = NULL;

            //查找绑定的用户

            if (username)
            {
                //停止指纹认证
                kiran_biometrics_call_verify_fprint_stop_sync(priv->biometrics, NULL, NULL);
                priv->cur_fprint_session = NULL;
                //指纹认证成功
                kiran_authentication_gen_emit_auth_status(KIRAN_AUTHENTICATION_GEN(service),
                                                          username,
                                                          SESSION_AUTH_SUCCESS,
                                                          session->sid);
            }
        }
    }
    else if (session->session_auth_type == SESSION_AUTH_TYPE_TOGETHER_WITH_USER)
    {
        //对当前用户的指纹进行认证
        if (arg_found && g_strcmp0(arg_id, session->fprint_id) == 0)
        {
            //停止指纹认证
            kiran_biometrics_call_verify_fprint_stop_sync(priv->biometrics, NULL, NULL);
            priv->cur_fprint_session = NULL;
            //指纹认证成功
            kiran_authentication_gen_emit_auth_status(KIRAN_AUTHENTICATION_GEN(service),
                                                      session->username,
                                                      SESSION_AUTH_SUCCESS,
                                                      session->sid);
        }
    }
    else
    {
        if (arg_found && g_strcmp0(arg_id, session->fprint_id) == 0)
        {
            //停止指纹认证
            kiran_biometrics_call_verify_fprint_stop_sync(priv->biometrics, NULL, NULL);
            priv->cur_fprint_session = NULL;

            if (session->user_auth_mode & ACCOUNTS_AUTH_MODE_PASSWORD)
            {
                //进行串行认证，指纹通过，启动密码认证
                do_session_passwd_auth(service, session);
            }
            else
            {
                kiran_authentication_gen_emit_auth_status(KIRAN_AUTHENTICATION_GEN(service),
                                                          session->username,
                                                          SESSION_AUTH_SUCCESS,
                                                          session->sid);
            }
            return;
        }

        if (arg_done)
        {
            //认证失败
            kiran_authentication_gen_emit_auth_status(KIRAN_AUTHENTICATION_GEN(service),
                                                      session->username,
                                                      SESSION_AUTH_FAIL,
                                                      session->sid);
        }
    }
}

static AuthSession *
find_auth_session_by_sender(KiranAuthService *service,
                            const char *sender)
{
    KiranAuthServicePrivate *priv = service->priv;
    GList *iter = priv->auth_list;

    for (; iter; iter = iter->next)
    {
        AuthSession *session = iter->data;

        if (g_strcmp0(session->sender, sender) == 0)
        {
            return session;
        }
    }

    return NULL;
}

static void
auth_session_stop(KiranAuthService *service,
                  AuthSession *session)
{
    KiranAuthServicePrivate *priv = service->priv;

    if (session == priv->cur_fprint_session)
    {
        //停止指纹认证
        kiran_biometrics_call_verify_fprint_stop_sync(priv->biometrics, NULL, NULL);
        priv->cur_fprint_session = NULL;
    }

    //停止密码认证
    if (session->pam_handle)
    {
        session->stop_auth = TRUE;
        g_mutex_lock(&session->stop_mutex);
        g_cond_wait(&session->stop_cond, &session->stop_mutex);
        g_mutex_unlock(&session->stop_mutex);
    }

    //删除该会话
    priv->auth_list = g_list_remove(priv->auth_list, session);
    auth_session_free(session);
}

static void
on_name_lost(GDBusConnection *connection,
             const gchar *sender_name,
             const gchar *object_path,
             const gchar *interface_name,
             const gchar *signal_name,
             GVariant *parameters,
             gpointer user_data)
{
    KiranAuthService *service = KIRAN_AUTH_SERVICE(user_data);
    KiranAuthServicePrivate *priv = service->priv;
    AuthSession *session = NULL;
    GVariant *value;
    const gchar *first;
    const gchar *last;
    gsize length;
    gsize i;

    length = g_variant_n_children(parameters);

    if (length < 1)
        return;

    value = g_variant_get_child_value(parameters, 0);
    first = g_variant_get_string(value, NULL);

    value = g_variant_get_child_value(parameters, length - 1);
    last = g_variant_get_string(value, NULL);

    session = find_auth_session_by_sender(service, first);

    if (session && (g_strcmp0(last, "") == 0))
    {
        //dbus连接断开，停止本次认证
        auth_session_stop(service, session);
    }
}

static void
bus_acquired_cb(GDBusConnection *connection,
                const char *name,
                gpointer user_data)
{
    KiranAuthService *service = KIRAN_AUTH_SERVICE(user_data);
    KiranAuthServicePrivate *priv = service->priv;
    GDBusInterfaceSkeleton *skeleton = G_DBUS_INTERFACE_SKELETON(service);
    GError *error = NULL;

    priv->connection = connection;
    g_dbus_interface_skeleton_export(skeleton,
                                     connection,
                                     AUTH_SERVICE_OBJECT_PATH,
                                     &error);

    if (error != NULL)
    {
        dzlog_error("Failed export interface: %s", error->message);
        g_error_free(error);
    }

    error = NULL;
    priv->biometrics = kiran_biometrics_proxy_new_sync(connection,
                                                       G_BUS_NAME_WATCHER_FLAGS_NONE,
                                                       "com.kylinsec.Kiran.SystemDaemon.Biometrics",
                                                       "/com/kylinsec/Kiran/SystemDaemon/Biometrics",
                                                       NULL,
                                                       &error);
    if (priv->biometrics)
    {
        g_signal_connect(priv->biometrics,
                         "verify-fprint-status",
                         G_CALLBACK(verify_fprint_status_cb),
                         service);
    }
    else
    {
        dzlog_error("Failed biometrics new: %s", error->message);
        g_error_free(error);
    }

    error = NULL;
    priv->accounts = kiran_accounts_proxy_new_sync(connection,
                                                   G_BUS_NAME_WATCHER_FLAGS_NONE,
                                                   ACCOUNTS_DBUS_NAME,
                                                   ACCOUNTS_OBJECT_PATH,
                                                   NULL,
                                                   &error);
    if (priv->accounts == NULL)
    {
        dzlog_error("Error with getting the bus: %s", error->message);
        g_error_free(error);
    }

    //监听bus总线信号
    g_dbus_connection_signal_subscribe(connection,
                                       "org.freedesktop.DBus",
                                       "org.freedesktop.DBus",
                                       NULL,
                                       "/org/freedesktop/DBus",
                                       NULL,
                                       G_DBUS_SIGNAL_FLAGS_NONE,
                                       (GDBusSignalCallback)on_name_lost,
                                       service, NULL);
}

static AuthSession *
find_auth_session_by_sid(KiranAuthService *service,
                         const char *sid)
{
    KiranAuthServicePrivate *priv = service->priv;
    GList *iter = priv->auth_list;

    for (; iter; iter = iter->next)
    {
        AuthSession *session = iter->data;

        if (g_strcmp0(session->sid, sid) == 0)
        {
            return session;
        }
    }

    return NULL;
}

static gboolean
kiran_auth_service_handle_create_auth(KiranAuthenticationGen *object,
                                      GDBusMethodInvocation *invocation)
{
    KiranAuthService *service = KIRAN_AUTH_SERVICE(object);
    KiranAuthServicePrivate *priv = service->priv;
    AuthSession *new_auth_session = NULL;
    AuthSession *session = NULL;
    gchar *sid = g_uuid_string_random();
    const gchar *sender;

    sender = g_dbus_method_invocation_get_sender(invocation);

    session = find_auth_session_by_sender(service, sender);
    if (session)
    {
        //每个连接只允许创建一个认证
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_INVALID_ARGS,
                                              "Have create a auth with connection");
        return TRUE;
    }

    session = find_auth_session_by_sid(service, sid);
    while (session != NULL)
    {
        //如果生成sid已经被占用，则重新生成
        g_free(sid);
        sid = g_uuid_string_random();
        session = find_auth_session_by_sid(service, sid);
    }

    new_auth_session = g_new0(AuthSession, 1);
    new_auth_session->sid = sid;

    if (sender)
        new_auth_session->sender = g_strdup(sender);

    //添加到会话列表中
    priv->auth_list = g_list_append(priv->auth_list, new_auth_session);

    g_dbus_method_invocation_return_value(invocation,
                                          g_variant_new("(s)", new_auth_session->sid));

    return TRUE;
}

static char *
parser_auth_items_json_data(const char *data)
{
    JsonParser *jparse = json_parser_new();
    JsonNode *root;
    JsonReader *reader;
    GError *error = NULL;
    char *id = NULL;
    gboolean ret;

    ret = json_parser_load_from_data(jparse,
                                     data,
                                     -1,
                                     &error);
    if (!ret)
    {
        dzlog_error("Error with parse json data: %s", error->message);
        g_error_free(error);
        return NULL;
    }

    root = json_parser_get_root(jparse);
    if (json_node_get_node_type(root) == JSON_NODE_ARRAY)
    {
        JsonArray *array = json_node_get_array(root);
        GList *list = json_array_get_elements(array);
        GList *iter;

        reader = json_reader_new(NULL);
        for (iter = list; iter; iter = iter->next)
        {
            const gchar *data_id;

            json_reader_set_root(reader, iter->data);
            json_reader_read_member(reader, "data_id");
            data_id = json_reader_get_string_value(reader);
            if (data_id)
            {
                id = strdup(data_id);
                break;
            }
        }
        g_object_unref(reader);
    }

    g_object_unref(jparse);

    return id;
}

static void
get_user_account_info(KiranAuthService *service,
                      AuthSession *session)
{
    KiranAuthServicePrivate *priv = service->priv;
    KiranAccountsUser *user = NULL;
    GError *error = NULL;
    gchar *path = NULL;
    gchar *auth = NULL;
    gchar *auth_items = NULL;
    gboolean ret;

    session->user_auth_mode = ACCOUNTS_AUTH_MODE_NONE;
    path = NULL;
    error = NULL;

    ret = kiran_accounts_call_find_user_by_name_sync(priv->accounts,
                                                     session->username,
                                                     &path,
                                                     NULL,
                                                     &error);
    if (!ret)
    {
        dzlog_error("Error with find the user object path: %s", error->message);
        g_error_free(error);
    }

    error = NULL;
    user = kiran_accounts_user_proxy_new_sync(priv->connection,
                                              G_BUS_NAME_WATCHER_FLAGS_NONE,
                                              ACCOUNTS_DBUS_INTERFACE_NAME,
                                              path,
                                              NULL,
                                              &error);
    g_free(path);

    if (user == NULL)
    {
        dzlog_error("Error with getting the bus: %s", error->message);
        g_error_free(error);
    }

    session->user_auth_mode = kiran_accounts_user_get_auth_modes(user);

    error = NULL;
    ret = kiran_accounts_user_call_get_auth_items_sync(user,
                                                       ACCOUNTS_AUTH_MODE_FINGERPRINT,
                                                       &auth_items,
                                                       NULL,
                                                       &error);
    if (!ret || !auth_items)
    {
        dzlog_error("Error with getting the auth item: %s", error->message);
        g_error_free(error);
    }
    else
    {
        session->fprint_id = parser_auth_items_json_data(auth_items);
    }

    g_object_unref(user);
}

static gboolean
kiran_auth_service_handle_start_auth(KiranAuthenticationGen *object,
                                     GDBusMethodInvocation *invocation,
                                     const gchar *arg_username,
                                     const gchar *arg_sid,
                                     gint arg_type_op,
                                     gboolean arg_occupy)
{
    KiranAuthService *service = KIRAN_AUTH_SERVICE(object);
    KiranAuthServicePrivate *priv = service->priv;
    AuthSession *session = NULL;
    GError *error = NULL;
    gboolean ret = FALSE;

    session = find_auth_session_by_sid(service, arg_sid);
    if (session == NULL)
    {
        //不存在对应的会话
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_INVALID_ARGS,
                                              "The auth session id %s not existed",
                                              arg_sid);
        return TRUE;
    }

    if (session->is_start)
    {
        //该会话正在进行中
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_INVALID_ARGS,
                                              "The auth session already runnig");
        return TRUE;
    }

    g_free(session->username);
    session->username = g_strdup(arg_username);

    if (arg_type_op == SESSION_AUTH_TYPE_ONE ||
        arg_type_op == SESSION_AUTH_TYPE_TOGETHER ||
        arg_type_op == SESSION_AUTH_TYPE_TOGETHER_WITH_USER)
    {
        session->session_auth_type = arg_type_op;
    }
    else
    {  //使用默认的认证方式
        session->session_auth_type = priv->default_session_auth_type;
    }

    session->occupy = arg_occupy;
    get_user_account_info(service, session);
    session->stop_auth = FALSE;
    session->service = service;

    g_mutex_init(&session->prompt_mutex);
    g_cond_init(&session->prompt_cond);
    g_mutex_init(&session->stop_mutex);
    g_cond_init(&session->stop_cond);

    ret = g_thread_pool_push(priv->auth_thread_pool,
                             session,
                             &error);
    if (!ret)
    {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_INVALID_ARGS,
                                              "Push to auth thread pool failed: %s",
                                              error->message);
        dzlog_error("ush to auth thread pool failed: %s", error->message);
        g_error_free(error);
    }
}

static gboolean
kiran_auth_service_handle_stop_auth(KiranAuthenticationGen *object,
                                    GDBusMethodInvocation *invocation,
                                    const gchar *arg_sid)
{
    KiranAuthService *service = KIRAN_AUTH_SERVICE(object);
    KiranAuthServicePrivate *priv = service->priv;
    AuthSession *session = NULL;

    session = find_auth_session_by_sid(service, arg_sid);
    if (session == NULL)
    {
        //不存在对应的会话
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_INVALID_ARGS,
                                              "The auth session id %s not existed",
                                              arg_sid);
        return TRUE;
    }

    auth_session_stop(service, session);

    return TRUE;
}

static gboolean
kiran_auth_service_handle_response_message(KiranAuthenticationGen *object,
                                           GDBusMethodInvocation *invocation,
                                           const gchar *arg_message,
                                           const gchar *arg_sid)
{
    KiranAuthService *service = KIRAN_AUTH_SERVICE(object);
    KiranAuthServicePrivate *priv = service->priv;
    AuthSession *session = NULL;

    session = find_auth_session_by_sid(service, arg_sid);
    if (session != NULL)
    {
        g_mutex_lock(&session->prompt_mutex);
        g_free(session->respons_msg);
        session->respons_msg = g_strdup(arg_message);
        g_cond_signal(&session->prompt_cond);
        g_mutex_unlock(&session->prompt_mutex);
    }
}

static void
kiran_authentication_gen_init(KiranAuthenticationGenIface *iface)
{
    iface->handle_create_auth = kiran_auth_service_handle_create_auth;
    iface->handle_start_auth = kiran_auth_service_handle_start_auth;
    iface->handle_stop_auth = kiran_auth_service_handle_stop_auth;
    iface->handle_response_message = kiran_auth_service_handle_response_message;
}

static int
pam_conv_cb(int msg_length,
            const struct pam_message **msg,
            struct pam_response **resp,
            void *app_data)
{
    AuthSession *session = app_data;
    KiranAuthService *service = session->service;
    const struct pam_message *m = msg[0];
    struct pam_response *response = calloc(1, sizeof(struct pam_response));
    struct pam_response *r = &response[0];

    if (session->stop_auth)
        return PAM_CONV_ERR;

    //发送认证消息
    kiran_authentication_gen_emit_auth_messages(KIRAN_AUTHENTICATION_GEN(service),
                                                m->msg,
                                                m->msg_style,
                                                session->sid);

    if (m->msg_style == PAM_PROMPT_ECHO_ON ||
        m->msg_style == PAM_PROMPT_ECHO_OFF)
    {
        //等待请求的消息
        g_mutex_lock(&session->prompt_mutex);
        g_cond_wait(&session->prompt_cond, &session->prompt_mutex);
        r->resp = g_strdup(session->respons_msg);
        r->resp_retcode = 0;
        g_mutex_unlock(&session->prompt_mutex);
    }

    *resp = response;

    return PAM_SUCCESS;
}

static void
do_session_passwd_auth(KiranAuthService *service,
                       AuthSession *session)
{
    struct pam_conv conversation = {pam_conv_cb, session};
    int ret, state;
    const void *user;

    ret = pam_start(SERVICE, session->username, &conversation, &session->pam_handle);
    if (ret != PAM_SUCCESS)
    {
        dzlog_error("Failed to start PAM: %s", pam_strerror(NULL, ret));
        return;
    }

    ret = pam_authenticate(session->pam_handle, 0);
    if (ret != PAM_SUCCESS)
    {
        //认证失败
        state = SESSION_AUTH_FAIL;
        dzlog_error("Failed to PAM authenticate: %s", pam_strerror(NULL, ret));
    }
    else
    {
        //认证成功
        state = SESSION_AUTH_SUCCESS;
    }

    pam_get_item(session->pam_handle, PAM_USER, &user);
    kiran_authentication_gen_emit_auth_status(KIRAN_AUTHENTICATION_GEN(service),
                                              user,
                                              state,
                                              session->sid);

    pam_end(session->pam_handle, 0);
    session->pam_handle = NULL;
    g_mutex_lock(&session->stop_mutex);
    g_cond_signal(&session->stop_cond);
    g_mutex_unlock(&session->stop_mutex);
}

static gboolean
do_session_fingerprint_auth(KiranAuthService *service,
                            AuthSession *session)
{
    KiranAuthServicePrivate *priv = service->priv;
    GError *error = NULL;

    if (session->occupy)
    {
        //抢占该认证
        kiran_biometrics_call_verify_fprint_stop_sync(priv->biometrics, NULL, NULL);
    }

    kiran_biometrics_call_verify_fprint_start_sync(priv->biometrics,
                                                   NULL,
                                                   &error);

    if (error != NULL)
    {
        dzlog_error("call verify fprint start failed: %s", error->message);
        g_error_free(error);
        return FALSE;
    }

    priv->cur_fprint_session = session;

    return TRUE;
}

static void
do_authentication(gpointer data,
                  gpointer user_data)
{
    KiranAuthService *service = KIRAN_AUTH_SERVICE(user_data);
    AuthSession *session = data;

    dzlog_debug("Start authentication with sid: %s, username:%s, authmode:%d, session_auth_type:%d, occupy:%d",
                session->sid, session->username, session->user_auth_mode,
                session->session_auth_type, session->occupy);

    //开启认证
    session->is_start = TRUE;

    switch (session->session_auth_type)
    {
    case SESSION_AUTH_TYPE_TOGETHER:
        //并行认证模式
        //启动指纹认证
        do_session_fingerprint_auth(service, session);

        //启动密码认证
        do_session_passwd_auth(service, session);
        break;

    case SESSION_AUTH_TYPE_TOGETHER_WITH_USER:
        //并行认证模式, 针对给定用户
        if (session->user_auth_mode & ACCOUNTS_AUTH_MODE_FINGERPRINT)
        {
            //启动指纹认证
            do_session_fingerprint_auth(service, session);
        }

        //启动密码认证
        do_session_passwd_auth(service, session);
        break;

    default:
        //串行认证模式
        if (session->user_auth_mode & ACCOUNTS_AUTH_MODE_FINGERPRINT)
        {
            //启动指纹认证
            do_session_fingerprint_auth(service, session);
        }
    }
}

static void
kiran_auth_service_init(KiranAuthService *self)
{
    KiranAuthServicePrivate *priv;
    static guint id;
    GError *error = NULL;

    priv = self->priv = KIRAN_AUTH_SERVICE_GET_PRIVATE(self);
    priv->auth_list = NULL;
    priv->biometrics = NULL;
    priv->cur_fprint_session = NULL;

    default_session_auth_setting(self);
    priv->auth_thread_pool = g_thread_pool_new(do_authentication,
                                               self,
                                               MAX_THREAD_NUM,
                                               TRUE,
                                               &error);

    if (priv->auth_thread_pool == NULL)
    {
        dzlog_error("Failed ceate thread pool: %s", error->message);
        g_error_free(error);
    }

    //向DBus守护程序请求拥有DBus
    priv->bus_name_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
                                       AUTH_SERVICE_DBUS_NAME,
                                       G_BUS_NAME_OWNER_FLAGS_NONE,
                                       bus_acquired_cb,
                                       NULL,
                                       NULL,
                                       self,
                                       NULL);
}

static void
kiran_auth_service_class_init(KiranAuthServiceClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS(klass);

    gobject_class->finalize = kiran_auth_service_finalize;

    g_type_class_add_private(gobject_class, sizeof(KiranAuthServicePrivate));
}

/*
 *@brief 创建认证服务对象
 *
 *@return 成功返回对象的地址，失败返回NULL
 */
KiranAuthService*
kiran_auth_servie_new()
{
    return g_object_new(KIRAN_TYPE_AUTH_SERVICE, NULL);
}
