/**
 *@file kiran-auth-service.h
 *@brief 实现DBus服务的认证接口
 *@author wangxiaoqing <wangxiaoqing@kylinos.com.cn>
 *@copyright(c) 2021 KylinSec.All rights reserved.
 */
#ifndef __KIRAN_AUTH_SERVICE__
#define __KIRAN_AUTH_SERVICE__

#include "kiran-authentication-gen.h"

#define KIRAN_TYPE_AUTH_SERVICE (kiran_auth_service_get_type())
#define KIRAN_AUTH_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
                                                            KIRAN_TYPE_AUTH_SERVICE, KiranAuthService))
#define KIRAN_AUTH_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
                                                                 KIRAN_TYPE_AUTH_SERVICE, KiranAuthServiceClass))
#define KIRAN_IS_AUTH_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
                                                               KIRAN_TYPE_AUTH_SERVICE))
#define KIRAN_IS_AUTH_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
                                                                    KIRAN_TYPE_AUTH_SERVICE))
#define KIRAN_AUTH_SERVICE_GET_CLASS(obj) (G_TYPE_CHECK_INSTANCE_GET_CLASS((obj), \
                                                                           KIRAN_TYPE_AUTH_SERVICE, KiranAuthServiceClass))

typedef struct _KiranAuthService KiranAuthService;
typedef struct _KiranAuthServicePrivate KiranAuthServicePrivate;
typedef struct _KiranAuthServiceClass KiranAuthServiceClass;

struct _KiranAuthService
{
    KiranAuthenticationGenSkeleton parent;
    KiranAuthServicePrivate *priv;
};

struct _KiranAuthServiceClass
{
    KiranAuthenticationGenSkeletonClass parent_class;
};

GType kiran_auth_servie_get_type();
KiranAuthService *kiran_auth_servie_new();

#endif /* __KIRAN_AUTH_SERVICE__ */
