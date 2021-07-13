/**
 *@file authentication_i.h
 *@brief 认证服务头文件
 *@author wangxiaoqing <wangxiaoqing@kylinos.com.cn>
 *@copyright(c) 2021 KylinSec.All rights reserved.
 */
#ifndef __AUTHENTICATION_I_H__
#define __AUTHENTICATION_I_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define AUTH_SERVICE_DBUS_NAME "com.kylinsec.Kiran.SystemDaemon.Authentication"
#define AUTH_SERVICE_OBJECT_PATH "/com/kylinsec/Kiran/SystemDaemon/Authentication"
#define ASK_AUTH_SID "ReqSessionId"

    /**
    * 认证方式
    *
    */
    enum SessionAuthType
    {
        //使用默认的认证类型
        SESSION_AUTH_TYPE_DEFAULT = 0,
        //串行认证方式，依次进行认证
        SESSION_AUTH_TYPE_ONE = 1,
        //并行认证方式，同时进行多种认证
        SESSION_AUTH_TYPE_TOGETHER = 2,
        //并行认证方式，生物认证对给定的用户进行认证
        SESSION_AUTH_TYPE_TOGETHER_WITH_USER = 3,
    };

    /* 
     * 认证状态
     *
     */
    enum SessionAuthState
    {
        //认证成功
        SESSION_AUTH_SUCCESS = 0,
        //认证失败
        SESSION_AUTH_FAIL = 1,
    };

#ifdef __cplusplus
}
#endif
#endif /* __AUTHENTICATION_I_H__ */
