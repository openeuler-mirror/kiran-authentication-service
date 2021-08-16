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

#define MAX_RSA_TEXT_LEN 256 /* 最大可以加密的数据长度 */

    /* 消息类型 */
#define AUTH_SERVICE_PROMPT_ECHO_OFF 1 /* 请求密文应答信息 */
#define AUTH_SERVICE_PROMPT_ECHO_ON 2  /* 请求明文应答信息 */
#define AUTH_SERVICE_ERROR_MSG 3       /* 错误消息 */
#define AUTH_SERVICE_TEXT_INFO 4       /* 提示信息 */

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

    enum SessionAuthMethod
    {
        // 没有任何验证方式
        SESSION_AUTH_METHOD_NONE = 0,
        // 密码验证
        SESSION_AUTH_METHOD_PASSWORD = (1 << 0),
        // 指纹验证
        SESSION_AUTH_METHOD_FINGERPRINT = (1 << 1),
        // 人脸识别验证
        SESSION_AUTH_METHOD_FACE = (1 << 2),
        SESSION_AUTH_METHOD_LAST = (1 << 3),
    };

    /**
     * @brief rsa公钥对数据进行加密
     *
     * @param[in] data 要加密的数据
     * @param[in] data_len 要加密的数据长度
     * @key [in] 公钥内容
     * @encrypted [out] 加密后数据的内存地址
     * @return 返回加密后的数据长度，当等于-1时表示加密失败
     */
    int kiran_authentication_rsa_public_encrypt(char *data,
                                                int data_len,
                                                unsigned char *key,
                                                unsigned char **encrypted);

    /**
     * @brief rsa公钥对数据进行解密
     *
     * @param[in] enc_data 要解密的加密数据
     * @param[in] data_len 要解密的加密数据长度
     * @key [in] 私钥内容
     * @decrypted [out] 解密后数据的内存地址
     * @return 返回解秘后的数据长度，当等于-1时表示解密失败
     */
    int kiran_authentication_rsa_private_decrypt(unsigned char *enc_data,
                                                 int data_len,
                                                 unsigned char *key,
                                                 char **decrypted);

    /**
     * @brief rsa公私钥生成
     *
     * @param[out] public_key 公钥内存地址
     * @param [out] private_key 私钥内存地址
     *
     * @return 返回公私钥生成结果，当等于-1时表示生成失败
     */
    int kiran_authentication_rsa_key_gen(char **public_key, char **private_key);

#ifdef __cplusplus
}
#endif
#endif /* __AUTHENTICATION_I_H__ */
