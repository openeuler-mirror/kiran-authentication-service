/**
 * Copyright (c) 2025 ~ 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     yangfeng <yangfeng@kylinsec.com.cn>
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

// 驱动分类
enum DriverType
{
    // 指纹
    DRIVER_TYPE_FINGERPRINT,
    // 人脸
    DRIVER_TYPE_FACE,
    // 指静脉
    DRIVER_TYPE_FINGERVEIN,
    // 虹膜
    DRIVER_TYPE_IRIS,
    // 声纹
    DRIVER_TYPE_VOICEPRINT,
    // ukey
    DRIVER_TYPE_UKEY,
    // 软驱动
    DRIVER_TYPE_SOFT,
};

// 软驱动子类型
enum SoftDriverType
{
    // 非软驱动（物理设备）/ 默认值
    SOFT_DRIVER_TYPE_NONE = 0,
    // 软人脸
    SOFT_DRIVER_TYPE_FACE = 1,
    // 软验证码
    SOFT_DRIVER_TYPE_CODE,
    // 软验证码（无摄像头）
    SOFT_DRIVER_TYPE_CODE_NO_CAMERA,
};

/**
 * @brief 驱动抽象基类
 *
 * 第三方厂商实现驱动时只需继承此类或其子类，
 * 无需依赖 Qt 框架。
 */
class Driver
{
public:
    Driver() = default;
    virtual ~Driver() = default;

    /**
     * @brief 获取驱动名称
     * @return 驱动名称字符串
     */
    virtual std::string getDriverName() = 0;

    /**
     * @brief 根据错误码获取错误消息
     * @param errorNum 错误码
     * @return 错误描述字符串
     */
    virtual std::string getErrorMsg(int errorNum) = 0;

    /**
     * @brief 获取驱动类型
     * @return DriverType 枚举值
     */
    virtual DriverType getType() = 0;

    /**
     * @brief 获取软驱动子类型
     *
     * 仅当 getType() 返回 DRIVER_TYPE_SOFT 时有效。
     * 物理设备驱动无需重写，默认返回 SOFT_DRIVER_TYPE_NONE。
     *
     * @return SoftDriverType 枚举值
     */
    virtual SoftDriverType getSoftType()
    {
        return SOFT_DRIVER_TYPE_NONE;
    }

    /**
     * @brief 获取驱动支持的外部认证类型列表（KADAuthType 枚举值）
     * @return 认证类型列表
     */
    virtual std::vector<int> getSupportedAuthTypes() = 0;

    /**
     * @brief 获取驱动支持的厂商 ID / 产品 ID 列表
     *
     * 物理设备驱动应重写此方法；软驱动无需重写，默认返回空列表。
     *
     * @return vid/pid 键值对列表
     */
    virtual std::vector<std::pair<std::string, std::string>> getSupportVidPid()
    {
        return {};
    }
};

using DriverPtr = std::shared_ptr<Driver>;
typedef Driver *(*CreateDriverFunc)();

/**
 * @brief 软人脸驱动抽象基类
 */
class SoftFaceDriver : public Driver
{
public:
    SoftFaceDriver() = default;
    virtual ~SoftFaceDriver() = default;

    /**
     * @brief 执行识别
     * @param extraInfo 附加信息（JSON 字符串）
     * @return 0 成功，非 0 错误码
     */
    virtual int identify(const std::string &extraInfo) = 0;

    /**
     * @brief 识别结果后处理（无论成功失败）
     * @param extraInfo 附加信息（JSON 字符串）
     */
    virtual void identifyResultPostProcess(const std::string &extraInfo) = 0;
};

using SoftFaceDriverPtr = std::shared_ptr<SoftFaceDriver>;

/**
 * @brief 软验证码驱动抽象基类
 */
class SoftCodeDriver : public Driver
{
public:
    SoftCodeDriver() = default;
    virtual ~SoftCodeDriver() = default;

    /**
     * @brief 执行识别
     * @param extraInfo 附加信息（JSON 字符串）
     * @return 0 成功，非 0 错误码
     */
    virtual int identify(const std::string &extraInfo) = 0;

    /**
     * @brief 识别结果后处理（无论成功失败）
     * @param extraInfo 附加信息（JSON 字符串）
     */
    virtual void identifyResultPostProcess(const std::string &extraInfo) = 0;
};

using SoftCodeDriverPtr = std::shared_ptr<SoftCodeDriver>;

/**
 * @brief UKey 驱动抽象基类
 */
class UKeyDriver : public Driver
{
public:
    UKeyDriver() = default;
    virtual ~UKeyDriver() = default;

    /**
     * @brief 获取在线设备序列号
     *        由于私钥存储在设备内，调用接口必须指定序列号。
     * @return 在线设备序列号列表
     */
    virtual std::vector<std::string> getOnlineSerials() = 0;

    /**
     * @brief 绑定用户（录入）
     * @param pin PIN 码
     * @param pubKey [out] 生成的公钥
     * @param serialNumber 设备序列号
     * @return 0 成功，非 0 错误码
     */
    virtual int enroll(const std::string &pin,
                       std::vector<uint8_t> &pubKey,
                       const std::string &serialNumber) = 0;

    /**
     * @brief 验证用户（识别）
     * @param pin PIN 码
     * @param pubKey 已存储的公钥
     * @param serialNumber 设备序列号
     * @return 0 成功，非 0 错误码
     */
    virtual int identify(const std::string &pin,
                         const std::vector<uint8_t> &pubKey,
                         const std::string &serialNumber) = 0;
};

using UKeyDriverPtr = std::shared_ptr<UKeyDriver>;
