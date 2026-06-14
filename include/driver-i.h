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

// 设备类型
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
    // 虚拟人脸
    DRIVER_TYPE_VIRTUAL_FACE,
    // 虚拟验证码
    DRIVER_TYPE_VIRTUAL_CODE,
    // 虚拟验证码（无摄像头）
    DRIVER_TYPE_VIRTUAL_CODE_NO_CAMERA,
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
     * @brief 获取驱动支持的外部认证类型列表（KADAuthType 枚举值）
     * @return 认证类型列表
     */
    virtual std::vector<int> getSupportedAuthTypes() = 0;
};

using DriverPtr = std::shared_ptr<Driver>;
typedef Driver* (*CreateDriverFunc)();

/**
 * @brief 物理设备驱动抽象基类
 */
class PhysicalDriver : public Driver
{
public:
    PhysicalDriver() = default;
    virtual ~PhysicalDriver() = default;

    /**
     * @brief 获取驱动支持的厂商 ID / 产品 ID 列表
     * @return vid/pid 键值对列表
     */
    virtual std::vector<std::pair<std::string, std::string>> getSupportVidPid() = 0;
};

using PhysicalDriverPtr = std::shared_ptr<PhysicalDriver>;

/**
 * @brief 虚拟人脸驱动抽象基类
 */
class VirtualFaceDriver : public Driver
{
public:
    VirtualFaceDriver() = default;
    virtual ~VirtualFaceDriver() = default;

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

using VirtualFaceDriverPtr = std::shared_ptr<VirtualFaceDriver>;

/**
 * @brief 虚拟验证码驱动抽象基类
 */
class VirtualCodeDriver : public Driver
{
public:
    VirtualCodeDriver() = default;
    virtual ~VirtualCodeDriver() = default;

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

using VirtualCodeDriverPtr = std::shared_ptr<VirtualCodeDriver>;

/**
 * @brief UKey 驱动抽象基类
 */
class UKeyDriver : public PhysicalDriver
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
