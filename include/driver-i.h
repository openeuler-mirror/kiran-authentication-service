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
#include <functional>
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

    /**
     * @brief 是否为本地能力驱动（无硬件绑定，设备管理服务启动期装载）
     *
     * 本地驱动（如本地人脸识别）不依赖 udev 热插拔，由设备管理服务
     * 在启动时直接创建设备；物理设备驱动无需重写，默认返回 false。
     */
    virtual bool isLocalDriver()
    {
        return false;
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
 * @brief 本地人脸驱动抽象基类
 *
 * 本驱动在本机完成人脸检测、特征提取与比对（ncnn），
 * 与"软人脸"（SoftFaceDriver，比对在远端服务器执行）无关。
 * 驱动实现为 Qt 驱动（参考 ks-authhub ks-soft-driver 惯例），
 * 错误文案经驱动自带翻译文件按 locale 提供；
 * 接口参数为解析后的类型（JSON 解析由设备层完成）。
 * 错误码由驱动实现自定（设备层只区分成功(0)与非零）。
 */
class FaceDriver : public Driver
{
public:
    FaceDriver() = default;
    virtual ~FaceDriver() = default;

    /**
     * @brief 执行人脸识别
     *
     * 打开摄像头连续采集，检测人脸并提取特征，与给定特征逐一比对。
     * 画面中出现多张人脸时拒绝处理并返回多脸错误。
     * 默认 10 秒超时；不匹配/超时/被停止均结束本次识别。
     *
     * 识别过程中通过 onRetry 回调上报"可重试"提示（未检测到人脸、
     * 多张人脸等），由设备层翻译为界面提示；回调在工作线程中触发，
     * 实现方不得在回调中做耗时操作。
     *
     * @param features 目标用户的已录入特征列表(每项为 <特征ID, 128 维 float 原始字节>)
     * @param onRetry 重试提示回调（retryCode 为 FaceDriverError 值）
     * @param featureID [out] 匹配命中时返回特征 ID
     * @return FACE_DRIVER_ERROR_SUCCESS 匹配成功；
     *         FACE_DRIVER_ERROR_NOT_MATCH 不匹配；
     *         其他非 0 为错误码
     */
    virtual int identify(const std::vector<std::pair<std::string, std::vector<uint8_t>>> &features,
                         const std::function<void(int retryCode, const std::string &message)> &onRetry,
                         std::string &featureID) = 0;

    /**
     * @brief 请求停止进行中的识别
     *
     * 识别线程应在下一次采集循环检查到停止请求后尽快返回
     * FACE_DRIVER_ERROR_STOPPED，调用方将丢弃其结果。
     */
    virtual void stopIdentify() = 0;

    /**
     * @brief 执行人脸录入
     *
     * 对传入的 JPEG 图像做人脸检测（无脸/质量不达标拒绝,多脸取最大脸）、
     * 特征提取与重复检测，返回特征数据与特征 ID。
     *
     * @param imageJpeg JPEG 编码的图像数据
     * @param existingFeatures 已录入特征列表(每项为 <特征ID, 128 维 float 原始字节>)，
     *                         用于相似度重复检测
     * @param feature [out] 128 维 float 特征原始字节
     * @param featureID [out] 特征数据 MD5（小写十六进制,与 FeatureDB 历史格式一致）
     * @return 0 成功，其他非 0 为错误码（错误码由驱动实现自定）
     */
    virtual int enroll(const std::vector<uint8_t> &imageJpeg,
                       const std::vector<std::pair<std::string, std::vector<uint8_t>>> &existingFeatures,
                       std::vector<uint8_t> &feature,
                       std::string &featureID) = 0;

    /**
     * @brief 识别结果后处理（无论成功失败）
     * @param extraInfo 附加信息（JSON 字符串，由设备层透传）
     */
    virtual void identifyResultPostProcess(const std::string &extraInfo) = 0;
};

using FaceDriverPtr = std::shared_ptr<FaceDriver>;

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
