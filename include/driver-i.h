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

    /**
     * @brief 带会话上下文查询支持的认证类型
     *
     * 新增原因：SSH MFA 白名单需要把会话上下文（channel/account/client_ip）
     * 从 PAM 经 daemon 透传到可插拔驱动，驱动据此决定可用认证类型
     * （例如白名单 IP 可豁免二次认证）。因此在既有无参接口之外追加本重载，
     * 作为带上下文查询入口；既有无参虚函数槽位保持不变。
     *
     * @param[in] extraInfo JSON 字符串（如 {"channel":"ssh","account":...,"client_ip":...}）；空表示无上下文（等价无参版本）
     * @return 认证类型列表
     * @note 默认忽略 extraInfo 并转调无参版本；可插拔驱动可按需覆盖（如 SSH 白名单）。
     *       置于类末尾：新虚函数追加在既有虚函数之后，不改变既有槽位顺序。
     */
    virtual std::vector<int> getSupportedAuthTypes(const std::string &extraInfo)
    {
        (void)extraInfo;
        return getSupportedAuthTypes();
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

/**
 * @brief 指纹驱动录入状态码
 *
 * 取值与 kas-authentication-i.h 中的 EnrollStatus 枚举保持一致，
 * 上层可据此直接转发为 D-Bus EnrollStatus 信号。
 */
enum FingerprintEnrollStatus
{
    // 录入完成
    FINGERPRINT_ENROLL_COMPLETE = 0,
    // 录入失败
    FINGERPRINT_ENROLL_FAIL = 1,
    // 录入阶段性完成
    FINGERPRINT_ENROLL_PASS = 2,
    // 因为扫描质量或者用户扫描过程中发生的问题引起，需要重试
    FINGERPRINT_ENROLL_RETRY = 3,
    // 重复录入同一特征
    FINGERPRINT_ENROLL_REPEATED = 4,
    // 正常录入中，用来传递消息，不涉及状态改变
    FINGERPRINT_ENROLL_NORMAL = 5,
};

/**
 * @brief 指纹驱动识别状态码
 *
 * 取值与 kas-authentication-i.h 中的 IdentifyStatus 枚举保持一致，
 * 上层可据此直接转发为 D-Bus IdentifyStatus 信号。
 */
enum FingerprintIdentifyStatus
{
    // 认证失败
    FINGERPRINT_IDENTIFY_NOT_MATCH = 0,
    // 认证成功
    FINGERPRINT_IDENTIFY_MATCH = 1,
    // 因为扫描质量或者用户扫描过程中发生的问题导致认证不成功
    FINGERPRINT_IDENTIFY_RETRY = 2,
    // 正常识别中，用来传递消息，不涉及状态改变
    FINGERPRINT_IDENTIFY_NORMAL = 3,
};

/**
 * @brief 指纹驱动错误码
 *
 * 必须避开 FingerprintEnrollStatus / FingerprintIdentifyStatus 的值域（0~5），
 * 否则上层会把错误码误判为录入/识别状态。
 */
enum FingerprintDriverError
{
    FINGERPRINT_ERROR_OPEN_FAIL = 100,
    FINGERPRINT_ERROR_ENROLL_FAIL = 101,
    FINGERPRINT_ERROR_IDENTIFY_FAIL = 102,
    FINGERPRINT_ERROR_CANCELED = 103,
    FINGERPRINT_ERROR_NO_FEATURE = 104,
    FINGERPRINT_ERROR_PERMISSION_DENIED = 105,
    FINGERPRINT_ERROR_SERVICE_UNAVAILABLE = 106,
    FINGERPRINT_ERROR_BUSY = 107,
    /** fprintd 可用但当前没有指纹仪 */
    FINGERPRINT_ERROR_NO_DEVICE = 108,
};

/** FeatureDB 中 fprintd 映射特征的字节前缀：fprintd:<user>:<finger_name> */
#define FINGERPRINT_FPRINTD_FEATURE_PREFIX "fprintd:"

/**
 * @brief 指纹驱动抽象基类
 *
 * 第三方厂商实现指纹驱动时继承此类，无需依赖 Qt 框架。
 * 驱动插件实例可能被多个设备对象共享，因此 open() 返回独立设备句柄，
 * 后续所有操作均传入该句柄，避免设备间状态互相覆盖。
 *
 * 录入/识别均为同步阻塞接口，驱动内部循环采集直到完成；
 * 过程中通过回调上报进度与提示消息，供上层转发为 D-Bus 信号。
 *
 * 回调中的 result 取值使用本头文件中定义的
 * FingerprintEnrollStatus / FingerprintIdentifyStatus 枚举。
 */
class FingerprintDriver : public Driver
{
public:
    FingerprintDriver() = default;
    virtual ~FingerprintDriver() = default;

    /**
     * @brief 打开指纹设备，返回独立设备句柄
     * @param vid 厂商 ID（小写十六进制字符串，如 "1b55"）
     * @param pid 产品 ID（小写十六进制字符串，如 "0120"）
     * @return 设备句柄，失败返回 nullptr
     */
    virtual void *open(const std::string &vid, const std::string &pid) = 0;

    /**
     * @brief 打开指纹设备（带回错误码）
     * @param handleOut [out] 成功时非空句柄
     * @return 0 成功；非 0 为 FingerprintDriverError（如 NO_DEVICE / SERVICE_UNAVAILABLE）
     */
    virtual int openEx(const std::string &vid, const std::string &pid, void **handleOut)
    {
        if (!handleOut)
        {
            return FINGERPRINT_ERROR_OPEN_FAIL;
        }
        *handleOut = open(vid, pid);
        return (*handleOut) ? 0 : FINGERPRINT_ERROR_OPEN_FAIL;
    }

    /**
     * @brief 关闭指纹设备
     * @param handle 由 open() 返回的设备句柄
     */
    virtual void close(void *handle) = 0;

    /**
     * @brief 当前是否真的存在可用指纹设备（硬件在位）
     *
     * 不做耗时占用；用于设备进程「无硬件时不对外暴露指纹认证类型」，
     * 让 daemon 的 GetAuthTypeByApp 不再把指纹排到密码前面。
     * 非本地驱动默认按有设备处理（沿用旧行为）。
     */
    virtual bool hasDevice()
    {
        return true;
    }

    /**
     * @brief 录入指纹（同步阻塞，直到录入完成/失败/被取消）
     *
     * 录入过程中通过 progressCb 上报进度（progress 0~100）与提示消息，
     * 例如"请按压手指""请移开手指再试一次"。
     *
     * @param handle 设备句柄
     * @param extraInfo 附加信息（JSON 字符串，预留，可传空串）
     * @param progressCb 进度回调 (progress, result, message)，result 为 FingerprintEnrollStatus
     * @param featureData [out] 录入成功后的特征数据（序列化字节串），供上层存入特征库
     * @return 0 录入成功，非 0 错误码
     */
    virtual int enroll(void *handle,
                       const std::string &extraInfo,
                       const std::function<void(int, int, const std::string &)> &progressCb,
                       std::string &featureData) = 0;

    /**
     * @brief 识别指纹（同步阻塞，扫描并与模板库比对）
     *
     * @param handle 设备句柄
     * @param featureDataList 待比对的模板数据列表（由上层从特征库加载）
     * @param statusCb 识别过程状态回调 (result, message)，result 为 FingerprintIdentifyStatus
     * @param matchIndex [out] 匹配到的模板下标，明确不匹配时为 -1
     * @return 0 识别成功（matchIndex >= 0 表示匹配，-1 表示不匹配），非 0 错误码
     */
    virtual int identify(void *handle,
                         const std::vector<std::string> &featureDataList,
                         const std::function<void(int, const std::string &)> &statusCb,
                         int &matchIndex) = 0;

    /**
     * @brief 取消/停止当前录入或识别操作
     *
     * 取消后正在阻塞的 enroll/identify 应尽快返回非 0 错误码。
     *
     * @param handle 设备句柄
     */
    virtual void cancel(void *handle) = 0;

    /**
     * @brief 删除已录入指纹（可选，默认不支持）
     *
     * fprintd 后端根据 featureData（fprintd:user:finger）调用 DeleteEnrolledFinger。
     *
     * @param featureData 特征映射字节串
     * @return 0 成功，非 0 错误码
     */
    virtual int deleteEnrolledPrint(const std::string &featureData)
    {
        (void)featureData;
        return FINGERPRINT_ERROR_ENROLL_FAIL;
    }

    /**
     * @brief 列出用户在 fprintd 中已录入的 finger_name（可选）
     * @return 0 成功，非 0 错误码
     */
    virtual int listEnrolledFingers(void *handle,
                                    const std::string &userName,
                                    std::vector<std::string> &fingers)
    {
        (void)handle;
        (void)userName;
        fingers.clear();
        return FINGERPRINT_ERROR_ENROLL_FAIL;
    }
};

using FingerprintDriverPtr = std::shared_ptr<FingerprintDriver>;
