/**
 * Copyright (c) 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author:     yangfeng <yangfeng@kylinsec.com.cn>
 */

#pragma once

// 本地人脸识别驱动:基于 ncnn(YuNet 检测 + SFace 特征 + 余弦比对)
// 与"软人脸"(SoftFaceDriver,远端比对)无关。
// 驱动为 Qt 驱动(参考 ks-authhub 的 ks-soft-driver 惯例):
// 错误文案经自带翻译文件(translations/face-driver.zh_CN.ts)按 locale 提供。

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <QObject>
#include <opencv2/core.hpp>

#include "driver-i.h"

class YunetNcnn;
class SfaceNcnn;

class FaceDriverImpl : public QObject, public FaceDriver
{
    Q_OBJECT
public:
    explicit FaceDriverImpl(QObject *parent = nullptr);
    ~FaceDriverImpl() override;

    // Driver 接口
    std::string getDriverName() override;
    std::string getErrorMsg(int errorNum) override;
    DriverType getType() override;
    std::vector<int> getSupportedAuthTypes() override;
    bool isLocalDriver() override;

    // FaceDriver 接口
    int identify(const std::vector<std::pair<std::string, std::vector<uint8_t>>> &features,
                 const std::function<void(int retryCode, const std::string &message)> &onRetry,
                 std::string &featureID) override;
    int enroll(const std::vector<uint8_t> &imageJpeg,
               const std::vector<std::pair<std::string, std::vector<uint8_t>>> &existingFeatures,
               std::vector<uint8_t> &feature,
               std::string &featureID) override;
    void identifyResultPostProcess(const std::string &extraInfo) override;
    void stopIdentify() override;

private:
    // 加载自带翻译文件(face-driver.<locale>.qm),locale 兜底 zh_CN
    void loadTranslator(const QString &translatorName);
    // 模型路径解析:环境变量 KAS_FACE_MODEL_DIR > 编译期安装目录 > 开发树相对路径
    std::string resolveModelDir() const;
    // kad.ini 路径:安装目录 > 开发树相对路径
    std::string resolveKadIniPath() const;
    void ensureModelsLoaded();  // 懒加载,线程安全

    // 检测人脸并对齐;画面多脸时取面积最大的一张(录入与认证一致)
    int detectFace(const cv::Mat &image, cv::Mat &aligned112);

private:
    std::string m_modelDir;
    std::string m_kadIniPath;
    double m_threshold;
    int m_identifyTimeoutMs;

    std::mutex m_modelMutex;
    bool m_modelsLoaded{false};
    std::unique_ptr<YunetNcnn> m_detector;
    std::unique_ptr<SfaceNcnn> m_recognizer;

    std::atomic<bool> m_identifyStopRequested{false};
};
