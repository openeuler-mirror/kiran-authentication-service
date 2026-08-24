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

#include "face-driver.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/videoio.hpp>
#include <syslog.h>
#include <thread>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QHash>
#include <QLocale>
#include <QMap>
#include <QTranslator>

#include "face-driver-errors.h"
#include "config.h"
#include "sface-ncnn.h"
#include "yunet-ncnn.h"

#define FACE_DRIVER_NAME "face"
#define FACE_DRIVER_TRANSLATOR_NAME "face-driver"
#define FACE_DEFAULT_THRESHOLD 0.6        // 余弦相似度阈值,标定前初值
#define FACE_DEFAULT_TIMEOUT_MS 10000     // 识别默认超时(FR-013)
#define FACE_MIN_FACE_RATIO 0.1f          // 最小人脸框(相对图像短边),质量门限
#define FACE_SCORE_THRESHOLD 0.6f         // 检测置信度阈值(与参考实现一致)

// 注意:kas-authentication-i.h 依赖 Qt(驱动已为 Qt 驱动,仍按惯例不包含,
// 保持与 daemon 头文件解耦)。KAD_AUTH_TYPE_FACE = (1 << 2)
#define KAD_AUTH_TYPE_FACE_VALUE 4

// 错误文案表:英文源文经 QT_TRANSLATE_NOOP 提取进 translations/face-driver.zh_CN.ts,
// 运行时按 locale 翻译(参考 ks-authhub ks-soft-driver 的 getKsErrorMsg 惯例)
static const QMap<int, const char *> FACE_ERROR_MSG = {
    {FACE_DRIVER_ERROR_SUCCESS, QT_TRANSLATE_NOOP("QObject", "Success")},
    {FACE_DRIVER_ERROR_OPEN_CAMERA, QT_TRANSLATE_NOOP("QObject", "Unable to open the camera")},
    {FACE_DRIVER_ERROR_CAPTURE, QT_TRANSLATE_NOOP("QObject", "Camera capture failed")},
    {FACE_DRIVER_ERROR_CAMERA_CLOSED, QT_TRANSLATE_NOOP("QObject", "Camera is closed")},
    {FACE_DRIVER_ERROR_LOAD_MODEL, QT_TRANSLATE_NOOP("QObject", "Failed to load face models")},
    {FACE_DRIVER_ERROR_NO_FACE, QT_TRANSLATE_NOOP("QObject", "No face detected")},
    {FACE_DRIVER_ERROR_MULTI_FACE, QT_TRANSLATE_NOOP("QObject", "More than one face in view")},
    {FACE_DRIVER_ERROR_EXTRACT, QT_TRANSLATE_NOOP("QObject", "Failed to extract face feature")},
    {FACE_DRIVER_ERROR_DECODE_IMAGE, QT_TRANSLATE_NOOP("QObject", "Invalid image, cannot decode")},
    {FACE_DRIVER_ERROR_DUPLICATE, QT_TRANSLATE_NOOP("QObject", "This feature has already been enrolled")},
    {FACE_DRIVER_ERROR_SAVE, QT_TRANSLATE_NOOP("QObject", "Failed to save feature")},
    {FACE_DRIVER_ERROR_NOT_MATCH, QT_TRANSLATE_NOOP("QObject", "Face not match")},
    {FACE_DRIVER_ERROR_TIMEOUT, QT_TRANSLATE_NOOP("QObject", "Identify timeout")},
    {FACE_DRIVER_ERROR_STOPPED, QT_TRANSLATE_NOOP("QObject", "Identify stopped")},
};

// ============ 小工具 ============

namespace
{
std::string trim(const std::string &s)
{
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
    {
        return {};
    }
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

std::string envValue(const char *name)
{
    const char *value = getenv(name);
    return (value != nullptr) ? trim(value) : std::string();
}

bool fileExists(const std::string &path)
{
    FILE *fp = fopen(path.c_str(), "rb");
    if (fp)
    {
        fclose(fp);
        return true;
    }
    return false;
}

bool parseDouble(const std::string &text, double &out)
{
    if (text.empty())
    {
        return false;
    }
    char *end = nullptr;
    double value = strtod(text.c_str(), &end);
    if (end == text.c_str())
    {
        return false;
    }
    out = value;
    return true;
}

// 轻量 INI 解析:读取 [section] 下 key=value
bool readIniValue(const std::string &iniPath, const std::string &section,
                  const std::string &key, std::string &out)
{
    FILE *fp = fopen(iniPath.c_str(), "r");
    if (!fp)
    {
        return false;
    }
    char line[512];
    bool inSection = false;
    std::string target = "[" + section + "]";
    while (fgets(line, sizeof(line), fp))
    {
        std::string s = trim(line);
        if (s.empty() || s[0] == '#' || s[0] == ';')
        {
            continue;
        }
        if (s[0] == '[')
        {
            inSection = (s == target);
            continue;
        }
        if (inSection)
        {
            size_t eq = s.find('=');
            if (eq == std::string::npos)
            {
                continue;
            }
            if (trim(s.substr(0, eq)) == key)
            {
                out = trim(s.substr(eq + 1));
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

}  // namespace

// ============ FaceDriverImpl ============

FaceDriverImpl::FaceDriverImpl(QObject *parent) : QObject(parent)
{
    openlog("face-driver", LOG_PID, LOG_USER);
    loadTranslator(QStringLiteral(FACE_DRIVER_TRANSLATOR_NAME));
    m_modelDir = resolveModelDir();
    m_kadIniPath = resolveKadIniPath();
    m_threshold = FACE_DEFAULT_THRESHOLD;
    m_identifyTimeoutMs = FACE_DEFAULT_TIMEOUT_MS;

    // 阈值优先级:环境变量 KAS_FACE_THRESHOLD > kad.ini [Face] Threshold > 默认值
    const auto thresholdEnv = envValue("KAS_FACE_THRESHOLD");
    double threshold = 0.0;
    if (parseDouble(thresholdEnv, threshold))
    {
        m_threshold = threshold;
    }
    else
    {
        std::string iniThreshold;
        if (readIniValue(m_kadIniPath, "Face", "Threshold", iniThreshold))
        {
            double value = 0.0;
            if (parseDouble(iniThreshold, value) && value > 0.0 && value < 1.0)
            {
                m_threshold = value;
            }
        }
    }
    const auto timeoutEnv = envValue("KAS_FACE_IDENTIFY_TIMEOUT_MS");
    double timeoutMs = 0.0;
    if (parseDouble(timeoutEnv, timeoutMs) && timeoutMs > 0)
    {
        m_identifyTimeoutMs = static_cast<int>(timeoutMs);
    }

    syslog(LOG_INFO, "init: modelDir=%s threshold=%.3f timeoutMs=%d",
           m_modelDir.c_str(), m_threshold, m_identifyTimeoutMs);
}

FaceDriverImpl::~FaceDriverImpl()
{
    stopIdentify();
    closelog();
}

std::string FaceDriverImpl::getDriverName()
{
    return FACE_DRIVER_NAME;
}

std::string FaceDriverImpl::getErrorMsg(int errorNum)
{
    // 错误文案经自带翻译文件按 locale 提供(参考 ks-authhub ks-soft-driver 惯例)
    const auto iter = FACE_ERROR_MSG.find(errorNum);
    const char *source = (iter != FACE_ERROR_MSG.end())
                             ? iter.value()
                             : QT_TRANSLATE_NOOP("QObject", "Unknown error");
    const QString translated = QCoreApplication::translate("QObject", source);
    const QByteArray utf8 = translated.toUtf8();
    return std::string(utf8.constData(), static_cast<size_t>(utf8.size()));
}

void FaceDriverImpl::loadTranslator(const QString &translatorName)
{
    /* 各驱动独立 translator,避免后加载的 .qm 覆盖先加载的 */
    static QHash<QString, QTranslator *> translators;
    if (translators.contains(translatorName))
    {
        return;
    }

    /* 仅做 locale 探测与翻译文件加载,不修改进程全局 locale:
       设备管理服务启动时已通过 setupProcessLocale 解析进程 locale,
       QLocale::system() 会遵循 LC_ALL/LC_MESSAGES/LANG 等环境变量 */
    const QLocale locale = QLocale::system();
    QTranslator *translator = new QTranslator();
    if (!translator->load(locale, translatorName, ".", KAS_INSTALL_TRANSLATIONDIR, ".qm") &&
        !translator->load(translatorName + QStringLiteral(".zh_CN"), KAS_INSTALL_TRANSLATIONDIR))
    {
        syslog(LOG_WARNING, "load translator failed: %s locale=%s",
               translatorName.toUtf8().constData(), locale.name().toUtf8().constData());
        delete translator;
        return;
    }

    QCoreApplication::installTranslator(translator);
    translators.insert(translatorName, translator);
}

DriverType FaceDriverImpl::getType()
{
    return DRIVER_TYPE_FACE;
}

bool FaceDriverImpl::isLocalDriver()
{
    return true;
}

std::vector<int> FaceDriverImpl::getSupportedAuthTypes()
{
    // KAD_AUTH_TYPE_FACE(include/kas-authentication-i.h,驱动不依赖 Qt,此处用字面值)
    return {KAD_AUTH_TYPE_FACE_VALUE};
}

std::string FaceDriverImpl::resolveKadIniPath() const
{
#ifdef KAS_INSTALL_SYSCONFDIR
    const std::string installPath = std::string(KAS_INSTALL_SYSCONFDIR) + "/kad.ini";
    if (fileExists(installPath))
    {
        return installPath;
    }
#endif
    // 开发树相对路径
    if (fileExists("data/kad.ini"))
    {
        return "data/kad.ini";
    }
#ifdef KAS_INSTALL_SYSCONFDIR
    return std::string(KAS_INSTALL_SYSCONFDIR) + "/kad.ini";
#else
    return "data/kad.ini";
#endif
}

std::string FaceDriverImpl::resolveModelDir() const
{
    // 1) 环境变量覆盖(测试/部署可定制)
    const auto envDir = envValue("KAS_FACE_MODEL_DIR");
    if (!envDir.empty() && fileExists(envDir + "/yunet.param"))
    {
        return envDir;
    }

    // 2) 编译期安装目录
#ifdef KAS_INSTALL_DATADIR
    const std::string installDir = std::string(KAS_INSTALL_DATADIR) + "/models/face";
    if (fileExists(installDir + "/yunet.param"))
    {
        return installDir;
    }
#endif

    // 3) 开发树相对路径
    if (fileExists("models/face/yunet.param"))
    {
        return "models/face";
    }
    if (fileExists("data/models/face/yunet.param"))
    {
        return "data/models/face";
    }

    // 找不到也返回安装目录,让模型加载报错给出具体路径
#ifdef KAS_INSTALL_DATADIR
    return std::string(KAS_INSTALL_DATADIR) + "/models/face";
#else
    return "models/face";
#endif
}

void FaceDriverImpl::ensureModelsLoaded()
{
    std::lock_guard<std::mutex> lock(m_modelMutex);
    if (m_modelsLoaded)
    {
        return;
    }
    m_detector = std::unique_ptr<YunetNcnn>(new YunetNcnn(m_modelDir));
    m_recognizer = std::unique_ptr<SfaceNcnn>(new SfaceNcnn(m_modelDir));
    m_modelsLoaded = true;
    syslog(LOG_INFO, "models loaded from %s", m_modelDir.c_str());
}

int FaceDriverImpl::detectFace(const cv::Mat &image, cv::Mat &aligned112)
{
    // 输入尺寸需与图像一致
    m_detector->setInputSize(image.size());
    cv::Mat faces = m_detector->detect(image, FACE_SCORE_THRESHOLD, 0.3f);
    if (faces.empty())
    {
        return FACE_DRIVER_ERROR_NO_FACE;
    }

    // 多脸时取面积最大的一张(录入与认证一致,2026-08-19 裁决)
    cv::Mat selected = faces.row(0);
    double maxArea = -1.0;
    for (int r = 0; r < faces.rows; r++)
    {
        double area = static_cast<double>(faces.at<float>(r, 2)) * faces.at<float>(r, 3);
        if (area > maxArea)
        {
            maxArea = area;
            selected = faces.row(r);
        }
    }

    // 质量门限:人脸框不小于图像短边的 FACE_MIN_FACE_RATIO
    float w = selected.at<float>(0, 2);
    float h = selected.at<float>(0, 3);
    int shortSide = std::min(image.cols, image.rows);
    if (w < shortSide * FACE_MIN_FACE_RATIO || h < shortSide * FACE_MIN_FACE_RATIO)
    {
        return FACE_DRIVER_ERROR_NO_FACE;
    }

    aligned112 = m_recognizer->alignCrop(image, selected);
    return FACE_DRIVER_ERROR_SUCCESS;
}

int FaceDriverImpl::identify(const std::vector<std::pair<std::string, std::vector<uint8_t>>> &features,
                             const std::function<void(int retryCode, const std::string &message)> &onRetry,
                             std::string &featureID)
{
    m_identifyStopRequested = false;

    try
    {
        ensureModelsLoaded();
    }
    catch (const std::exception &e)
    {
        syslog(LOG_ERR, "identify: load models failed: %s", e.what());
        return FACE_DRIVER_ERROR_LOAD_MODEL;
    }

    syslog(LOG_INFO, "identify: start, featureCount=%zu timeoutMs=%d",
           features.size(), m_identifyTimeoutMs);

    // 摄像头选择:kad.ini [Face] Camera 指定索引(纯数字)或设备路径,默认 0
    cv::VideoCapture cap;
    std::string cameraSource;
    readIniValue(m_kadIniPath, "Face", "Camera", cameraSource);
    if (!cameraSource.empty())
    {
        char *end = nullptr;
        const long index = strtol(cameraSource.c_str(), &end, 10);
        if (end != cameraSource.c_str() && *end == '\0' && index >= 0)
        {
            cap.open(static_cast<int>(index));
        }
        else
        {
            cap.open(cameraSource);
        }
    }
    else
    {
        cap.open(0);
    }
    if (!cap.isOpened())
    {
        syslog(LOG_ERR, "identify: open camera 0 failed");
        return FACE_DRIVER_ERROR_OPEN_CAMERA;
    }
    cap.set(cv::CAP_PROP_FRAME_WIDTH, 640);
    cap.set(cv::CAP_PROP_FRAME_HEIGHT, 480);

    // 跳过开摄像头后的前几帧,等待自动曝光/白平衡稳定
    for (int i = 0; i < 3; i++)
    {
        cv::Mat warmup;
        cap.read(warmup);
    }

    auto startTime = std::chrono::steady_clock::now();
    int lastRetryCode = -1;
    double sessionBestSimilarity = -1.0;
    bool comparedAny = false;  // 窗口内是否比对过至少一张人脸(区分不匹配与超时)
    auto notify = [&](int code, const std::string &message)
    {
        if (lastRetryCode != code)
        {
            lastRetryCode = code;
            if (onRetry)
            {
                onRetry(code, message);
            }
        }
    };

    while (true)
    {
        if (m_identifyStopRequested)
        {
            return FACE_DRIVER_ERROR_STOPPED;
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - startTime)
                           .count();
        if (elapsed > m_identifyTimeoutMs)
        {
            if (comparedAny)
            {
                // 窗口内比对过人脸但均不匹配:报不匹配结束
                syslog(LOG_INFO, "identify: not match, sessionBest=%.3f threshold=%.3f",
                       sessionBestSimilarity, m_threshold);
                return FACE_DRIVER_ERROR_NOT_MATCH;
            }
            // 窗口内未检测到可比对人脸:报超时结束
            syslog(LOG_INFO, "identify: timeout, no face compared, threshold=%.3f",
                   m_threshold);
            return FACE_DRIVER_ERROR_TIMEOUT;
        }

        cv::Mat frame;
        if (!cap.read(frame) || frame.empty())
        {
            notify(FACE_DRIVER_ERROR_CAPTURE, getErrorMsg(FACE_DRIVER_ERROR_CAPTURE));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        try
        {
            cv::Mat aligned;
            int ret = detectFace(frame, aligned);
            if (FACE_DRIVER_ERROR_SUCCESS == ret)
            {
                comparedAny = true;
                cv::Mat feat = m_recognizer->feature(aligned);
                double bestSimilarity = -1.0;
                for (const auto &entry : features)
                {
                    if (entry.second.size() != feat.total() * feat.elemSize())
                    {
                        continue;
                    }
                    cv::Mat stored = SfaceNcnn::bytesToFeature(entry.second);
                    double similarity = SfaceNcnn::match(feat, stored);
                    if (similarity > bestSimilarity)
                    {
                        bestSimilarity = similarity;
                    }
                    if (similarity >= m_threshold)
                    {
                        featureID = entry.first;
                        syslog(LOG_INFO, "identify: match featureID=%s similarity=%.3f",
                               featureID.c_str(), similarity);
                        return FACE_DRIVER_ERROR_SUCCESS;
                    }
                }
                // 窗口内不匹配不结束:继续采集下一帧,直到匹配/超时/停止
                // (2026-08-19 裁决修正 FR-013)
                if (bestSimilarity > sessionBestSimilarity)
                {
                    sessionBestSimilarity = bestSimilarity;
                }
            }
            else
            {
                notify(ret, getErrorMsg(ret));
            }
        }
        catch (const cv::Exception &e)
        {
            return FACE_DRIVER_ERROR_EXTRACT;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
}

int FaceDriverImpl::enroll(const std::vector<uint8_t> &imageJpeg,
                           const std::vector<std::pair<std::string, std::vector<uint8_t>>> &existingFeatures,
                           std::vector<uint8_t> &feature,
                           std::string &featureID)
{
    try
    {
        ensureModelsLoaded();
    }
    catch (const std::exception &e)
    {
        syslog(LOG_ERR, "enroll: load models failed: %s", e.what());
        return FACE_DRIVER_ERROR_LOAD_MODEL;
    }

    syslog(LOG_INFO, "enroll: start, imageSize=%zu", imageJpeg.size());

    if (imageJpeg.empty())
    {
        syslog(LOG_WARNING, "enroll: empty image");
        return FACE_DRIVER_ERROR_DECODE_IMAGE;
    }
    cv::Mat raw(1, static_cast<int>(imageJpeg.size()), CV_8UC1,
                const_cast<uint8_t *>(imageJpeg.data()));
    cv::Mat image = cv::imdecode(raw, cv::IMREAD_COLOR);
    if (image.empty())
    {
        return FACE_DRIVER_ERROR_DECODE_IMAGE;
    }

    try
    {
        cv::Mat aligned;
        int ret = detectFace(image, aligned);
        if (FACE_DRIVER_ERROR_SUCCESS != ret)
        {
            return ret;
        }
        cv::Mat feat = m_recognizer->feature(aligned);
        feature = SfaceNcnn::featureToBytes(feat);
        // 特征 ID = 特征数据 MD5,小写十六进制,
        // 与 FeatureDB 历史 ID 格式一致(QCryptographicHash::toHex)
        featureID = QCryptographicHash::hash(
                        QByteArray(reinterpret_cast<const char *>(feature.data()),
                                   static_cast<int>(feature.size())),
                        QCryptographicHash::Md5)
                        .toHex()
                        .toStdString();

        // 重复录入检测:与库中已有特征做余弦相似度比对,
        // 超过识别阈值即判定为同一人脸并拒绝
        for (const auto &entry : existingFeatures)
        {
            if (entry.second.size() != feature.size())
            {
                continue;
            }
            const double similarity = SfaceNcnn::match(feat, SfaceNcnn::bytesToFeature(entry.second));
            if (similarity >= m_threshold)
            {
                syslog(LOG_WARNING, "enroll: duplicate face, existing featureID=%s similarity=%.3f",
                       entry.first.c_str(), similarity);
                return FACE_DRIVER_ERROR_DUPLICATE;
            }
        }

        syslog(LOG_INFO, "enroll: success featureID=%s", featureID.c_str());
        return FACE_DRIVER_ERROR_SUCCESS;
    }
    catch (const cv::Exception &e)
    {
        syslog(LOG_ERR, "enroll: extract feature failed: %s", e.what());
        return FACE_DRIVER_ERROR_EXTRACT;
    }
}

void FaceDriverImpl::identifyResultPostProcess(const std::string &extraInfo)
{
    // 本地识别暂无后处理需求(无人走监测,见 spec FR-021),保留接口
}

void FaceDriverImpl::stopIdentify()
{
    m_identifyStopRequested = true;
}

// ============ 插件导出 ============

extern "C" Driver *createDriver()
{
    return new FaceDriverImpl();
}
