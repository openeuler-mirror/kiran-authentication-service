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

#include <qt5-log-i.h>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>
#include <QPointer>
#include <QtConcurrent/QtConcurrent>

#include "auth_device_adaptor.h"
#include "face-device.h"
#include "lib/feature-data.h"
#include "lib/feature-db.h"
#include "lib/utils.h"

namespace Kiran
{
#define FACE_ENROLL_PROGRESS_PROCESSING 20
#define FACE_ENROLL_PROGRESS_COMPLETE 100

FaceDevice::FaceDevice(DriverPtr driver, QObject *parent) : Device(driver, parent)
{
    m_driver = std::dynamic_pointer_cast<FaceDriver>(driver);

    connect(&m_enrollWatcher, &QFutureWatcher<FaceEnrollResult>::finished, this, [this]()
            {
                const FaceEnrollResult result = m_enrollWatcher.result();
                const int ret = result.ret;
                const bool stopped = m_enrollStopRequested;
                m_enrollStopRequested = false;
                m_status = DEVICE_STATUS_IDLE;

                if (stopped)
                {
                    KLOG_INFO() << "FaceDevice enroll finished but stop requested, ignore result, deviceID=" << m_devId;
                    return;
                }

                if (0 != ret)
                {
                    QString msg = Utils::stdStringToQStringUtf8(m_driver->getErrorMsg(ret));
                    KLOG_WARNING() << "FaceDevice enroll fail, code=" << ret << "msg=" << msg;
                    Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, msg);
                    return;
                }

                KLOG_INFO() << "FaceDevice enroll success, featureID=" << result.featureID.c_str();
                FeatureData featureData;
                QByteArray featureBlob(reinterpret_cast<const char *>(result.feature.data()),
                                       static_cast<int>(result.feature.size()));
                featureData.feature = featureBlob;
                featureData.featureID = QString::fromStdString(result.featureID);
                featureData.deviceType = DEVICE_TYPE_FACE;
                featureData.authType = KAD_AUTH_TYPE_FACE;
                QJsonObject json = structToJson<FeatureData>(featureData);
                QString data = QString(QJsonDocument(json).toJson(QJsonDocument::Compact));

                Q_EMIT m_dbusAdaptor->EnrollStatus(data, FACE_ENROLL_PROGRESS_COMPLETE,
                                                   ENROLL_STATUS_COMPLETE, tr("enroll success"));
            });

    connect(&m_identifyWatcher, &QFutureWatcher<FaceIdentifyResult>::finished, this, [this]()
            {
                const FaceIdentifyResult result = m_identifyWatcher.result();
                const int ret = result.ret;
                const bool stopped = m_identifyStopRequested;
                m_identifyStopRequested = false;
                m_status = DEVICE_STATUS_IDLE;

                KLOG_INFO() << "FaceDevice identify finished, ret=" << ret
                            << "stopRequested=" << stopped << "deviceID=" << m_devId;

                if (stopped)
                {
                    KLOG_INFO() << "FaceDevice identify finished but stop requested, ignore result";
                    return;
                }

                if (0 == ret)
                {
                    KLOG_INFO() << "FaceDevice identify match, featureID=" << result.featureID.c_str();
                    Q_EMIT m_dbusAdaptor->IdentifyStatus(QString::fromStdString(result.featureID),
                                                         IDENTIFY_STATUS_MATCH, tr("identify success"));
                }
                else
                {
                    QString msg = Utils::stdStringToQStringUtf8(m_driver->getErrorMsg(ret));
                    KLOG_WARNING() << "FaceDevice identify fail, code=" << ret << "msg=" << msg;
                    Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, msg);
                }
            });
}

FaceDevice::~FaceDevice()
{
}

DeviceType FaceDevice::deviceType()
{
    return DEVICE_TYPE_FACE;
}

void FaceDevice::doEnrollStart(const QString &extraInfo)
{
    KLOG_INFO() << "FaceDevice EnrollStart"
                << "driver=" << QString::fromStdString(m_driver->getDriverName())
                << "deviceID=" << m_devId
                << "status=" << deviceStatus();

    if (DEVICE_STATUS_IDLE != deviceStatus())
    {
        QString message = tr("Device Busy");
        KLOG_WARNING() << "FaceDevice EnrollStart rejected: device busy, deviceID=" << m_devId;
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        return;
    }

    // 解析 extraInfo:{ "faceImage": "<JPEG base64>" }
    KLOG_INFO() << "FaceDevice extraInfo len=" << extraInfo.size()
                << "head=" << extraInfo.left(60);
    QJsonDocument doc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject obj = doc.object();
    QByteArray image = QByteArray::fromBase64(obj.value("faceImage").toString().toLatin1());

    m_status = DEVICE_STATUS_DOING_ENROLL;
    m_enrollStopRequested = false;
    Q_EMIT m_dbusAdaptor->EnrollStatus("", FACE_ENROLL_PROGRESS_PROCESSING,
                                       ENROLL_STATUS_NORMAL, tr("processing"));

    auto driver = m_driver;
    std::vector<uint8_t> imageVec(image.begin(), image.end());
    // 已录入特征(ID + blob),供驱动做相似度重复检测
    std::vector<std::pair<std::string, std::vector<uint8_t>>> existingFeatures;
    const auto existingIDList = GetFeatureIDList();
    for (const auto &featureID : existingIDList)
    {
        QByteArray blob = FeatureDB::getInstance()->getFeature(featureID);
        if (blob.isEmpty())
        {
            continue;
        }
        existingFeatures.emplace_back(featureID.toStdString(),
                                      std::vector<uint8_t>(blob.begin(), blob.end()));
    }
    m_enrollWatcher.setFuture(QtConcurrent::run([driver, imageVec, existingFeatures]() -> FaceEnrollResult
                                                {
                                                    FaceEnrollResult result;
                                                    result.ret = driver->enroll(imageVec, existingFeatures,
                                                                               result.feature, result.featureID);
                                                    return result;
                                                }));
}

void FaceDevice::EnrollStop()
{
    KLOG_INFO() << "FaceDevice EnrollStop, deviceID=" << m_devId << "status=" << deviceStatus();
    if (DEVICE_STATUS_DOING_ENROLL == deviceStatus())
    {
        m_enrollStopRequested = true;
        KLOG_INFO() << "FaceDevice EnrollStop: marked stop requested, deviceID=" << m_devId;
    }
}

void FaceDevice::doIdentifyStart(const QString &extraInfo)
{
    KLOG_INFO() << "FaceDevice IdentifyStart"
                << "driver=" << QString::fromStdString(m_driver->getDriverName())
                << "deviceID=" << m_devId
                << "status=" << deviceStatus();

    if (DEVICE_STATUS_IDLE != deviceStatus())
    {
        QString message = tr("Device Busy");
        KLOG_WARNING() << "FaceDevice IdentifyStart rejected: device busy, deviceID=" << m_devId;
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        return;
    }

    // 解析 extraInfo:{ "feature_ids": ["<md5>", ...] }
    QJsonDocument doc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject obj = doc.object();
    QJsonArray featureIds = obj.value("feature_ids").toArray();

    QStringList featureIDList;
    if (featureIds.isEmpty())
    {
        // 可切换锁屏场景:daemon 不指定目标用户,按平台契约全库比对(FR-014),
        // 命中后由 daemon 经 matchUser 反查用户并校验合法性
        KLOG_INFO() << "FaceDevice IdentifyStart: feature_ids empty, fallback to all face features";
        featureIDList = GetFeatureIDList();
    }
    else
    {
        for (const auto &value : featureIds)
        {
            featureIDList << value.toString();
        }
    }

    // 从 FeatureDB 读取特征(ID + 128 维 float 字节)
    std::vector<std::pair<std::string, std::vector<uint8_t>>> features;
    for (const auto &featureID : featureIDList)
    {
        QByteArray blob = FeatureDB::getInstance()->getFeature(featureID);
        if (blob.isEmpty())
        {
            KLOG_WARNING() << "FaceDevice feature not found in db, featureID=" << featureID;
            continue;
        }
        features.emplace_back(featureID.toStdString(),
                              std::vector<uint8_t>(blob.begin(), blob.end()));
    }

    if (features.empty())
    {
        QString message = tr("no enrolled face feature");
        KLOG_WARNING() << "FaceDevice IdentifyStart rejected: no features, deviceID=" << m_devId;
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        return;
    }

    m_status = DEVICE_STATUS_DOING_IDENTIFY;
    m_identifyStopRequested = false;

    auto driver = m_driver;
    QPointer<FaceDevice> guard(this);
    // Qt 5.6 仅支持 const char* 槽名重载,不可传 lambda(需 Qt >= 5.10)
    auto onRetry = [guard](int /*retryCode*/, const std::string &message)
    {
        // 回调在识别工作线程触发,经事件循环转回设备线程后发信号
        if (!guard)
        {
            return;
        }
        QMetaObject::invokeMethod(guard.data(),
                                  "onIdentifyRetry",
                                  Qt::QueuedConnection,
                                  Q_ARG(QString, Utils::stdStringToQStringUtf8(message)));
    };

    m_identifyWatcher.setFuture(QtConcurrent::run([driver, features, onRetry]() -> FaceIdentifyResult
                                                  {
                                                      FaceIdentifyResult result;
                                                      result.ret = driver->identify(features, onRetry, result.featureID);
                                                      return result;
                                                  }));
}

void FaceDevice::onIdentifyRetry(const QString &message)
{
    if (DEVICE_STATUS_DOING_IDENTIFY != deviceStatus())
    {
        return;
    }
    Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_RETRY, message);
}

void FaceDevice::IdentifyStop()
{
    KLOG_INFO() << "FaceDevice IdentifyStop, deviceID=" << m_devId << "status=" << deviceStatus();
    if (DEVICE_STATUS_DOING_IDENTIFY == deviceStatus())
    {
        m_identifyStopRequested = true;
        m_driver->stopIdentify();
        KLOG_INFO() << "FaceDevice IdentifyStop: stop requested to driver, deviceID=" << m_devId;
    }
}

QStringList FaceDevice::GetFeatureIDList()
{
    // 本地人脸设备无 vid/pid/序列号,入库时设备信息为空(NULL);
    // 按 deviceType 做 SQL 过滤查询
    return FeatureDB::getInstance()->getFeatureIDByDeviceType(DEVICE_TYPE_FACE);
}

void FaceDevice::IdentifyResultPostProcess(const QString &extraInfo)
{
    KLOG_INFO() << "FaceDevice identifyResultPostProcess, extraInfo=" << extraInfo;
    m_driver->identifyResultPostProcess(Utils::qStringToUtf8StdString(extraInfo));
}

}  // namespace Kiran
