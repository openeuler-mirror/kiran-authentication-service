/**
 * Copyright (c) 2026 ~ 2029 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     yujingmin <yujingmin@kylinsec.com.cn>
 */

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonArray>
#include <QMetaObject>
#include <QPointer>
#include <QThread>
#include <QTimer>
#include <qt5-log-i.h>
#include <QtConcurrent/QtConcurrent>

#include "auth_device_adaptor.h"
#include "driver-i.h"
#include "fingerprint-device.h"
#include "kas-authentication-i.h"
#include "lib/feature-db.h"
#include "lib/utils.h"

namespace Kiran
{
namespace
{
struct FprintdFeatureMapping
{
    QString featureID;
    QString userName;
    QString fingerName;
};
}  // namespace

FingerprintDevice::FingerprintDevice(const QString& vid, const QString& pid, DriverPtr driver, QObject* parent)
    : Device(driver, parent)
{
    KLOG_INFO() << "FingerprintDevice::FingerprintDevice"
                << "vid:" << vid << "pid:" << pid << "deviceID:" << deviceID();
    m_driver = std::static_pointer_cast<FingerprintDriver>(driver);
    m_idVendor = vid;
    m_idProduct = pid;

    connect(&m_openWatcher, &QFutureWatcher<FingerprintOpenResult>::finished, this, [this]()
            {
                const FingerprintOpenResult result = m_openWatcher.result();
                m_openInProgress = false;
                // 析构会先 disconnect；若仍进 abandoned，勿接管 handle——留给 future/result
                // 析构时 shared_ptr 收口 close，避免与 Device 侧双关。
                if (m_abandoned)
                {
                    return;
                }

                if (result.handle)
                {
                    m_driverHandle = result.handle;
                    m_status = DEVICE_STATUS_IDLE;
                    KLOG_INFO() << "FingerprintDevice open success, deviceID:" << m_devId
                                << "vid:" << m_idVendor << "pid:" << m_idProduct;
                    // 维护任务与业务解耦：先续跑 pending，孤儿收敛在后台做
                    startSyncWithFprintdAsync();

                    if (!m_pendingEnrollStartExtraInfo.isNull())
                    {
                        const QString extra = m_pendingEnrollStartExtraInfo;
                        m_pendingEnrollStartExtraInfo = QString();
                        doEnrollStart(extra);
                        return;
                    }

                    if (!m_pendingIdentifyExtraInfo.isNull())
                    {
                        const QString extra = m_pendingIdentifyExtraInfo;
                        m_pendingIdentifyExtraInfo = QString();
                        doIdentifyStart(extra);
                    }
                    return;
                }

                // 懒 open：无设备是暂时状态，保持 IDLE 以便插上后再次录入/认证可重试
                m_status = DEVICE_STATUS_IDLE;
                const QString failMsg = messageForDriverError(result.errorCode);
                KLOG_ERROR() << "FingerprintDevice open failed, deviceID:" << m_devId
                             << "vid:" << m_idVendor << "pid:" << m_idProduct
                             << "code:" << result.errorCode
                             << "msg:" << failMsg;

                if (!m_pendingEnrollStartExtraInfo.isNull())
                {
                    m_pendingEnrollStartExtraInfo = QString();
                    Q_EMIT m_dbusAdaptor->EnrollStatus({}, 0, ENROLL_STATUS_FAIL, failMsg);
                }

                // open 失败：若 Identify 曾挂起等待，必须回传，避免 daemon/锁屏一直等。
                // 一律 DEVICE_UNAVAILABLE：非按错手指，daemon 不记失败次数。
                if (!m_pendingIdentifyExtraInfo.isNull())
                {
                    m_pendingIdentifyExtraInfo = QString();
                    Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_DEVICE_UNAVAILABLE, failMsg);
                }
            });

    connect(&m_enrollWatcher, &QFutureWatcher<FingerprintEnrollResult>::finished, this, [this]()
            {
                const FingerprintEnrollResult result = m_enrollWatcher.result();
                const int ret = result.ret;
                const bool stopped = m_enrollStopRequested;
                m_enrollStopRequested = false;
                m_status = DEVICE_STATUS_IDLE;

                if (m_abandoned)
                {
                    return;
                }

                if (stopped)
                {
                    KLOG_INFO() << "FingerprintDevice Enroll finished but stop requested, ignore result"
                                << "deviceID:" << m_devId;
                    return;
                }

                if (FINGERPRINT_ENROLL_REPEATED == ret)
                {
                    KLOG_WARNING() << "FingerprintDevice enroll rejected: duplicate feature, deviceID:" << m_devId;
                    notifyEnrollProcess(0, ENROLL_STATUS_REPEATED,
                                        tr("This fingerprint may already be enrolled for this or another user"));
                    return;
                }

                if (0 != ret)
                {
                    dropHandleIfStale(ret);
                    const QString msg = messageForDriverError(ret);
                    KLOG_ERROR() << "FingerprintDevice enroll fail:"
                                 << "code:" << ret
                                 << "msg:" << msg
                                 << "deviceID:" << m_devId;
                    notifyEnrollProcess(0, ENROLL_STATUS_FAIL, msg);
                    return;
                }

                // 录入成功：feature 为 fprintd:user:finger 映射串，featureID=MD5(映射串)
                const QByteArray feature = result.featureData;
                FeatureData featureData;
                featureData.feature = feature;
                featureData.featureID = QCryptographicHash::hash(feature, QCryptographicHash::Md5).toHex();
                featureData.idVendor = m_idVendor;
                featureData.idProduct = m_idProduct;
                featureData.deviceType = deviceType();
                KLOG_INFO() << "FingerprintDevice enroll success, deviceID:" << m_devId
                            << "featureID:" << featureData.featureID
                            << "feature token:" << QString::fromUtf8(feature);
                notifyEnrollProcess(100, ENROLL_STATUS_COMPLETE, tr("enroll success"), featureData);
            });

    connect(&m_identifyWatcher, &QFutureWatcher<FingerprintIdentifyResult>::finished, this, [this]()
            {
                const FingerprintIdentifyResult result = m_identifyWatcher.result();
                const int ret = result.ret;
                const int matchIndex = result.matchIndex;
                const bool stopped = m_identifyStopRequested;
                m_identifyStopRequested = false;
                m_status = DEVICE_STATUS_IDLE;

                if (m_abandoned)
                {
                    return;
                }

                if (stopped)
                {
                    KLOG_INFO() << "FingerprintDevice Identify finished but stop requested, ignore result"
                                << "deviceID:" << m_devId;
                    return;
                }

                if (0 != ret)
                {
                    // 非 0：未能完成有效比对（占用/权限/服务不可用/开验失败等），
                    // 走 DEVICE_UNAVAILABLE → AuthUnavail，不记失败次数。
                    // 真·按错手指只走下方 ret==0 && matchIndex<0。
                    dropHandleIfStale(ret);
                    const QString msg = messageForDriverError(ret);
                    KLOG_ERROR() << "FingerprintDevice identify fail (not counted as auth failure):"
                                 << "code:" << ret
                                 << "msg:" << msg
                                 << "deviceID:" << m_devId;
                    notifyIdentifyProcess(IDENTIFY_STATUS_DEVICE_UNAVAILABLE, msg);
                    return;
                }

                // matchIndex 记录在本次识别启动时传入的 feature_ids 列表位置
                if (matchIndex >= 0 && matchIndex < m_identifyFeatureIDs.count())
                {
                    QString featureID = m_identifyFeatureIDs.value(matchIndex);
                    KLOG_INFO() << "FingerprintDevice identify success, deviceID:" << m_devId
                                << "featureID:" << featureID;
                    notifyIdentifyProcess(IDENTIFY_STATUS_MATCH, tr("identify success"), featureID);
                }
                else
                {
                    KLOG_INFO() << "FingerprintDevice identify no match, deviceID:" << m_devId;
                    notifyIdentifyProcess(IDENTIFY_STATUS_NOT_MATCH, tr("identify fail!"));
                }
            });

    connect(&m_syncWatcher, &QFutureWatcher<FingerprintSyncResult>::finished, this, [this]()
            {
                if (m_abandoned)
                {
                    return;
                }
                const FingerprintSyncResult result = m_syncWatcher.result();
                for (const QString &featureID : result.orphanFeatureIDs)
                {
                    KLOG_WARNING() << "FingerprintDevice sync: orphan mapping removed"
                                   << "featureID:" << featureID
                                   << "deviceID:" << m_devId;
                    FeatureDB::getInstance()->deleteFeature(featureID);
                }
            });
}

FingerprintDevice::~FingerprintDevice()
{
    m_abandoned = true;
    m_openInProgress = false;
    m_pendingIdentifyExtraInfo = QString();

    if (m_driverHandle)
    {
        m_driver->cancel(m_driverHandle.get());
    }
    // 尽量等 worker 结束；不能死等 waitForFinished（槽/回调与主线程互相等待风险）。
    // close 不在此处强行调用：handle 由 shared_ptr 持有，Device / future / 任务各自持有引用，
    // 最后一持有者释放时 deleter 调 driver->close，既不 UAF 也不漏关。
    if (!waitForWorkers())
    {
        KLOG_WARNING() << "FingerprintDevice destructor: workers still running, handle kept alive by shared_ptr"
                       << "deviceID:" << m_devId
                       << "handleUseCount:" << m_driverHandle.use_count();
    }
    m_driverHandle.reset();
}

bool FingerprintDevice::waitForWorkers()
{
    // 循环前 disconnect：避免 processEvents 触发 finished 槽写正在析构的对象。
    // intermediate 槽靠 m_abandoned 短路，勿在析构期再发 D-Bus。
    disconnect(&m_openWatcher, &QFutureWatcher<FingerprintOpenResult>::finished, nullptr, nullptr);
    disconnect(&m_enrollWatcher, &QFutureWatcher<FingerprintEnrollResult>::finished, nullptr, nullptr);
    disconnect(&m_identifyWatcher, &QFutureWatcher<FingerprintIdentifyResult>::finished, nullptr, nullptr);
    disconnect(&m_syncWatcher, &QFutureWatcher<FingerprintSyncResult>::finished, nullptr, nullptr);

    constexpr int kWaitTimeoutMs = 35000;
    QElapsedTimer timer;
    timer.start();
    while ((m_openWatcher.isRunning() || m_enrollWatcher.isRunning() || m_identifyWatcher.isRunning() ||
            m_syncWatcher.isRunning()) &&
           timer.elapsed() < kWaitTimeoutMs)
    {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        QThread::msleep(10);
    }

    const bool allDone = !m_openWatcher.isRunning() &&
                         !m_enrollWatcher.isRunning() &&
                         !m_identifyWatcher.isRunning() &&
                         !m_syncWatcher.isRunning();

    if (!allDone)
    {
        KLOG_WARNING() << "FingerprintDevice waitForWorkers timeout, deviceID:" << m_devId
                       << "openRunning:" << m_openWatcher.isRunning()
                       << "enrollRunning:" << m_enrollWatcher.isRunning()
                       << "identifyRunning:" << m_identifyWatcher.isRunning()
                       << "syncRunning:" << m_syncWatcher.isRunning();
    }

    m_openInProgress = false;

    return allDone;
}

void FingerprintDevice::startOpenAsync()
{
    if (m_driverHandle || m_openInProgress)
    {
        return;
    }

    m_openInProgress = true;
    // 不置 DEVICE_STATUS_BUSY：D-Bus DeviceStatus 被客户端直接展示为「设备忙」
    // 注意：勿清空 pending enroll/identify，调用方已写入，open 成功后要续跑。

    KLOG_INFO() << "FingerprintDevice startOpenAsync (lazy), deviceID:" << m_devId
                << "vid:" << m_idVendor << "pid:" << m_idProduct
                << "pendingEnroll:" << !m_pendingEnrollStartExtraInfo.isNull()
                << "pendingIdentify:" << !m_pendingIdentifyExtraInfo.isNull();

    // 延后到事件循环再排队 open，避免在调用栈里立刻 QtConcurrent。
    // fprintd：仅 GetDefaultDevice 解析对象路径，真正占用在后续 Claim。
    QTimer::singleShot(0, this, SLOT(onDeferredOpen()));
}

void FingerprintDevice::onDeferredOpen()
{
    if (m_abandoned || m_driverHandle)
    {
        m_openInProgress = false;
        return;
    }

    auto driver = m_driver;
    const std::string vid = m_idVendor.toStdString();
    const std::string pid = m_idProduct.toStdString();
    KLOG_INFO() << "FingerprintDevice open job queued, deviceID:" << m_devId
                << "vid:" << m_idVendor << "pid:" << m_idProduct;

    m_openWatcher.setFuture(
        QtConcurrent::run([driver, vid, pid]() -> FingerprintOpenResult
                          {
                              FingerprintOpenResult result;
                              void *raw = nullptr;
                              result.errorCode = driver->openEx(vid, pid, &raw);
                              if (0 == result.errorCode && raw)
                              {
                                  result.handle = FingerprintDriverHandle(raw, [driver](void *h)
                                                                          {
                                                                              if (h)
                                                                              {
                                                                                  driver->close(h);
                                                                              }
                                                                          });
                              }
                              else if (0 == result.errorCode)
                              {
                                  result.errorCode = FINGERPRINT_ERROR_OPEN_FAIL;
                              }
                              return result;
                          }));
}

DeviceType FingerprintDevice::deviceType()
{
    return DEVICE_TYPE_FINGERPRINT;
}

void FingerprintDevice::doEnrollStart(const QString& extraInfo)
{
    KLOG_INFO() << "FingerprintDevice EnrollStart"
                << "deviceID:" << m_devId
                << "status:" << deviceStatus()
                << "extraInfo:" << extraInfo;

    if (!m_driverHandle)
    {
        // fprintd：用时再解析设备路径；无硬件时失败并保持可重试
        m_pendingEnrollStartExtraInfo = extraInfo;
        m_pendingIdentifyExtraInfo = QString();
        if (!isOpenInProgress())
        {
            KLOG_INFO() << "FingerprintDevice EnrollStart: lazy open"
                        << "deviceID:" << m_devId;
            startOpenAsync();
        }
        else
        {
            KLOG_INFO() << "FingerprintDevice EnrollStart deferred until open completes"
                        << "deviceID:" << m_devId;
        }
        return;
    }

    if (DEVICE_STATUS_IDLE != deviceStatus())
    {
        QString message = tr("Device Busy");
        KLOG_WARNING() << "FingerprintDevice EnrollStart rejected: device busy"
                       << "deviceID:" << m_devId
                       << "status:" << deviceStatus();
        Q_EMIT m_dbusAdaptor->EnrollStatus({}, 0, ENROLL_STATUS_FAIL, message);
        return;
    }

    m_status = DEVICE_STATUS_DOING_ENROLL;
    m_enrollStopRequested = false;

    m_pendingEnrollExtraInfo = extraInfo;
    startEnrollWorker(tr("Please press the finger to enroll"));
}

void FingerprintDevice::startEnrollWorker(const QString& enrollStartTip)
{
    if (!m_driverHandle)
    {
        return;
    }

    onEnrollIntermediateStatus(0, ENROLL_STATUS_NORMAL, enrollStartTip);

    auto driver = m_driver;
    auto handle = m_driverHandle;
    auto info = Utils::qStringToUtf8StdString(m_pendingEnrollExtraInfo);
    QPointer<FingerprintDevice> guard(this);

    m_enrollWatcher.setFuture(QtConcurrent::run([driver, handle, info, guard]() -> FingerprintEnrollResult
                                                {
                                                    FingerprintEnrollResult out;
                                                    std::string featureData;
                                                    out.ret = driver->enroll(handle.get(),
                                                                             info,
                                                                             [guard](int progress, int result, const std::string& message)
                                                                             {
                                                                                 if (result == FINGERPRINT_ENROLL_COMPLETE || result == FINGERPRINT_ENROLL_FAIL)
                                                                                 {
                                                                                     return;
                                                                                 }
                                                                                 if (!guard)
                                                                                 {
                                                                                     return;
                                                                                 }
                                                                                 QMetaObject::invokeMethod(guard.data(),
                                                                                                           "onEnrollIntermediateStatus",
                                                                                                           Qt::QueuedConnection,
                                                                                                           Q_ARG(int, progress),
                                                                                                           Q_ARG(int, result),
                                                                                                           Q_ARG(QString, Utils::stdStringToQStringUtf8(message)));
                                                                             },
                                                                             featureData);
                                                    if (0 == out.ret)
                                                    {
                                                        out.featureData = QByteArray(featureData.data(),
                                                                                     static_cast<int>(featureData.size()));
                                                    }
                                                    return out;
                                                }));
}

void FingerprintDevice::EnrollStop()
{
    KLOG_INFO() << "FingerprintDevice EnrollStop"
                << "deviceID:" << m_devId
                << "status:" << deviceStatus()
                << "stopRequestedBefore:" << m_enrollStopRequested;

    // 懒 open 尚未完成：取消挂起的录入，避免 open 成功后误开录；须回终态，否则上层一直等
    if (!m_pendingEnrollStartExtraInfo.isNull())
    {
        m_pendingEnrollStartExtraInfo = QString();
        KLOG_INFO() << "FingerprintDevice EnrollStop: cleared pending enroll during open"
                    << "deviceID:" << m_devId;
        Q_EMIT m_dbusAdaptor->EnrollStatus({}, 0, ENROLL_STATUS_FAIL,
                                           tr("fingerprint operation canceled"));
    }

    if (DEVICE_STATUS_DOING_ENROLL == deviceStatus())
    {
        m_enrollStopRequested = true;
        // 驱动接口支持真正的取消，通知驱动尽快结束阻塞的录入流程
        if (m_driverHandle)
        {
            m_driver->cancel(m_driverHandle.get());
        }
        KLOG_INFO() << "FingerprintDevice EnrollStop: marked stop requested, deviceID:" << m_devId;
    }
}

void FingerprintDevice::doIdentifyStart(const QString& extraInfo)
{
    KLOG_INFO() << "FingerprintDevice IdentifyStart"
                << "deviceID:" << m_devId
                << "status:" << deviceStatus()
                << "extraInfo:" << extraInfo;

    if (!m_driverHandle)
    {
        m_pendingIdentifyExtraInfo = extraInfo;
        m_pendingEnrollStartExtraInfo = QString();
        if (!isOpenInProgress())
        {
            KLOG_INFO() << "FingerprintDevice IdentifyStart: lazy open"
                        << "deviceID:" << m_devId;
            startOpenAsync();
        }
        else
        {
            KLOG_INFO() << "FingerprintDevice IdentifyStart deferred until open completes"
                        << "deviceID:" << m_devId;
        }
        return;
    }

    if (DEVICE_STATUS_IDLE != deviceStatus())
    {
        QString message = tr("Device Busy");
        KLOG_WARNING() << "FingerprintDevice IdentifyStart rejected: device busy"
                       << "deviceID:" << m_devId
                       << "status:" << deviceStatus();
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_DEVICE_UNAVAILABLE, message);
        return;
    }

    // 解析 daemon 下发的特征白名单。
    // 非空：不可切换用户，仅匹配该用户特征（不做全库，避免误命中他人后被 matchUser 拒绝）。
    // 为空：可切换用户，按 FeatureDB 全库组装，命中后由 daemon matchUser 决定登录用户。
    QStringList daemonFeatureIDs;
    QJsonArray jsonArray = Utils::getValueFromJsonString(extraInfo, AUTH_DEVICE_JSON_KEY_FEATURE_IDS).toArray();
    if (!jsonArray.isEmpty())
    {
        QVariantList varList = jsonArray.toVariantList();
        for (auto var : varList)
        {
            daemonFeatureIDs << var.toString();
        }
    }
    // 注意：m_identifyFeatureIDs 与 featuresThatNeedToIdentify 同步构建，
    // 保证两者索引一一对应（驱动返回的 matchIndex 才能正确反查 featureID）。

    QList<QByteArray> featuresThatNeedToIdentify;
    m_identifyFeatureIDs.clear();

    auto appendFeatureByID = [&](const QString &featureID)
    {
        if (m_identifyFeatureIDs.contains(featureID))
        {
            return;
        }
        QByteArray feature = FeatureDB::getInstance()->getFeature(featureID);
        if (!feature.isEmpty())
        {
            featuresThatNeedToIdentify << feature;
            m_identifyFeatureIDs << featureID;
        }
    };

    if (!daemonFeatureIDs.isEmpty())
    {
        for (const auto &featureID : daemonFeatureIDs)
        {
            appendFeatureByID(featureID);
        }
    }
    else
    {
        // 可切换：全库指纹映射；fprintd 一指一用户，无需再按 user_name 优先排序
        const QStringList allIDs = GetFeatureIDList();
        for (const auto &featureID : allIDs)
        {
            appendFeatureByID(featureID);
        }
        KLOG_INFO() << "FingerprintDevice IdentifyStart: switchable match"
                    << "deviceID:" << m_devId
                    << "totalCount:" << m_identifyFeatureIDs.size();
    }

    if (featuresThatNeedToIdentify.count() == 0)
    {
        // 无特征：正常应由 daemon 在 startGeneralAuth 中 skipAuthTypeNoFeature 短路。
        // 此处仍可能因 ID/blob 不同步等边角情况到达；非按错，不记失败次数。
        KLOG_WARNING() << "FingerprintDevice IdentifyStart: no found feature"
                       << "deviceID:" << m_devId;
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_DEVICE_UNAVAILABLE,
                                             tr("no enrolled fingerprint feature"));
        return;
    }

    m_status = DEVICE_STATUS_DOING_IDENTIFY;
    m_identifyStopRequested = false;

    // 将待比对模板转换为驱动接口需要的字节串列表
    std::vector<std::string> featureDataList;
    featureDataList.reserve(featuresThatNeedToIdentify.count());
    for (auto& feature : featuresThatNeedToIdentify)
    {
        featureDataList.emplace_back(feature.constData(), static_cast<size_t>(feature.size()));
    }

    auto driver = m_driver;
    auto handle = m_driverHandle;
    // 工作线程回调经事件循环转回设备线程后发信号，QPointer 防止设备已销毁时访问悬空指针
    QPointer<FingerprintDevice> guard(this);
    m_identifyWatcher.setFuture(QtConcurrent::run([driver, handle, featureDataList, guard]() -> FingerprintIdentifyResult
                                                  {
                                                      FingerprintIdentifyResult out;
                                                      out.ret = driver->identify(handle.get(),
                                                                                 featureDataList,
                                                                                 [guard](int result, const std::string& message)
                                                                                 {
                                                                                     // 终态统一由 finished 回调处理，这里只转发中间进度
                                                                                     if (result == FINGERPRINT_IDENTIFY_MATCH || result == FINGERPRINT_IDENTIFY_NOT_MATCH)
                                                                                     {
                                                                                         return;
                                                                                     }
                                                                                     if (!guard)
                                                                                     {
                                                                                         return;
                                                                                     }
                                                                                     QMetaObject::invokeMethod(guard.data(),
                                                                                                               "onIdentifyIntermediateStatus",
                                                                                                               Qt::QueuedConnection,
                                                                                                               Q_ARG(int, result),
                                                                                                               Q_ARG(QString, Utils::stdStringToQStringUtf8(message)));
                                                                                 },
                                                                                 out.matchIndex);
                                                      return out;
                                                  }));
}

void FingerprintDevice::IdentifyStop()
{
    KLOG_INFO() << "FingerprintDevice IdentifyStop"
                << "deviceID:" << m_devId
                << "status:" << deviceStatus()
                << "stopRequestedBefore:" << m_identifyStopRequested;

    // 懒 open 尚未完成：取消挂起的识别；须回终态，否则 daemon/锁屏一直等
    if (!m_pendingIdentifyExtraInfo.isNull())
    {
        m_pendingIdentifyExtraInfo = QString();
        KLOG_INFO() << "FingerprintDevice IdentifyStop: cleared pending identify during open"
                    << "deviceID:" << m_devId;
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_DEVICE_UNAVAILABLE,
                                             tr("fingerprint operation canceled"));
    }

    if (DEVICE_STATUS_DOING_IDENTIFY == deviceStatus())
    {
        m_identifyStopRequested = true;
        // 驱动接口支持真正的取消，通知驱动尽快结束阻塞的识别流程
        if (m_driverHandle)
        {
            m_driver->cancel(m_driverHandle.get());
        }
        KLOG_INFO() << "FingerprintDevice IdentifyStop: marked stop requested, deviceID:" << m_devId;
    }
}

QStringList FingerprintDevice::GetFeatureIDList()
{
    // 与人脸本地设备一致：按 deviceType 全库查询
    // （避免依赖 vid/pid 匹配导致已录入特征查询不到）
    return FeatureDB::getInstance()->getFeatureIDByDeviceType(deviceType());
}

void FingerprintDevice::dropHandleIfStale(int driverError)
{
    if (driverError != FINGERPRINT_ERROR_SERVICE_UNAVAILABLE &&
        driverError != FINGERPRINT_ERROR_OPEN_FAIL &&
        driverError != FINGERPRINT_ERROR_NO_DEVICE)
    {
        return;
    }
    if (!m_driverHandle)
    {
        return;
    }
    KLOG_INFO() << "FingerprintDevice drop stale handle after error"
                << "code:" << driverError
                << "deviceID:" << m_devId;
    m_driverHandle.reset();
}

QString FingerprintDevice::messageForDriverError(int driverError) const
{
    switch (driverError)
    {
    case FINGERPRINT_ERROR_CANCELED:
        return tr("fingerprint operation canceled");
    case FINGERPRINT_ERROR_PERMISSION_DENIED:
        return tr("Fingerprint permission denied");
    case FINGERPRINT_ERROR_SERVICE_UNAVAILABLE:
        return tr("fprintd service unavailable");
    case FINGERPRINT_ERROR_NO_DEVICE:
        return tr("No fingerprint device found");
    case FINGERPRINT_ERROR_BUSY:
        return tr("Device Busy");
    case FINGERPRINT_ERROR_NO_FEATURE:
        return tr("no enrolled fingerprint feature");
    case FINGERPRINT_ERROR_OPEN_FAIL:
        return tr("Failed to open fingerprint device");
    default:
        if (m_driver)
        {
            return Utils::stdStringToQStringUtf8(m_driver->getErrorMsg(driverError));
        }
        return tr("Failed to open fingerprint device");
    }
}

void FingerprintDevice::startSyncWithFprintdAsync()
{
    if (!m_driverHandle || !m_driver || m_abandoned)
    {
        return;
    }
    if (m_syncWatcher.isRunning())
    {
        KLOG_INFO() << "FingerprintDevice sync already running, skip"
                    << "deviceID:" << m_devId;
        return;
    }

    // FeatureDB 非线程安全：主线程做快照，worker 只打 fprintd List
    QList<FprintdFeatureMapping> mappings;
    const QStringList ids = GetFeatureIDList();
    for (const QString &featureID : ids)
    {
        const QByteArray blob = FeatureDB::getInstance()->getFeature(featureID);
        if (!blob.startsWith(FINGERPRINT_FPRINTD_FEATURE_PREFIX))
        {
            continue;
        }

        const QString qtoken = QString::fromUtf8(blob);
        const QString rest = qtoken.mid(QString(FINGERPRINT_FPRINTD_FEATURE_PREFIX).size());
        const int colon = rest.indexOf(QLatin1Char(':'));
        if (colon <= 0)
        {
            continue;
        }

        FprintdFeatureMapping m;
        m.featureID = featureID;
        m.userName = rest.left(colon);
        m.fingerName = rest.mid(colon + 1);
        mappings.append(m);
    }

    if (mappings.isEmpty())
    {
        return;
    }

    auto driver = m_driver;
    auto handle = m_driverHandle;
    const QString deviceID = m_devId;
    KLOG_INFO() << "FingerprintDevice sync queued, deviceID:" << deviceID
                << "mappingCount:" << mappings.size();

    m_syncWatcher.setFuture(QtConcurrent::run([driver, handle, mappings, deviceID]() -> FingerprintSyncResult
                                              {
                                                  FingerprintSyncResult out;
                                                  QMap<QString, QStringList> fingersByUser;
                                                  QStringList listFailedUsers;

                                                  for (const FprintdFeatureMapping &m : mappings)
                                                  {
                                                      if (listFailedUsers.contains(m.userName))
                                                      {
                                                          continue;
                                                      }

                                                      if (!fingersByUser.contains(m.userName))
                                                      {
                                                          std::vector<std::string> fingers;
                                                          const int ret = driver->listEnrolledFingers(
                                                              handle.get(), m.userName.toStdString(), fingers);
                                                          if (0 != ret)
                                                          {
                                                              listFailedUsers << m.userName;
                                                              KLOG_WARNING()
                                                                  << "FingerprintDevice sync: ListEnrolledFingers failed, skip cleanup"
                                                                  << "user:" << m.userName
                                                                  << "code:" << ret
                                                                  << "msg:" << QString::fromStdString(driver->getErrorMsg(ret))
                                                                  << "deviceID:" << deviceID;
                                                              continue;
                                                          }
                                                          QStringList list;
                                                          for (const auto &f : fingers)
                                                          {
                                                              list << QString::fromStdString(f);
                                                          }
                                                          fingersByUser.insert(m.userName, list);
                                                      }

                                                      if (!fingersByUser.value(m.userName).contains(m.fingerName))
                                                      {
                                                          out.orphanFeatureIDs << m.featureID;
                                                      }
                                                  }
                                                  return out;
                                              }));
}

void FingerprintDevice::onEnrollIntermediateStatus(int progress, int result, const QString& message)
{
    if (m_abandoned || DEVICE_STATUS_DOING_ENROLL != deviceStatus())
    {
        return;
    }

    QString translated = message;
    switch (result)
    {
    case FINGERPRINT_ENROLL_RETRY:
        translated = tr("scan quality issue, please retry");
        break;
    case FINGERPRINT_ENROLL_PASS:
        translated = tr("enroll pass, please press again");
        break;
    case FINGERPRINT_ENROLL_REPEATED:
        translated = tr("This fingerprint may already be enrolled for this or another user");
        break;
    case FINGERPRINT_ENROLL_NORMAL:
        // 驱动侧可能仍带英文占位；已有设备层 tip 时保留非空已翻译文案，否则补一条
        if (message.isEmpty() || message.startsWith(QLatin1String("Please press")))
        {
            translated = tr("Please press the finger to enroll");
        }
        break;
    default:
        break;
    }

    Q_EMIT m_dbusAdaptor->EnrollStatus({}, progress, result, translated);
}

void FingerprintDevice::onIdentifyIntermediateStatus(int result, const QString& message)
{
    if (m_abandoned || DEVICE_STATUS_DOING_IDENTIFY != deviceStatus())
    {
        return;
    }

    if (result == FINGERPRINT_IDENTIFY_MATCH || result == FINGERPRINT_IDENTIFY_NOT_MATCH)
    {
        return;
    }

    QString translated = message;
    if (result == FINGERPRINT_IDENTIFY_RETRY)
    {
        translated = tr("scan quality issue, please retry");
    }

    Q_EMIT m_dbusAdaptor->IdentifyStatus("", result, translated);
}

void FingerprintDevice::notifyEnrollProcess(int progress, int result, const QString& message, const FeatureData& featureData)
{
    switch (result)
    {
    case ENROLL_STATUS_COMPLETE:
        Q_EMIT m_dbusAdaptor->EnrollStatus(structToJsonString<FeatureData>(featureData), progress, ENROLL_STATUS_COMPLETE, message);
        break;
    case ENROLL_STATUS_FAIL:
        Q_EMIT m_dbusAdaptor->EnrollStatus({}, 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_STATUS_REPEATED:
        Q_EMIT m_dbusAdaptor->EnrollStatus({}, 0, ENROLL_STATUS_REPEATED, message);
        break;
    default:
        Q_EMIT m_dbusAdaptor->EnrollStatus({}, progress, result, message);
        break;
    }

    if (!message.isEmpty())
    {
        KLOG_DEBUG() << "FingerprintDevice enroll process:" << message
                     << "progress:" << progress
                     << "result:" << result;
    }
}

void FingerprintDevice::notifyIdentifyProcess(int result, const QString& message, const QString& featureID)
{
    switch (result)
    {
    case IDENTIFY_STATUS_MATCH:
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_STATUS_MATCH, message);
        break;
    case IDENTIFY_STATUS_NOT_MATCH:
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        break;
    case IDENTIFY_STATUS_DEVICE_UNAVAILABLE:
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_DEVICE_UNAVAILABLE, message);
        break;
    default:
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", result, message);
        break;
    }

    if (!message.isEmpty())
    {
        KLOG_DEBUG() << "FingerprintDevice identify process:" << message
                     << "result:" << result
                     << "featureID:" << featureID;
    }
}

}  // namespace Kiran
