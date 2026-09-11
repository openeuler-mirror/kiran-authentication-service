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

#pragma once

#include <QFutureWatcher>

#include <memory>

#include "device.h"
#include "driver-i.h"
#include "lib/feature-data.h"

namespace Kiran
{
/**
 * @brief 指纹驱动设备句柄（shared_ptr + close deleter）
 *
 * 生命周期与 FingerprintDevice 解耦：Device 析构只释放自身引用；
 * open/enroll/identify 的 QtConcurrent 任务持有副本，最后一持有者释放时 close。
 * 避免「工作线程未结束就 close」的 UAF，以及「超时跳过 close」的泄漏。
 */
using FingerprintDriverHandle = std::shared_ptr<void>;

/** 驱动 open() 在 QtConcurrent 中返回的结果 */
struct FingerprintOpenResult
{
    FingerprintDriverHandle handle;
    /** handle 为空时的 FingerprintDriverError；成功为 0 */
    int errorCode{0};
};

/** 录入 worker 返回值：经 QFuture 回传，避免工作线程写 Device 成员导致 UAF/竞争 */
struct FingerprintEnrollResult
{
    int ret{0};
    QByteArray featureData;
};

/** 识别 worker 返回值：经 QFuture 回传 matchIndex */
struct FingerprintIdentifyResult
{
    int ret{0};
    int matchIndex{-1};
};

/** 异步 sync 结果：仅回传待删孤儿 featureID，DB 写入仍在设备线程 */
struct FingerprintSyncResult
{
    QStringList orphanFeatureIDs;
};

class FingerprintDevice : public Device
{
    Q_OBJECT
public:
    FingerprintDevice(const QString &vid, const QString &pid, DriverPtr driver, QObject *parent = nullptr);
    ~FingerprintDevice();

    DeviceType deviceType() override;
    void doEnrollStart(const QString &extraInfo) override;
    void EnrollStop() override;
    void doIdentifyStart(const QString &extraInfo) override;
    void IdentifyStop() override;
    QStringList GetFeatureIDList() override;

    /**
     * @brief 异步解析 fprintd 设备路径（GetDefaultDevice）
     *
     * 不在启动时调用；由录入/识别在尚无句柄时触发（懒 open）。
     * 调用方须先写入 m_pendingEnrollStartExtraInfo / m_pendingIdentifyExtraInfo。
     */
    void startOpenAsync();

    /** @brief 上报录入进度（将驱动回调转换为 D-Bus EnrollStatus 信号） */
    void notifyEnrollProcess(int progress, int result, const QString &message, const FeatureData &featureData = {});
    /** @brief 上报识别结果（将驱动回调转换为 D-Bus IdentifyStatus 信号） */
    void notifyIdentifyProcess(int result, const QString &message, const QString &featureID = QString());

private Q_SLOTS:
    /**
     * @brief 事件循环启动后投递 open 到线程池
     *
     * 使用 SLOT 而非 functor：兼容本工程 Qt 5.6，且避免 lambda 未链进产物。
     */
    void onDeferredOpen();
    /**
     * @brief 录入中间状态（工作线程经 QueuedConnection 投递到设备线程）
     *
     * Qt 5.6 仅支持 const char* 槽名重载，不可传 lambda（需 Qt >= 5.10）。
     */
    void onEnrollIntermediateStatus(int progress, int result, const QString &message);
    /** @brief 识别中间状态（工作线程经 QueuedConnection 投递到设备线程） */
    void onIdentifyIntermediateStatus(int result, const QString &message);

private:
    /**
     * @brief 析构时尽量等待 open/录入/识别工作线程结束
     *
     * @return true 表示全部 watcher 已结束；false 表示超时仍有线程在跑
     */
    bool waitForWorkers();

    void startEnrollWorker(const QString &enrollStartTip);

    /**
     * @brief open 成功后异步收敛 FeatureDB 与 fprintd（不挡 pending 录入/识别）
     *
     * 主线程只做 FeatureDB 快照与删除；ListEnrolledFingers 在线程池执行。
     */
    void startSyncWithFprintdAsync();

    /** 服务不可用/设备消失时丢弃缓存路径，下次业务再懒 open */
    void dropHandleIfStale(int driverError);

    /** 将 open/驱动错误码转为面向用户的提示（需在 GUI 线程调用以便 tr） */
    QString messageForDriverError(int driverError) const;

    bool isOpenInProgress() const { return m_openInProgress; }

public:
    QString m_idVendor;
    QString m_idProduct;

    FingerprintDriverPtr m_driver;

    /** @brief open 成功后的设备句柄；空表示尚未 open 或已失败/已释放 */
    FingerprintDriverHandle m_driverHandle;

    QFutureWatcher<FingerprintOpenResult> m_openWatcher;
    QFutureWatcher<FingerprintEnrollResult> m_enrollWatcher;
    QFutureWatcher<FingerprintIdentifyResult> m_identifyWatcher;
    QFutureWatcher<FingerprintSyncResult> m_syncWatcher;
    bool m_enrollStopRequested{false};
    bool m_identifyStopRequested{false};
    /** @brief 析构后置位，open/中间状态回调不得再写设备或发 D-Bus */
    bool m_abandoned{false};
    /** @brief 已排队/正在执行异步 open */
    bool m_openInProgress{false};

    /** @brief open 进行中收到的 IdentifyStart，open 成功后补跑 */
    QString m_pendingIdentifyExtraInfo;
    /** @brief open 进行中收到的 EnrollStart，open 成功后补跑 */
    QString m_pendingEnrollStartExtraInfo;

    /** @brief 本次识别传入的待匹配特征 ID 列表，用于匹配结果反查 featureID */
    QStringList m_identifyFeatureIDs;

    QString m_pendingEnrollExtraInfo;
};
typedef QSharedPointer<FingerprintDevice> FingerprintDevicePtr;

}  // namespace Kiran
