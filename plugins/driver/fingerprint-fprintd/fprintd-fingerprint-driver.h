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

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include <QObject>
#include <QString>

#include "driver-i.h"

/** 接收 fprintd Device 的 EnrollStatus / VerifyStatus 信号（需 moc） */
class FprintdStatusWatcher : public QObject
{
    Q_OBJECT
public:
    explicit FprintdStatusWatcher(QObject *parent = nullptr);

    void reset();

    std::function<void(const QString &result, bool done)> onEnroll;
    std::function<void(const QString &result, bool done)> onVerify;
    std::function<void(const QString &finger)> onVerifyFingerMatched;

public Q_SLOTS:
    void enrollStatus(const QString &result, bool done);
    void verifyStatus(const QString &result, bool done);
    void verifyFingerMatched(const QString &finger);
};

/**
 * @brief 经系统 fprintd（net.reactivated.Fprint）实现的指纹驱动
 *
 * 不链接 libfprint.so；生物模板由 fprintd 持久化。
 * FeatureDB 仅存映射串：fprintd:<user>:<finger_name>
 */
class FprintdFingerprintDriver : public FingerprintDriver
{
public:
    FprintdFingerprintDriver();
    ~FprintdFingerprintDriver() override;

    std::string getDriverName() override;
    std::string getErrorMsg(int errorNum) override;
    DriverType getType() override;
    std::vector<int> getSupportedAuthTypes() override;
    bool isLocalDriver() override;
    bool hasDevice() override;

    void *open(const std::string &vid, const std::string &pid) override;
    int openEx(const std::string &vid, const std::string &pid, void **handleOut) override;
    void close(void *handle) override;
    int enroll(void *handle,
               const std::string &extraInfo,
               const std::function<void(int, int, const std::string &)> &progressCb,
               std::string &featureData) override;
    int identify(void *handle,
                 const std::vector<std::string> &featureDataList,
                 const std::function<void(int, const std::string &)> &statusCb,
                 int &matchIndex) override;
    void cancel(void *handle) override;
    int deleteEnrolledPrint(const std::string &featureData) override;
    int listEnrolledFingers(void *handle,
                            const std::string &userName,
                            std::vector<std::string> &fingers) override;

    static bool parseFeatureToken(const std::string &token, std::string &user, std::string &finger);
    static std::string makeFeatureToken(const std::string &user, const std::string &finger);

private:
    struct DeviceHandle
    {
        std::string objectPath;
        std::atomic<bool> cancelRequested{false};
        /** enroll/identify/list 互斥；cancel 只置位+发 Stop，禁止抢此锁以免与 loop.exec 死锁 */
        std::mutex opMutex;
    };

    static const char *kFprintService;
    static const char *kManagerPath;
    static const char *kManagerIface;
    static const char *kDeviceIface;

    int mapDBusError(const std::string &name, const std::string &message) const;
};
