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

#include "fprintd-fingerprint-driver.h"

#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QCoreApplication>
#include <QDebug>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStringList>
#include <QTimer>
#include <QUuid>

#include <algorithm>
#include <map>
#include <vector>

namespace
{
constexpr int KAD_AUTH_TYPE_FINGERPRINT_VALUE = (1 << 1);

const char *const kFingerNames[] = {
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
    "right-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "left-thumb",
};

QString uniqueConnectionName(const char *prefix)
{
    // Qt 5.6：无 QUuid::WithoutBraces（需 5.11+），与 Device::Device 一致手工去花括号
    const QString uuid = QUuid::createUuid().toString().remove(QLatin1Char('{')).remove(QLatin1Char('}'));
    return QString("%1-%2").arg(QLatin1String(prefix), uuid);
}

QDBusConnection openSystemBus(const QString &name, bool &ok)
{
    QDBusConnection conn = QDBusConnection::connectToBus(QDBusConnection::SystemBus, name);
    ok = conn.isConnected();
    return conn;
}

void closeSystemBus(const QString &name)
{
    QDBusConnection::disconnectFromBus(name);
}

QString jsonStringValue(const std::string &json, const char *key)
{
    const QJsonObject obj = QJsonDocument::fromJson(QByteArray::fromStdString(json)).object();
    return obj.value(QLatin1String(key)).toString();
}

}  // namespace

FprintdStatusWatcher::FprintdStatusWatcher(QObject *parent)
    : QObject(parent)
{
}

void FprintdStatusWatcher::reset()
{
    onEnroll = nullptr;
    onVerify = nullptr;
    onVerifyFingerMatched = nullptr;
}

void FprintdStatusWatcher::enrollStatus(const QString &result, bool done)
{
    if (onEnroll)
    {
        onEnroll(result, done);
    }
}

void FprintdStatusWatcher::verifyStatus(const QString &result, bool done)
{
    if (onVerify)
    {
        onVerify(result, done);
    }
}

void FprintdStatusWatcher::verifyFingerMatched(const QString &finger)
{
    if (onVerifyFingerMatched)
    {
        onVerifyFingerMatched(finger);
    }
}

const char *FprintdFingerprintDriver::kFprintService = "net.reactivated.Fprint";
const char *FprintdFingerprintDriver::kManagerPath = "/net/reactivated/Fprint/Manager";
const char *FprintdFingerprintDriver::kManagerIface = "net.reactivated.Fprint.Manager";
const char *FprintdFingerprintDriver::kDeviceIface = "net.reactivated.Fprint.Device";

FprintdFingerprintDriver::FprintdFingerprintDriver() = default;

FprintdFingerprintDriver::~FprintdFingerprintDriver() = default;

std::string FprintdFingerprintDriver::getDriverName()
{
    return "FingerPrint";
}

std::string FprintdFingerprintDriver::getErrorMsg(int errorNum)
{
    switch (errorNum)
    {
    case FINGERPRINT_ERROR_OPEN_FAIL:
        return "Failed to open fingerprint device (fprintd)";
    case FINGERPRINT_ERROR_ENROLL_FAIL:
        return "Fingerprint enroll failed";
    case FINGERPRINT_ERROR_IDENTIFY_FAIL:
        return "Fingerprint identify failed";
    case FINGERPRINT_ERROR_CANCELED:
        return "Fingerprint operation canceled";
    case FINGERPRINT_ERROR_NO_FEATURE:
        return "No enrolled fingerprint feature";
    case FINGERPRINT_ERROR_PERMISSION_DENIED:
        return "Fingerprint permission denied (polkit)";
    case FINGERPRINT_ERROR_SERVICE_UNAVAILABLE:
        return "fprintd service unavailable";
    case FINGERPRINT_ERROR_BUSY:
        return "Fingerprint device busy";
    case FINGERPRINT_ERROR_NO_DEVICE:
        return "No fingerprint device found";
    default:
        return "Unknown fingerprint error";
    }
}

bool FprintdFingerprintDriver::hasDevice()
{
    // 轻量探测：GetDefaultDevice/GetDevices 返回空视作无设备（不触发 Claim/占用）
    void *handle = nullptr;
    const int ret = openEx(std::string(), std::string(), &handle);
    if (0 == ret && handle)
    {
        close(handle);
        return true;
    }
    return false;
}

DriverType FprintdFingerprintDriver::getType()
{
    return DRIVER_TYPE_FINGERPRINT;
}

std::vector<int> FprintdFingerprintDriver::getSupportedAuthTypes()
{
    return {KAD_AUTH_TYPE_FINGERPRINT_VALUE};
}

bool FprintdFingerprintDriver::isLocalDriver()
{
    return true;
}

bool FprintdFingerprintDriver::parseFeatureToken(const std::string &token, std::string &user, std::string &finger)
{
    const std::string prefix = FINGERPRINT_FPRINTD_FEATURE_PREFIX;
    if (token.compare(0, prefix.size(), prefix) != 0)
    {
        return false;
    }
    const std::string rest = token.substr(prefix.size());
    const auto pos = rest.find(':');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= rest.size())
    {
        return false;
    }
    user = rest.substr(0, pos);
    finger = rest.substr(pos + 1);
    return !user.empty() && !finger.empty();
}

std::string FprintdFingerprintDriver::makeFeatureToken(const std::string &user, const std::string &finger)
{
    return std::string(FINGERPRINT_FPRINTD_FEATURE_PREFIX) + user + ":" + finger;
}

int FprintdFingerprintDriver::mapDBusError(const std::string &name, const std::string &message) const
{
    const QString n = QString::fromStdString(name);
    const QString m = QString::fromStdString(message);
    if (n.contains(QLatin1String("PermissionDenied")) || m.contains(QLatin1String("Not Authorized")))
    {
        return FINGERPRINT_ERROR_PERMISSION_DENIED;
    }
    if (n.contains(QLatin1String("AlreadyInUse")) || m.contains(QLatin1String("AlreadyInUse")))
    {
        return FINGERPRINT_ERROR_BUSY;
    }
    if (n.contains(QLatin1String("NoSuchDevice")) || n.contains(QLatin1String("ServiceUnknown")))
    {
        return FINGERPRINT_ERROR_SERVICE_UNAVAILABLE;
    }
    if (n.contains(QLatin1String("ClaimDevice")))
    {
        return FINGERPRINT_ERROR_BUSY;
    }
    return FINGERPRINT_ERROR_ENROLL_FAIL;
}

void *FprintdFingerprintDriver::open(const std::string &vid, const std::string &pid)
{
    void *handle = nullptr;
    openEx(vid, pid, &handle);
    return handle;
}

int FprintdFingerprintDriver::openEx(const std::string &vid, const std::string &pid, void **handleOut)
{
    Q_UNUSED(vid);
    Q_UNUSED(pid);

    if (!handleOut)
    {
        return FINGERPRINT_ERROR_OPEN_FAIL;
    }
    *handleOut = nullptr;

    bool ok = false;
    const QString connName = uniqueConnectionName("fprintd-open");
    QDBusConnection conn = openSystemBus(connName, ok);
    if (!ok)
    {
        return FINGERPRINT_ERROR_SERVICE_UNAVAILABLE;
    }

    QDBusInterface manager(QLatin1String(kFprintService),
                           QLatin1String(kManagerPath),
                           QLatin1String(kManagerIface),
                           conn);
    if (!manager.isValid())
    {
        closeSystemBus(connName);
        return FINGERPRINT_ERROR_SERVICE_UNAVAILABLE;
    }

    QString path;
    QDBusReply<QDBusObjectPath> reply = manager.call(QLatin1String("GetDefaultDevice"));
    if (reply.isValid())
    {
        path = reply.value().path();
    }
    else
    {
        // GetDefaultDevice 在无设备时常失败；再问 GetDevices 区分「无硬件」与「服务异常」
        QDBusReply<QList<QDBusObjectPath>> devices = manager.call(QLatin1String("GetDevices"));
        if (!devices.isValid())
        {
            const int err = mapDBusError(devices.error().name().toStdString(),
                                         devices.error().message().toStdString());
            closeSystemBus(connName);
            return (err == FINGERPRINT_ERROR_ENROLL_FAIL) ? FINGERPRINT_ERROR_SERVICE_UNAVAILABLE : err;
        }
        if (!devices.value().isEmpty())
        {
            path = devices.value().first().path();
        }
    }

    closeSystemBus(connName);
    if (path.isEmpty() || path == QLatin1String("/"))
    {
        return FINGERPRINT_ERROR_NO_DEVICE;
    }

    auto *handle = new DeviceHandle();
    handle->objectPath = path.toStdString();
    *handleOut = handle;
    return 0;
}

void FprintdFingerprintDriver::close(void *handle)
{
    delete static_cast<DeviceHandle *>(handle);
}

void FprintdFingerprintDriver::cancel(void *handle)
{
    auto *h = static_cast<DeviceHandle *>(handle);
    if (!h)
    {
        return;
    }
    h->cancelRequested.store(true);

    bool ok = false;
    const QString connName = uniqueConnectionName("fprintd-cancel");
    QDBusConnection conn = openSystemBus(connName, ok);
    if (!ok)
    {
        return;
    }

    QDBusInterface device(QLatin1String(kFprintService),
                          QString::fromStdString(h->objectPath),
                          QLatin1String(kDeviceIface),
                          conn);
    device.call(QLatin1String("EnrollStop"));
    device.call(QLatin1String("VerifyStop"));
    closeSystemBus(connName);
}

int FprintdFingerprintDriver::deleteEnrolledPrint(const std::string &featureData)
{
    std::string user;
    std::string finger;
    if (!parseFeatureToken(featureData, user, finger))
    {
        return FINGERPRINT_ERROR_NO_FEATURE;
    }

    bool ok = false;
    const QString connName = uniqueConnectionName("fprintd-delete");
    QDBusConnection conn = openSystemBus(connName, ok);
    if (!ok)
    {
        return FINGERPRINT_ERROR_SERVICE_UNAVAILABLE;
    }

    QDBusInterface manager(QLatin1String(kFprintService),
                           QLatin1String(kManagerPath),
                           QLatin1String(kManagerIface),
                           conn);
    QDBusReply<QDBusObjectPath> devicePath = manager.call(QLatin1String("GetDefaultDevice"));
    if (!devicePath.isValid())
    {
        const int err = mapDBusError(devicePath.error().name().toStdString(),
                                     devicePath.error().message().toStdString());
        closeSystemBus(connName);
        return err;
    }

    QDBusInterface device(QLatin1String(kFprintService),
                          devicePath.value().path(),
                          QLatin1String(kDeviceIface),
                          conn);

    QDBusReply<void> claim = device.call(QLatin1String("Claim"), QString::fromStdString(user));
    if (!claim.isValid())
    {
        const int err = mapDBusError(claim.error().name().toStdString(),
                                     claim.error().message().toStdString());
        closeSystemBus(connName);
        return err;
    }

    QDBusReply<void> del = device.call(QLatin1String("DeleteEnrolledFinger"),
                                       QString::fromStdString(finger));
    device.call(QLatin1String("Release"));
    closeSystemBus(connName);

    if (!del.isValid())
    {
        return mapDBusError(del.error().name().toStdString(),
                            del.error().message().toStdString());
    }
    return 0;
}

int FprintdFingerprintDriver::enroll(void *handle,
                                     const std::string &extraInfo,
                                     const std::function<void(int, int, const std::string &)> &progressCb,
                                     std::string &featureData)
{
    auto *h = static_cast<DeviceHandle *>(handle);
    if (!h)
    {
        return FINGERPRINT_ERROR_OPEN_FAIL;
    }

    std::lock_guard<std::mutex> lock(h->opMutex);
    h->cancelRequested.store(false);

    const QString userName = jsonStringValue(extraInfo, "user_name");
    if (userName.isEmpty())
    {
        return FINGERPRINT_ERROR_ENROLL_FAIL;
    }

    bool ok = false;
    const QString connName = uniqueConnectionName("fprintd-enroll");
    QDBusConnection conn = openSystemBus(connName, ok);
    if (!ok)
    {
        return FINGERPRINT_ERROR_SERVICE_UNAVAILABLE;
    }

    QDBusInterface device(QLatin1String(kFprintService),
                          QString::fromStdString(h->objectPath),
                          QLatin1String(kDeviceIface),
                          conn);
    if (!device.isValid())
    {
        closeSystemBus(connName);
        return FINGERPRINT_ERROR_SERVICE_UNAVAILABLE;
    }

    auto releaseAndClose = [&]()
    {
        device.call(QLatin1String("Release"));
        closeSystemBus(connName);
    };

    QDBusReply<void> claim = device.call(QLatin1String("Claim"), userName);
    if (!claim.isValid())
    {
        const int err = mapDBusError(claim.error().name().toStdString(),
                                     claim.error().message().toStdString());
        closeSystemBus(connName);
        return err;
    }

    if (h->cancelRequested.load())
    {
        releaseAndClose();
        return FINGERPRINT_ERROR_CANCELED;
    }

    QDBusReply<QStringList> enrolled = device.call(QLatin1String("ListEnrolledFingers"), userName);
    QStringList used;
    if (enrolled.isValid())
    {
        used = enrolled.value();
    }

    QString fingerName;
    for (const char *name : kFingerNames)
    {
        if (!used.contains(QLatin1String(name)))
        {
            fingerName = QLatin1String(name);
            break;
        }
    }
    if (fingerName.isEmpty())
    {
        releaseAndClose();
        return FINGERPRINT_ERROR_ENROLL_FAIL;
    }

    FprintdStatusWatcher watcher;
    QEventLoop loop;
    bool finished = false;
    bool success = false;
    int progress = 0;
    QString failReason;

    watcher.onEnroll = [&](const QString &result, bool done)
    {
        if (result == QLatin1String("enroll-completed"))
        {
            success = true;
            progress = 100;
            if (progressCb)
            {
                progressCb(100, FINGERPRINT_ENROLL_COMPLETE, "enroll success");
            }
        }
        else if (result == QLatin1String("enroll-stage-passed"))
        {
            progress = std::min(90, progress + 20);
            if (progressCb)
            {
                progressCb(progress, FINGERPRINT_ENROLL_PASS, "enroll pass");
            }
        }
        else if (result.startsWith(QLatin1String("enroll-retry")))
        {
            if (progressCb)
            {
                progressCb(progress, FINGERPRINT_ENROLL_RETRY, "retry");
            }
        }
        else if (result == QLatin1String("enroll-duplicate"))
        {
            success = false;
            failReason = result;
            if (progressCb)
            {
                progressCb(progress, FINGERPRINT_ENROLL_REPEATED, "duplicate");
            }
        }
        else if (result.startsWith(QLatin1String("enroll-failed")) ||
                 result == QLatin1String("enroll-disconnected") ||
                 result == QLatin1String("enroll-data-full") ||
                 result == QLatin1String("enroll-unknown-error"))
        {
            success = false;
            failReason = result;
        }
        else if (progressCb)
        {
            progressCb(progress, FINGERPRINT_ENROLL_NORMAL, result.toStdString());
        }

        if (done)
        {
            finished = true;
            loop.quit();
        }
    };

    conn.connect(QLatin1String(kFprintService),
                 QString::fromStdString(h->objectPath),
                 QLatin1String(kDeviceIface),
                 QLatin1String("EnrollStatus"),
                 &watcher,
                 SLOT(enrollStatus(QString, bool)));

    // 按压提示由 FingerprintDevice 在启动 enroll 前用 tr() 发出，此处勿再发英文占位。

    QDBusReply<void> start = device.call(QLatin1String("EnrollStart"), fingerName);
    if (!start.isValid())
    {
        const int err = mapDBusError(start.error().name().toStdString(),
                                     start.error().message().toStdString());
        releaseAndClose();
        return err;
    }

    QTimer cancelPoll;
    QObject::connect(&cancelPoll, &QTimer::timeout, &loop, [&]()
                     {
                         if (h->cancelRequested.load())
                         {
                             device.call(QLatin1String("EnrollStop"));
                             finished = true;
                             success = false;
                             failReason = QLatin1String("canceled");
                             loop.quit();
                         }
                     });
    cancelPoll.start(200);

    loop.exec();
    cancelPoll.stop();

    conn.disconnect(QLatin1String(kFprintService),
                    QString::fromStdString(h->objectPath),
                    QLatin1String(kDeviceIface),
                    QLatin1String("EnrollStatus"),
                    &watcher,
                    SLOT(enrollStatus(QString, bool)));

    if (h->cancelRequested.load() || failReason == QLatin1String("canceled"))
    {
        releaseAndClose();
        return FINGERPRINT_ERROR_CANCELED;
    }

    if (!finished || !success)
    {
        releaseAndClose();
        if (failReason == QLatin1String("enroll-duplicate"))
        {
            return FINGERPRINT_ENROLL_REPEATED;
        }
        return FINGERPRINT_ERROR_ENROLL_FAIL;
    }

    featureData = makeFeatureToken(userName.toStdString(), fingerName.toStdString());
    releaseAndClose();
    return 0;
}

int FprintdFingerprintDriver::identify(void *handle,
                                       const std::vector<std::string> &featureDataList,
                                       const std::function<void(int, const std::string &)> &statusCb,
                                       int &matchIndex)
{
    matchIndex = -1;
    auto *h = static_cast<DeviceHandle *>(handle);
    if (!h)
    {
        return FINGERPRINT_ERROR_OPEN_FAIL;
    }

    std::lock_guard<std::mutex> lock(h->opMutex);
    h->cancelRequested.store(false);

    // 按特征列表顺序去重收集用户；matchIndex 取该用户首次出现的下标即可（只需定位用户）
    struct UserEntry
    {
        std::string user;
        int firstIndex{-1};
    };
    std::vector<UserEntry> users;
    std::map<std::string, size_t> userPos;

    for (int i = 0; i < static_cast<int>(featureDataList.size()); ++i)
    {
        std::string user;
        std::string finger;
        if (!parseFeatureToken(featureDataList[static_cast<size_t>(i)], user, finger))
        {
            continue;
        }
        Q_UNUSED(finger);
        if (userPos.find(user) != userPos.end())
        {
            continue;
        }
        UserEntry entry;
        entry.user = user;
        entry.firstIndex = i;
        userPos[user] = users.size();
        users.push_back(entry);
    }

    if (users.empty())
    {
        return FINGERPRINT_ERROR_NO_FEATURE;
    }

    bool ok = false;
    const QString connName = uniqueConnectionName("fprintd-identify");
    QDBusConnection conn = openSystemBus(connName, ok);
    if (!ok)
    {
        return FINGERPRINT_ERROR_SERVICE_UNAVAILABLE;
    }

    QDBusInterface device(QLatin1String(kFprintService),
                          QString::fromStdString(h->objectPath),
                          QLatin1String(kDeviceIface),
                          conn);
    if (!device.isValid())
    {
        closeSystemBus(connName);
        return FINGERPRINT_ERROR_SERVICE_UNAVAILABLE;
    }

    auto releaseIfNeeded = [&](bool claimed)
    {
        if (claimed)
        {
            device.call(QLatin1String("Release"));
        }
    };

    // 区分「真正比对过但未命中」与「从未开成验」（Claim/VerifyStart 全失败）。
    // 后者不得 return 0/-1，否则上层会当成按错手指并记失败次数。
    bool verifyAttempted = false;
    int lastStartError = 0;

    for (const auto &entry : users)
    {
        if (h->cancelRequested.load())
        {
            closeSystemBus(connName);
            return FINGERPRINT_ERROR_CANCELED;
        }

        const QString userName = QString::fromStdString(entry.user);
        QDBusReply<void> claim = device.call(QLatin1String("Claim"), userName);
        if (!claim.isValid())
        {
            lastStartError = mapDBusError(claim.error().name().toStdString(),
                                          claim.error().message().toStdString());
            if (lastStartError == FINGERPRINT_ERROR_ENROLL_FAIL)
            {
                lastStartError = FINGERPRINT_ERROR_IDENTIFY_FAIL;
            }
            qWarning() << "FprintdFingerprintDriver::identify Claim failed"
                       << "user:" << userName
                       << "error:" << claim.error().name()
                       << claim.error().message()
                       << "mapped:" << lastStartError;
            continue;
        }

        FprintdStatusWatcher watcher;
        QEventLoop loop;
        bool finished = false;
        bool matched = false;

        watcher.onVerify = [&](const QString &result, bool done)
        {
            if (result == QLatin1String("verify-match"))
            {
                matched = true;
            }
            else if (result.startsWith(QLatin1String("verify-retry")))
            {
                if (statusCb)
                {
                    statusCb(FINGERPRINT_IDENTIFY_RETRY, "retry");
                }
            }
            else if (result == QLatin1String("verify-no-match") ||
                     result.startsWith(QLatin1String("verify-disconnected")) ||
                     result == QLatin1String("verify-unknown-error") ||
                     result == QLatin1String("verify-error-no-prints"))
            {
                matched = false;
            }
            else if (statusCb)
            {
                statusCb(FINGERPRINT_IDENTIFY_NORMAL, result.toStdString());
            }

            if (done)
            {
                finished = true;
                loop.quit();
            }
        };

        conn.connect(QLatin1String(kFprintService),
                     QString::fromStdString(h->objectPath),
                     QLatin1String(kDeviceIface),
                     QLatin1String("VerifyStatus"),
                     &watcher,
                     SLOT(verifyStatus(QString, bool)));

        // 统一 any：一次按压即可匹配该用户下已录入的任一 finger
        QDBusReply<void> start = device.call(QLatin1String("VerifyStart"), QStringLiteral("any"));
        if (!start.isValid())
        {
            lastStartError = mapDBusError(start.error().name().toStdString(),
                                          start.error().message().toStdString());
            if (lastStartError == FINGERPRINT_ERROR_ENROLL_FAIL)
            {
                lastStartError = FINGERPRINT_ERROR_IDENTIFY_FAIL;
            }
            qWarning() << "FprintdFingerprintDriver::identify VerifyStart failed"
                       << "user:" << userName
                       << "error:" << start.error().name()
                       << start.error().message()
                       << "mapped:" << lastStartError;
            conn.disconnect(QLatin1String(kFprintService),
                            QString::fromStdString(h->objectPath),
                            QLatin1String(kDeviceIface),
                            QLatin1String("VerifyStatus"),
                            &watcher,
                            SLOT(verifyStatus(QString, bool)));
            releaseIfNeeded(true);
            continue;
        }

        verifyAttempted = true;

        QTimer cancelPoll;
        QObject::connect(&cancelPoll, &QTimer::timeout, &loop, [&]()
                         {
                             if (h->cancelRequested.load())
                             {
                                 device.call(QLatin1String("VerifyStop"));
                                 finished = true;
                                 matched = false;
                                 loop.quit();
                             }
                         });
        cancelPoll.start(200);
        loop.exec();
        cancelPoll.stop();

        conn.disconnect(QLatin1String(kFprintService),
                        QString::fromStdString(h->objectPath),
                        QLatin1String(kDeviceIface),
                        QLatin1String("VerifyStatus"),
                        &watcher,
                        SLOT(verifyStatus(QString, bool)));

        releaseIfNeeded(true);

        if (h->cancelRequested.load())
        {
            closeSystemBus(connName);
            return FINGERPRINT_ERROR_CANCELED;
        }

        if (finished && matched)
        {
            matchIndex = entry.firstIndex;
            closeSystemBus(connName);
            return 0;
        }

        // 不匹配则继续尝试下一用户（可切换场景）；不可切换时列表通常只有一个用户
    }

    closeSystemBus(connName);
    matchIndex = -1;
    if (!verifyAttempted)
    {
        return (lastStartError != 0) ? lastStartError : FINGERPRINT_ERROR_IDENTIFY_FAIL;
    }
    return 0;
}

int FprintdFingerprintDriver::listEnrolledFingers(void *handle,
                                                  const std::string &userName,
                                                  std::vector<std::string> &fingers)
{
    fingers.clear();
    auto *h = static_cast<DeviceHandle *>(handle);
    if (!h || userName.empty())
    {
        return FINGERPRINT_ERROR_OPEN_FAIL;
    }

    // 与 enroll/identify 串行，避免并发打同一 fprintd Device；cancel 不抢此锁以免死锁
    std::lock_guard<std::mutex> lock(h->opMutex);

    bool ok = false;
    const QString connName = uniqueConnectionName("fprintd-list");
    QDBusConnection conn = openSystemBus(connName, ok);
    if (!ok)
    {
        return FINGERPRINT_ERROR_SERVICE_UNAVAILABLE;
    }

    QDBusInterface device(QLatin1String(kFprintService),
                          QString::fromStdString(h->objectPath),
                          QLatin1String(kDeviceIface),
                          conn);
    QDBusReply<QStringList> reply = device.call(QLatin1String("ListEnrolledFingers"),
                                                QString::fromStdString(userName));
    closeSystemBus(connName);
    if (!reply.isValid())
    {
        return mapDBusError(reply.error().name().toStdString(),
                            reply.error().message().toStdString());
    }
    for (const QString &finger : reply.value())
    {
        fingers.push_back(finger.toStdString());
    }
    return 0;
}

extern "C" Driver *createDriver()
{
    return new FprintdFingerprintDriver();
}
