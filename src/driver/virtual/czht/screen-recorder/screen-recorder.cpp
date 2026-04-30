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
 
#include <qt5-log-i.h>
#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QHash>
#include <signal.h>

#include <pwd.h>
#include <sys/types.h>
#include <algorithm>

#include "config.h"
#include "screen-recorder.h"

namespace
{
QString quoteForShell(const QString &value)
{
    QString escapedValue = value;
    escapedValue.replace('\'', "'\"'\"'");
    return QString("'%1'").arg(escapedValue);
}

QString getEnvFromProcess(pid_t pid, const QString &key)
{
    QFile environFile(QString("/proc/%1/environ").arg(pid));
    if (!environFile.open(QIODevice::ReadOnly))
    {
        return QString();
    }

    const QList<QByteArray> envList = environFile.readAll().split('\0');
    const QByteArray keyPrefix = key.toUtf8() + '=';
    for (const QByteArray &env : envList)
    {
        if (env.startsWith(keyPrefix))
        {
            return QString::fromUtf8(env.mid(keyPrefix.size()));
        }
    }

    return QString();
}

QString getSessionEnvByUser(const QString &userName, const QString &envKey)
{
    struct passwd *pwd = getpwnam(userName.toUtf8().constData());
    if (pwd == nullptr)
    {
        return QString();
    }

    auto readRealUidFromStatus = [](const QString &statusPath, bool *okOut) -> uint {
        QFile statusFile(statusPath);
        if (!statusFile.open(QIODevice::ReadOnly))
        {
            if (okOut)
            {
                *okOut = false;
            }
            return 0;
        }

        const QByteArray content = statusFile.read(4096);
        const QList<QByteArray> lines = content.split('\n');
        for (const QByteArray &rawLine : lines)
        {
            const QByteArray line = rawLine.trimmed();
            if (!line.startsWith("Uid:"))
            {
                continue;
            }

            const QByteArray simplified = line.mid(4).simplified();
            QList<QByteArray> fields = simplified.split(' ');
            fields.erase(std::remove_if(fields.begin(), fields.end(),
                                        [](const QByteArray &b) { return b.isEmpty(); }),
                         fields.end());

            if (okOut)
            {
                *okOut = true;
            }
            if (fields.isEmpty())
            {
                return 0U;
            }
            return fields.first().toUInt();
        }

        if (okOut)
        {
            *okOut = false;
        }
        return 0;
    };

    QDir procDir("/proc");
    const QFileInfoList procEntries = procDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QFileInfo &entry : procEntries)
    {
        bool ok = false;
        pid_t pid = entry.fileName().toLongLong(&ok);
        if (!ok)
        {
            continue;
        }

        QFile cmdlineFile(entry.filePath() + "/cmdline");
        if (!cmdlineFile.open(QIODevice::ReadOnly))
        {
            continue;
        }

        const QList<QByteArray> argv = cmdlineFile.readAll().split('\0');
        if (argv.isEmpty() || argv.first().isEmpty())
        {
            continue;
        }

        const QString argv0 = QString::fromUtf8(argv.first());
        const QString exeName = QFileInfo(argv0).fileName();
        if (exeName != "kiran-session-manager" && exeName != "gnome-session")
        {
            continue;
        }

        bool statusOk = false;
        const uint realUid = readRealUidFromStatus(entry.filePath() + "/status", &statusOk);
        if (!statusOk || realUid != static_cast<uint>(pwd->pw_uid))
        {
            continue;
        }

        const QString envValue = getEnvFromProcess(pid, envKey);
        if (!envValue.isEmpty())
        {
            return envValue;
        }
    }

    return QString();
}

QString parseUserFromRecorderFileName(const QString &fileName)
{
    // 规则：按下划线分割，第二段就是用户名
    // 例如：5639_root_20260428091302.mp4 -> root
    //      456_yujingmin_789.mp4       -> yujingmin
    // 兼容带路径：/var/.../456_yujingmin_789.mp4
    const QString baseName = QFileInfo(fileName).fileName();
    const QStringList parts = baseName.split('_', Qt::SkipEmptyParts);
    if (parts.size() < 2)
    {
        return QString();
    }
    return parts.at(1);
}
}

ScreenRecorder::ScreenRecorder(QObject *parent)
    : QObject(parent)
{
    // D-Bus 连接在 start() 中根据文件名对应的用户 session 建立
}

ScreenRecorder::~ScreenRecorder()
{
    for (auto it = m_lockMonitors.begin(); it != m_lockMonitors.end(); ++it)
    {
        QProcess *proc = it.value();
        if (proc != nullptr && proc->state() != QProcess::NotRunning)
        {
            proc->kill();
            proc->waitForFinished(1000);
        }
    }
    m_lockMonitors.clear();
}

void ScreenRecorder::startUserLockMonitor(const QString &userName, const QString &busAddress)
{
    QProcess *existing = m_lockMonitors.value(userName, nullptr);
    if (existing != nullptr && existing->state() != QProcess::NotRunning)
    {
        return;
    }
    if (existing != nullptr)
    {
        delete existing;
        m_lockMonitors.remove(userName);
    }

    auto *proc = new QProcess(this);

    // 用目标用户身份监听其 session bus 上的锁屏信号，避免 root 直接连被策略拒绝
    const QString monitorCmd =
        QString("DBUS_SESSION_BUS_ADDRESS=%1 gdbus monitor --session --dest %2 --object-path %3")
            .arg(quoteForShell(busAddress),
                 quoteForShell("com.kylinsec.Kiran.ScreenSaver"),
                 quoteForShell("/com/kylinsec/Kiran/ScreenSaver"));

    QStringList args;
    args << "-" << userName << "-c" << monitorCmd;

    proc->setProgram("su");
    proc->setArguments(args);
    proc->setProcessChannelMode(QProcess::MergedChannels);

    connect(proc, &QProcess::readyRead, this, [this, proc]() {
        const QString out = QString::fromUtf8(proc->readAll());
        if (out.contains("ActiveChanged") && (out.contains(" true") || out.contains("true")))
        {
            stop();
        }
    });

    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, userName, proc](int code, QProcess::ExitStatus status) {
                KLOG_WARNING() << "Lock monitor exited. user:" << userName << "code:" << code << "status:" << status;
                if (m_lockMonitors.value(userName, nullptr) == proc)
                {
                    m_lockMonitors.remove(userName);
                }
                proc->deleteLater();
            });

    proc->start();
    if (!proc->waitForStarted(3000))
    {
        KLOG_WARNING() << "Failed to start lock monitor process for user:" << userName;
        proc->deleteLater();
        return;
    }

    m_lockMonitors.insert(userName, proc);
}

void ScreenRecorder::ensureSessionBusConnected(const QString &fileName)
{
    QString userName = parseUserFromRecorderFileName(fileName);
    if (userName.isEmpty())
    {
        KLOG_WARNING() << "Failed to parse user from file name:" << fileName;
    }

    QString busAddress;
    if (!userName.isEmpty())
    {
        busAddress = getSessionEnvByUser(userName, "DBUS_SESSION_BUS_ADDRESS");
        if (busAddress.isEmpty())
        {
            KLOG_WARNING() << "Failed to get DBUS_SESSION_BUS_ADDRESS for user:" << userName;
        }
    }

    if (!busAddress.isEmpty())
    {
        startUserLockMonitor(userName, busAddress);
    }
}

bool ScreenRecorder::tryCodec(const QString &codec, const QStringList &extraArgs,
                              const QString &resolution, const QString &display,
                              const QString &outputFile)
{
    // 创建一个测试输出文件
    QString testFile = outputFile + ".test";
    QString logFile = testFile + ".log";
    
    // 构建 ffmpeg 测试命令，使用 -t 0.1 参数只录制0.1秒进行测试
    QStringList ffmpegArgs;
    ffmpegArgs << "-f" << "x11grab"
               << "-framerate" << "12"
               << "-video_size" << resolution
               << "-i" << display
               << "-c:v" << codec;
    ffmpegArgs << extraArgs;
    ffmpegArgs << "-t" << "0.1"  // 只录制0.1秒进行快速测试
               << testFile
               << "-y";
    
    KLOG_INFO() << "try Codec:" << codec << "cmd: ffmpeg" << ffmpegArgs.join(" ");
    
    QProcess testProcess;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("DISPLAY", display);
    testProcess.setProcessEnvironment(env);
    testProcess.setStandardOutputFile(logFile);
    testProcess.setStandardErrorFile(logFile);
    
    testProcess.start("ffmpeg", ffmpegArgs);
    
    if (!testProcess.waitForStarted(3000))
    {
        KLOG_WARNING() << "Codec" << codec << "start failed";
        return false;
    }
    
    // 等待进程完成，最多等待3秒（0.1秒录制 + 编码时间）
    // 如果进程退出，检查退出码
    if (testProcess.waitForFinished(3000))
    {
        int exitCode = testProcess.exitCode();
        // 检查测试文件是否成功生成（文件存在且大小大于0）
        bool fileExists = QFile::exists(testFile) && QFileInfo(testFile).size() > 0;
        
        if (exitCode == 0 && fileExists)
        {
            // 测试成功，删除测试文件
            QFile::remove(testFile);
            QFile::remove(logFile);
            KLOG_INFO() << "Codec" << codec << "test success";
            return true;
        }
        else
        {
            KLOG_WARNING() << "Codec" << codec << "test failed, exit code:" << exitCode << "file exists:" << fileExists;
            // 清理测试文件
            QFile::remove(testFile);
            QFile::remove(logFile);
            return false;
        }
    }
    else
    {
        // 进程超时，可能是编码器有问题，停止测试进程
        testProcess.kill();
        testProcess.waitForFinished(1000);
        // 清理测试文件
        QFile::remove(testFile);
        QFile::remove(logFile);
        KLOG_WARNING() << "Codec" << codec << "test timeout";
        return false;
    }
}

void ScreenRecorder::start(const QString &fileName)
{
    // 如果文件名为空，使用当前时间生成默认文件名
    QString finalFileName = fileName;
    if (finalFileName.isEmpty())
    {
        finalFileName = QDateTime::currentDateTime().toString("yyyyMMddHHmmss") + ".mp4";
    }
    KLOG_INFO() << "screen recorder file name:" << finalFileName;

    // 根据文件名（携带用户名）连接到指定用户的 session bus，用于监听锁屏信号
    ensureSessionBusConnected(finalFileName);

    QString videoSaveDir = "/var/log/kylinsec/kiran-authentication-service/video";
    if (!QDir(videoSaveDir).exists())
    {
        QDir().mkpath(videoSaveDir);
    }
    finalFileName = videoSaveDir + "/" + finalFileName;

    // 构建并执行 ks-vaudit 命令
    QString logFile = finalFileName + ".log";
    QStringList ksvaudit;

    const QString userName = parseUserFromRecorderFileName(fileName);
    if (!userName.isEmpty())
    {
        const QString display = getSessionEnvByUser(userName, "DISPLAY");
        const QString xauth = getSessionEnvByUser(userName, "XAUTHORITY");
        if (!display.isEmpty())
        {
            ksvaudit << "--display=" + display;
        }
        if (!xauth.isEmpty())
        {
            ksvaudit << "--xauth=" + xauth;
        }
    }

    ksvaudit << "--purecli"
             << "--format=mp4"
             << "--outfile=" + finalFileName
             << "--y";

    KLOG_INFO() << "Start recording: ks-vaudit" << ksvaudit.join(" ");
    
    // 启动 ksvaudit 进程，将输出重定向到日志文件
    // 设置 DISPLAY 环境变量
    // TODO:这里不用设置DISPLAY环境变量，因为ks-vaudit会自动判断
    // QProcessEnvironment ksvauditEnv = QProcessEnvironment::systemEnvironment();
    // ksvauditEnv.insert("DISPLAY", display);
    // m_process.setProcessEnvironment(ksvauditEnv);
    m_process.setStandardOutputFile(logFile);
    m_process.setStandardErrorFile(logFile);
    m_process.start("ks-vaudit", ksvaudit);
    
    if (!m_process.waitForStarted(3000))
    {
        KLOG_ERROR() << "Failed to start ks-vaudit process";
    }
}

void ScreenRecorder::stop()
{
    KLOG_INFO() << "stop recorder";
    
    if (m_process.state() == QProcess::NotRunning)
    {
        KLOG_INFO() << "recorder process is not running, exit";
        exit(0);
        return;
    }
    
    // 先尝试优雅地停止 ks-vaudit（发送 SIGINT，相当于按 Ctrl+C）
    // ks-vaudit 收到 SIGINT 后会正常结束并完成文件写入
    qint64 pid = m_process.processId();
    if (pid > 0)
    {
        KLOG_INFO() << "send SIGINT to ks-vaudit process" << pid;
        kill(pid, SIGINT);
        
        // 等待进程正常结束，最多等待 5 秒
        if (m_process.waitForFinished(5000))
        {
            KLOG_INFO() << "ks-vaudit process finished normally, exit";
        }
        else
        {
            KLOG_WARNING() << "ks-vaudit process did not finish in time, forcing termination, exit";
            // 如果超时，强制终止
            m_process.kill();
            m_process.waitForFinished(1000);
        }
    }
    else
    {
        // 如果无法获取进程 ID，使用 terminate() 发送 SIGTERM
        KLOG_INFO() << "terminating ks-vaudit process";
        m_process.terminate();
        if (!m_process.waitForFinished(5000))
        {
            KLOG_WARNING() << "ks-vaudit process did not finish, forcing kill";
            m_process.kill();
            m_process.waitForFinished(1000);
        }
    }
    
    exit(0);
}
