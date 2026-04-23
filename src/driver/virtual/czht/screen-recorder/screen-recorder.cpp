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
#include <QDBusConnection>
#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QDir>
#include <signal.h>

#include "config.h"
#include "screen-recorder.h"

ScreenRecorder::ScreenRecorder(QObject *parent)
    : QObject(parent)
{
    // 监听锁屏信号
    QDBusConnection bus = QDBusConnection::sessionBus();
    auto ret = bus.connect("com.kylinsec.Kiran.ScreenSaver",
                           "/com/kylinsec/Kiran/ScreenSaver",
                           "com.kylinsec.Kiran.ScreenSaver", "ActiveChanged",
                           this, SLOT(onScreenLockChanged(bool)));
}

ScreenRecorder::~ScreenRecorder()
{
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

    QString videoSaveDir = "/var/log/kylinsec/kiran-authentication-service/video";
    if (!QDir(videoSaveDir).exists())
    {
        QDir().mkpath(videoSaveDir);
    }
    finalFileName = videoSaveDir + "/" + finalFileName;

    // 构建并执行 ks-vaudit 命令
    QString logFile = finalFileName + ".log";
    QStringList ksvaudit;
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

void ScreenRecorder::onScreenLockChanged(bool locked)
{
    KLOG_INFO() << "detect screen is" << (locked ? "Locked" : "Unlocked");
    if (locked)
    {
        stop();
    }
}