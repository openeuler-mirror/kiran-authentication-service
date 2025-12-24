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

    // 获取屏幕分辨率
    QString resolution;
    QProcess xdpyinfoProcess;
    // 设置 DISPLAY 环境变量，优先使用环境变量中的值，否则使用默认值 :0.0
    // TODO: 需要支持多显示显示服务
    QString display = qgetenv("DISPLAY");
    if (display.isEmpty())
    {
        display = ":0.0";
    }
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("DISPLAY", display);
    xdpyinfoProcess.setProcessEnvironment(env);
    xdpyinfoProcess.start("xdpyinfo", QStringList());
    if (xdpyinfoProcess.waitForFinished(3000))
    {
        QByteArray output = xdpyinfoProcess.readAllStandardOutput();
        QString outputStr = QString::fromUtf8(output);
        // 使用正则表达式匹配 "dimensions: 1920x1080" 格式
        QRegularExpression re("dimensions:\\s+(\\d+x\\d+)");
        QRegularExpressionMatch match = re.match(outputStr);
        if (match.hasMatch())
        {
            resolution = match.captured(1);
        }
        else
        {
            // 如果标准输出中没有找到，尝试从标准错误中查找
            QByteArray errorOutput = xdpyinfoProcess.readAllStandardError();
            QString errorStr = QString::fromUtf8(errorOutput);
            match = re.match(errorStr);
            if (match.hasMatch())
            {
                resolution = match.captured(1);
            }
        }
    }
    
    if (resolution.isEmpty())
    {
        KLOG_ERROR() << "Failed to get screen resolution";
        return;
    }
    KLOG_INFO() << "screen resolution:" << resolution;

    // 逐一尝试编码器，按优先级：NVIDIA > Intel QSV > VAAPI > CPU
    QString codec = "libx264";
    QStringList extraArgs;
    bool codecFound = false;
    
    // 1. 尝试 NVIDIA h264_nvenc
    if (!codecFound)
    {
        QStringList nvencArgs;
        nvencArgs << "-preset" << "fast" << "-b:v" << "5M";
        if (tryCodec("h264_nvenc", nvencArgs, resolution, display, finalFileName))
        {
            codec = "h264_nvenc";
            extraArgs = nvencArgs;
            codecFound = true;
            KLOG_INFO() << "Selected Codec: h264_nvenc (NVIDIA)";
        }
    }
    
    // 2. 尝试 Intel h264_qsv
    if (!codecFound)
    {
        QStringList qsvArgs;
        if (tryCodec("h264_qsv", qsvArgs, resolution, display, finalFileName))
        {
            codec = "h264_qsv";
            extraArgs = qsvArgs;
            codecFound = true;
            KLOG_INFO() << "Selected Codec: h264_qsv (Intel)";
        }
    }
    
    // 3. 尝试 VAAPI (支持 Intel 和 AMD)
    if (!codecFound)
    {
        // 查找可用的 renderD 设备
        QDir driDir("/dev/dri");
        QStringList renderNodes = driDir.entryList(QStringList() << "renderD*", QDir::Files);
        
        // 尝试每个 renderD 设备
        for (const QString &renderNode : renderNodes)
        {
            QString renderDevice = "/dev/dri/" + renderNode;
            QStringList vaapiArgs;
            vaapiArgs << "-vaapi_device" << renderDevice 
                      << "-vf" << "format=nv12,hwupload";
            
            if (tryCodec("h264_vaapi", vaapiArgs, resolution, display, finalFileName))
            {
                codec = "h264_vaapi";
                extraArgs = vaapiArgs;
                codecFound = true;
                KLOG_INFO() << "Selected Codec: h264_vaapi (VAAPI), device:" << renderDevice;
                break;
            }
        }
    }
    
    // 4. 最后尝试 CPU 编码 libx264
    if (!codecFound)
    {
        QStringList cpuArgs;
        if (tryCodec("libx264", cpuArgs, resolution, display, finalFileName))
        {
            codec = "libx264";
            extraArgs = cpuArgs;
            codecFound = true;
            KLOG_INFO() << "Selected Codec: libx264 (CPU)";
        }
        else
        {
            KLOG_ERROR() << "All codecs test failed, using default CPU codec libx264";
            codec = "libx264";
            extraArgs.clear();
        }
    }
    
    KLOG_INFO() << "Final used codec:" << codec;

    // 构建并执行 ffmpeg 命令
    QString logFile = finalFileName + ".log";
    QStringList ffmpegArgs;
    ffmpegArgs << "-f" << "x11grab"
               << "-framerate" << "12"
               << "-video_size" << resolution
               << "-i" << display
               << "-c:v" << codec;
    ffmpegArgs << extraArgs;
    ffmpegArgs << finalFileName
               << "-y";

    KLOG_INFO() << "Start recording: ffmpeg" << ffmpegArgs.join(" ");
    
    // 启动 ffmpeg 进程，将输出重定向到日志文件
    // 设置 DISPLAY 环境变量
    QProcessEnvironment ffmpegEnv = QProcessEnvironment::systemEnvironment();
    ffmpegEnv.insert("DISPLAY", display);
    m_process.setProcessEnvironment(ffmpegEnv);
    m_process.setStandardOutputFile(logFile);
    m_process.setStandardErrorFile(logFile);
    m_process.start("ffmpeg", ffmpegArgs);
    
    if (!m_process.waitForStarted(3000))
    {
        KLOG_ERROR() << "Failed to start ffmpeg process";
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
    
    // 先尝试优雅地停止 ffmpeg（发送 SIGINT，相当于按 Ctrl+C）
    // ffmpeg 收到 SIGINT 后会正常结束并完成文件写入
    qint64 pid = m_process.processId();
    if (pid > 0)
    {
        KLOG_INFO() << "send SIGINT to ffmpeg process" << pid;
        kill(pid, SIGINT);
        
        // 等待进程正常结束，最多等待 5 秒
        if (m_process.waitForFinished(5000))
        {
            KLOG_INFO() << "ffmpeg process finished normally, exit";
        }
        else
        {
            KLOG_WARNING() << "ffmpeg process did not finish in time, forcing termination, exit";
            // 如果超时，强制终止
            m_process.kill();
            m_process.waitForFinished(1000);
        }
    }
    else
    {
        // 如果无法获取进程 ID，使用 terminate() 发送 SIGTERM
        KLOG_INFO() << "terminating ffmpeg process";
        m_process.terminate();
        if (!m_process.waitForFinished(5000))
        {
            KLOG_WARNING() << "ffmpeg process did not finish, forcing kill";
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