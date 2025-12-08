
#include <qt5-log-i.h>
#include <QCoreApplication>

#include "screen-recorder.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    if (klog_qt5_init("", "kylinsec-session", "kiran-authentication-devices", "kiran-screen-recorder") != 0)
    {
        fprintf(stderr, "Failed to init kiran-log.");
    }
    KLOG_INFO() << "----------------------";

    // 获取第一个参数
    QString fileName = argc > 1 ? argv[1] : "";
    ScreenRecorder recorder;
    recorder.start(fileName);

    return app.exec();
}
