#include <qt5-log-i.h>
#include <QDBusConnection>

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

void ScreenRecorder::start(const QString &fileName)
{
    QString command = QString("%1").arg(QString(VIRTUAL_CZHT_DRIVER_INSTALL_DIR) + "/recorder.sh");
    m_process.start(command, QStringList() << fileName);
}

void ScreenRecorder::stop()
{
    m_process.kill();
}

void ScreenRecorder::onScreenLockChanged(bool locked)
{
    KLOG_INFO() << "detect screen is" << (locked ? "Locked" : "Unlocked");
    if (locked)
    {
        stop();
    }
}