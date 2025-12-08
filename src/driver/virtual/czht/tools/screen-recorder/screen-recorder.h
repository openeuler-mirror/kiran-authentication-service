#pragma once

#include <QObject>
#include <QProcess>

class ScreenRecorder : public QObject
{
    Q_OBJECT
public:
    explicit ScreenRecorder(QObject *parent = nullptr);
    ~ScreenRecorder();

    void start(const QString &fileName);
    void stop();

public slots:
    void onScreenLockChanged(bool locked);

private:
    QProcess m_process;
};