#pragma once

#include <QObject>
#include <QSharedPointer>

#include "src/device-manager/driver/virtual-face-driver.h"

class QDBusInterface;
class CZHTDriver : public VirtualFaceDriver
{
    Q_OBJECT
public:
    explicit CZHTDriver(QObject *parent = nullptr);
    ~CZHTDriver();

    QString getDriverName() override;
    QString getErrorMsg(int errorNum) override;
    DriverType getType() override;

    int identify(const QString &extraInfo) override;
    void identifySuccessedPostProcess(const QString &extraInfo) override;

private:
    QDBusInterface *getBusInterface();

    QString dbusCall(QString method, QString args);

    int startSearch(const QString &extraInfo);
    int startLeaveDetect(const QString &extraInfo);
    int stopLeaveDetect();

    // 处理锁屏信号连接与否
    void handleScreenLockSignal(bool connect = true);

private slots:
    void leaveDetected(QString info);
    void screenLockChanged(bool active);

private:
    QDBusInterface *m_iface;

    // 业务ID
    QString m_businessID;
    // 人脸搜索超时时间
    int m_searchTimeOut;
    // 人走监测超时时间
    int m_detectTimeOut;
    // 记录上一次识别的人名
    QString m_personNameLast;
};
typedef QSharedPointer<CZHTDriver> CZHTDriverPtr;
extern "C" Driver *
createDriver();
