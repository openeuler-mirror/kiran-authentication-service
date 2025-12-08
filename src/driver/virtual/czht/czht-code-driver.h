#pragma once

#include <QObject>
#include <QProcess>
#include <QSharedPointer>

#include "src/device-manager/driver/virtual-code-driver.h"

class QDBusInterface;
class CZHTDriverCode : public VirtualCodeDriver
{
    Q_OBJECT
public:
    explicit CZHTDriverCode(QObject *parent = nullptr);
    ~CZHTDriverCode();

    QString getDriverName() override;
    QString getErrorMsg(int errorNum) override;
    DriverType getType() override;

    int identify(const QString &extraInfo) override;
    void identifySuccessedPostProcess(const QString &extraInfo) override;

private:
    QString dbusCall(QString method, QString args);

    int verifyAuthorizationCode(const QString &extraInfo);
    int startLeaveDetect(const QString &extraInfo);

private slots:
    void leaveDetected(QString info);

private:
    QDBusInterface *m_iface;

    // 业务ID
    QString m_businessID;
    // 人走监测超时时间
    int m_detectTimeOut;
    // 记录上一次识别的人名
    QString m_personNameLast;
};
typedef QSharedPointer<CZHTDriverCode> CZHTDriverCodePtr;
extern "C" Driver *
createDriver();
