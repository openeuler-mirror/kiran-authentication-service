#include <qt5-log-i.h>
#include <QDBusInterface>
#include <QDBusReply>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSettings>

#include "config.h"
#include "czht-code-driver.h"
#include "czht-error.h"

static const QString DBUS_INTERFACE = "com.czht.face.daemon";
static const QString DBUS_PATH = "/com/czht/face/daemon";

CZHTDriverCode::CZHTDriverCode(QObject *parent) : VirtualCodeDriver(parent)
{
    m_businessID = "KylinsecOS";

    KLOG_INFO() << "CZHTDriverCode config file:" << QString(VIRTUAL_CZHT_DRIVER_INSTALL_DIR) + "/config.ini";
    QSettings settings(QString(VIRTUAL_CZHT_DRIVER_INSTALL_DIR) + "/config.ini", QSettings::IniFormat);
    m_detectTimeOut = settings.value("detect_time_out").toInt();

    m_iface = new QDBusInterface(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE,
                                 QDBusConnection::systemBus(), this);
    if (!m_iface->isValid())
    {
        KLOG_ERROR() << "D-Bus interface invalid";
        return;
    }

    bool ret = QDBusConnection::systemBus().connect(
        DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE, "LeaveDetected", this,
        SLOT(leaveDetected(QString)));
    KLOG_INFO() << "connect to dbus signal com.czht.face.daemon.LeaveDetected:" << ret;
}

CZHTDriverCode::~CZHTDriverCode()
{
    // 断开 systemBus 上的信号连接
    QDBusConnection::systemBus().disconnect(
        DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE, "LeaveDetected", this,
        SLOT(leaveDetected(QString)));
}

QString CZHTDriverCode::getDriverName() { return tr("virtual-code-czht"); }

QString CZHTDriverCode::getErrorMsg(int errorNum)
{
    return getCZHTErrorMsg(errorNum);
}

DriverType CZHTDriverCode::getType() { return DRIVER_TYPE_Virtual_Code; }

int CZHTDriverCode::identify(const QString &extraInfo)
{
    return verifyAuthorizationCode(extraInfo);
}

int CZHTDriverCode::verifyAuthorizationCode(const QString &extraInfo)
{
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject extraInfoJsonObj = extraInfoJsonDoc.object();
    QString searchUserName = extraInfoJsonObj.value("user_name").toString();
    QString searchMachineCode = extraInfoJsonObj.value("machine_code").toString();
    QString authorizationCode = extraInfoJsonObj.value("code").toString();

    QJsonObject jsonObj;
    jsonObj.insert("business_id", m_businessID);
    jsonObj.insert("user_id", searchUserName);
    jsonObj.insert("code", authorizationCode);
    jsonObj.insert("device_code", searchMachineCode);

    QJsonDocument jsonDoc(jsonObj);

    auto reply = dbusCall("CodeCheck", jsonDoc.toJson());
    KLOG_INFO() << "CodeCheck reply:" << reply;
    jsonDoc = QJsonDocument::fromJson(reply.toUtf8());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();

    if (error_code != CZHT_SUCCESS)
    {
        KLOG_ERROR() << "CodeCheck failed:" << error_code << jsonObj;
        return error_code;
    }

    bool found = false;
    QJsonArray users = jsonObj.value("users").toArray();
    for (const QJsonValue &user : users)
    {
        QJsonObject userObj = user.toObject();
        QString person_id = userObj.value("person_id").toString();
        QString personName = userObj.value("person_name").toString();
        QString user_id = userObj.value("user_id").toString();
        QJsonArray device_code = userObj.value("device_code").toArray();
        KLOG_INFO() << "person_id:" << person_id << "personName:" << personName << "user_id:" << user_id << "device_code:" << device_code;
        if (device_code.contains(searchMachineCode))
        {
            // 人脸服务的用户，用于启动人走监测
            m_personNameLast = personName;
            found = true;
            break;
        }
    }

    if (!found)
    {
        KLOG_ERROR() << "StartSearch user not match:" << searchUserName << searchMachineCode;
        return CZHT_ERROR_USER_NOT_MATCH;
    }

    return CZHT_SUCCESS;
}

void CZHTDriverCode::identifySuccessedPostProcess(const QString &extraInfo)
{
    // 启动人走监测
    startLeaveDetect(extraInfo);

    // 授权码登录需要录屏
    QString osUser = extraInfo.split(" ")[0];
    QString fileName = QString("%1_%2_3.mp4").arg(m_personNameLast).arg(osUser).arg(QDateTime::currentDateTime().toString("yyyyMMddHHmmss"));
    QProcess::startDetached("sudo", QStringList() << "-u"
                                                  << osUser
                                                  << "kiran-screen-recorder"
                                                  << fileName);
}

int CZHTDriverCode::startLeaveDetect(const QString &extraInfo)
{
    QJsonObject jsonObj;
    jsonObj.insert("business_id", m_businessID);
    jsonObj.insert("user_id", m_personNameLast);
    jsonObj.insert("os_user", extraInfo);
    jsonObj.insert("detect_time_out", m_detectTimeOut);
    QJsonDocument jsonDoc(jsonObj);

    auto reply = dbusCall("StartLeaveDetect", jsonDoc.toJson());
    jsonDoc = QJsonDocument::fromJson(reply.toUtf8());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    if (error_code != CZHT_SUCCESS)
    {
        KLOG_ERROR() << "DBus call failed:" << error_code << jsonObj;
        return error_code;
    }
    else
    {
        QString error_msg = jsonObj.value("error_msg").toString();
        KLOG_INFO() << "Reply from service:" << error_code << error_msg << jsonObj;
        return error_code;
    }
}

QString CZHTDriverCode::dbusCall(QString method, QString args)
{
    KLOG_INFO() << "DBus call:" << method << args;
    QDBusReply<QString> reply = m_iface->call(method, args);
    if (reply.isValid())
    {
        return reply.value();
    }
    else
    {
        KLOG_INFO() << "Call failed:" << reply.error().message().toLocal8Bit();
        return "";
    }
}

void CZHTDriverCode::leaveDetected(QString info)
{
    KLOG_INFO() << "czht leave detected, Lock screen. info:" << info;
}

extern "C" Driver *createDriver() { return new CZHTDriverCode(); }