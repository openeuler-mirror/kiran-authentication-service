#include <qt5-log-i.h>
#include <QDBusInterface>
#include <QDBusReply>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSettings>

#include "config.h"
#include "czht-driver.h"

static const QString DBUS_INTERFACE = "com.czht.face.daemon";
static const QString DBUS_PATH = "/com/czht/face/daemon";

// TODO: 需要诚志海图提供一份错误码信息
/*
1 JSON格式错误
2 缺少必需的JSON字段
3 参数范围超过限制
4 生成授权失败
5 授权验证失败
6 后端处理超时
7 正在执行其他任务
8 任务未执行
9 无法连接USB摄像头
10 主机通信异常
*/
enum CZHT_ERROR_NUM
{
    CZHT_SUCCESS = 0,
    CZHT_ERROR_JSON_FORMAT_ERROR = 1,
    CZHT_ERROR_MISSING_REQUIRED_FIELD = 2,
    CZHT_ERROR_PARAMETER_OUT_OF_RANGE = 3,
    CZHT_ERROR_GENERATE_AUTHORIZATION_FAILED = 4,
    CZHT_ERROR_AUTHORIZATION_VERIFICATION_FAILED = 5,
    CZHT_ERROR_BACKEND_PROCESS_TIMEOUT = 6,
    CZHT_ERROR_OTHER_TASK_EXECUTING = 7,
    CZHT_ERROR_TASK_NOT_EXECUTED = 8,
    CZHT_ERROR_CANNOT_CONNECT_USB_CAMERA = 9,
    CZHT_ERROR_HOST_COMMUNICATION_EXCEPTION = 10,
    CZHT_ERROR_USER_NOT_MATCH = 11,

    CZHT_ERROR_DAEMON_NOT_RUNNING = 100,
};

// 错误码对应的错误信息
static const QMap<int, QString> CZHT_ERROR_MSG = {
    {CZHT_SUCCESS, "成功"},
    {CZHT_ERROR_JSON_FORMAT_ERROR, "JSON格式错误"},
    {CZHT_ERROR_MISSING_REQUIRED_FIELD, "缺少必需的JSON字段"},
    {CZHT_ERROR_PARAMETER_OUT_OF_RANGE, "参数范围超过限制"},
    {CZHT_ERROR_GENERATE_AUTHORIZATION_FAILED, "生成授权失败"},
    {CZHT_ERROR_AUTHORIZATION_VERIFICATION_FAILED, "授权验证失败"},
    {CZHT_ERROR_BACKEND_PROCESS_TIMEOUT, "后端处理超时"},
    {CZHT_ERROR_OTHER_TASK_EXECUTING, "正在执行其他任务"},
    {CZHT_ERROR_TASK_NOT_EXECUTED, "任务未执行"},
    {CZHT_ERROR_CANNOT_CONNECT_USB_CAMERA, "无法连接USB摄像头"},
    {CZHT_ERROR_HOST_COMMUNICATION_EXCEPTION, "主机通信异常"},
    {CZHT_ERROR_USER_NOT_MATCH, "用户不匹配"},
    {CZHT_ERROR_DAEMON_NOT_RUNNING, "人脸服务未运行"},
};

CZHTDriver::CZHTDriver(QObject *parent) : VirtualFaceDriver(parent)
{
    m_businessID = "KylinsecOS";

    KLOG_INFO() << "CZHTDriver config file:" << QString(VIRTUAL_CZHT_DRIVER_INSTALL_DIR) + "/config.ini";
    QSettings settings(QString(VIRTUAL_CZHT_DRIVER_INSTALL_DIR) + "/config.ini", QSettings::IniFormat);
    m_searchTimeOut = settings.value("search_time_out").toInt();
    m_detectTimeOut = settings.value("detect_time_out").toInt();
    KLOG_INFO() << "CZHTDriver config: business_id:" << m_businessID << "search_time_out:" << m_searchTimeOut << "detect_time_out:" << m_detectTimeOut;

    m_iface = new QDBusInterface(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE,
                                 QDBusConnection::systemBus(), this);
    if (!m_iface->isValid())
    {
        KLOG_ERROR() << "D-Bus interface invalid";
        return;
    }

    // 人走监测由人脸服务完成，本驱动不处理
    // bool ret = QDBusConnection::systemBus().connect(
    //     DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE, "LeaveDetected", this,
    //     SLOT(leaveDetected(QString)));
    // KLOG_INFO() << "connect to dbus signal com.czht.face.daemon.LeaveDetected:" << ret;
}

CZHTDriver::~CZHTDriver()
{
    // 断开 systemBus 上的信号连接
    QDBusConnection::systemBus().disconnect(
        DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE, "LeaveDetected", this,
        SLOT(leaveDetected(QString)));

    // 断开锁屏信号连接
    handleScreenLockSignal(false);
}

QString CZHTDriver::getDriverName() { return tr("virtual-face-czht"); }

QString CZHTDriver::getErrorMsg(int errorNum)
{
    return CZHT_ERROR_MSG.value(errorNum);
}

DriverType CZHTDriver::getType() { return DRIVER_TYPE_Virtual_Face; }

int CZHTDriver::identify(const QString &extraInfo)
{
    return startSearch(extraInfo);
}

void CZHTDriver::identifySuccessedPostProcess(const QString &extraInfo)
{
    // 监听锁屏信号
    // handleScreenLockSignal();

    // 启动人走监测
    startLeaveDetect(extraInfo);
}

QDBusInterface *CZHTDriver::getBusInterface()
{
    if (!m_iface->isValid())
    {
        m_iface = new QDBusInterface(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE,
                                     QDBusConnection::systemBus(), this);
    }
    return m_iface;
}

QString CZHTDriver::dbusCall(QString method, QString args)
{
    QDBusInterface *iface = getBusInterface();
    if (!iface->isValid())
    {
        QJsonObject jsonObj;
        jsonObj.insert("code", CZHT_ERROR_DAEMON_NOT_RUNNING);
        QJsonDocument jsonDoc(jsonObj);
        KLOG_ERROR() << "D-Bus interface invalid";
        return jsonDoc.toJson();
    }

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

int CZHTDriver::startSearch(const QString &extraInfo)
{
    KLOG_INFO() << "CZHTDriver startSearch";
    QJsonDocument extraInfoJsonDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
    QJsonObject extraInfoJsonObj = extraInfoJsonDoc.object();
    QString searchUserName = extraInfoJsonObj.value("user_name").toString();
    QString searchMachineCode = extraInfoJsonObj.value("machine_code").toString();

    QJsonObject jsonObj;
    jsonObj.insert("business_id", m_businessID);
    jsonObj.insert("search_time_out", m_searchTimeOut);
    QJsonDocument jsonDoc(jsonObj);

    QString reply = dbusCall("StartSearch", jsonDoc.toJson());
    jsonDoc = QJsonDocument::fromJson(reply.toUtf8());
    jsonObj = jsonDoc.object();
    int error_code = jsonObj.value("code").toInt();
    KLOG_INFO() << "StartSearch reply:" << jsonObj;
    //StartSearch reply: QJsonObject({"business_id":"KylinsecOS","code":0,"users":[{"device_code":["0D8A-2D34-923E-180F"],"person_id":1,"person_name":"y","user_id":"root"},{"device_code":["0D8A-2D34-923E-180F"],"person_id":1,"person_name":"y","user_id":"root"}]})
    if (error_code != CZHT_SUCCESS)
    {
        KLOG_ERROR() << "StartSearch failed:" << error_code << jsonObj;
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
        if (user_id == searchUserName && device_code.contains(searchMachineCode))
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

int CZHTDriver::startLeaveDetect(const QString &extraInfo)
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

int CZHTDriver::stopLeaveDetect()
{
    QJsonObject jsonObj;
    jsonObj.insert("business_id", m_businessID);
    QJsonDocument jsonDoc(jsonObj);

    auto reply = dbusCall("StopLeaveDetect", jsonDoc.toJson());
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

void CZHTDriver::leaveDetected(QString info)
{
    // 锁屏
    KLOG_INFO() << "czht leave detected, Lock screen. info:" << info;
    // TODO: 需要适配底版本系统的锁屏命令

    // auto ret = QProcess::startDetached("sudo", {"-u", "root", "kiran-screensaver-command", "-l"});
    // KLOG_INFO() << "Lock screen result:" << ret;
    //调用 dbus "com.kylinsec.Kiran.ScreenSaver.Lock" 方法
    // QDBusInterface iface("com.kylinsec.Kiran.ScreenSaver", "/com/kylinsec/Kiran/ScreenSaver", "com.kylinsec.Kiran.ScreenSaver");
    // QDBusReply<void> reply = iface.call("Lock");
    // if (reply.isValid())
    // {
    //     KLOG_INFO() << "Lock screen result:" << reply.error().message();
    // }
    // else
    // {
    //     KLOG_INFO() << "Lock screen failed:" << reply.error().message();
    // }

    // 断开锁屏信号连接
    // handleScreenLockSignal(false);
}

void CZHTDriver::screenLockChanged(bool locked)
{
    KLOG_INFO() << "Screen lock changed, active:" << locked;
    if (!locked)
    {
        return;
    }

    // 停止监测
    stopLeaveDetect();
    // 断开锁屏信号连接
    handleScreenLockSignal(false);
}

void CZHTDriver::handleScreenLockSignal(bool connect)
{
    // NOTE: 需要适配底版本系统的锁屏命令
    // NOTE: 在随系统启动的程序中连接sessionBus会失败，应该另起一个程序，以当前认证用户连接sessionBus
    // // 锁屏信号连接、断开
    // bool ret = true;
    // if (connect)
    // {
    //     ret = QDBusConnection::sessionBus().connect(
    //         "com.kylinsec.Kiran.ScreenSaver", "/com/kylinsec/Kiran/ScreenSaver",
    //         "com.kylinsec.Kiran.ScreenSaver", "ActiveChanged", this,
    //         SLOT(screenLockChanged(bool)));
    //     KLOG_INFO() << "connect to dbus signal com.kylinsec.Kiran.ScreenSaver.ActiveChanged:" << ret;
    // }
    // else
    // {
    //     ret = QDBusConnection::sessionBus().disconnect(
    //         "com.kylinsec.Kiran.ScreenSaver", "/com/kylinsec/Kiran/ScreenSaver",
    //         "com.kylinsec.Kiran.ScreenSaver", "ActiveChanged", this,
    //         SLOT(screenLockChanged(bool)));
    //     KLOG_INFO() << "disconnect from dbus signal com.kylinsec.Kiran.ScreenSaver.ActiveChanged:" << ret;
    // }
}

extern "C" Driver *createDriver() { return new CZHTDriver(); }