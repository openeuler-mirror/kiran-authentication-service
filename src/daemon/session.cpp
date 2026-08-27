/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     tangjie02 <tangjie02@kylinos.com.cn>
 */

#include <qt5-log-i.h>
#include <QDBusConnection>
#include <QDateTime>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaEnum>

#include "auth-manager.h"
#include "auxiliary.h"
#include "device/device-adaptor-factory.h"
#include "error.h"
#include "kas-authentication-i.h"
#include "lib/feature-db.h"
#include "lib/utils.h"
#include "logging-category.h"
#include "proxy/dbus-daemon-proxy.h"
#include "session.h"
#include "session_adaptor.h"
#include "user-manager.h"

namespace Kiran
{
Session::Session(uint32_t sessionID,
                 const QString &serviceName,
                 const QString &pamServiceName,
                 const QString &userName,
                 KADAuthApplication authApp,
                 QObject *parent)
    : QObject(parent),
      m_sessionID(sessionID),
      m_serviceName(serviceName),
      m_pamServiceName(pamServiceName),
      m_userName(userName),
      m_loginUserSwitchable(false),
      m_authApplication(authApp),
      m_authMode(KADAuthMode::KAD_AUTH_MODE_OR),
      m_authType(KADAuthType::KAD_AUTH_TYPE_NONE),
      m_gencodeProcess(nullptr)
{
    this->m_dbusAdaptor = new SessionAdaptor(this);
    this->m_objectPath = QDBusObjectPath(QString("%1/%2").arg(KAD_SESSION_DBUS_OBJECT_PATH).arg(this->m_sessionID));

    this->m_authMode = AuthManager::getInstance()->getAuthMode();
    auto authTypes = AuthManager::getInstance()->GetAuthTypeByApp(m_authApplication);
    this->m_authType = authTypes.count() > 0 ? authTypes.first() : KAD_AUTH_TYPE_NONE;
    if (m_authMode == KAD_AUTH_MODE_AND)
    {
        this->m_authOrderWaiting = authTypes;
        this->m_verifyInfo.m_authenticatedUserName = m_userName;
    }

    auto systemConnection = QDBusConnection::systemBus();
    if (!systemConnection.registerObject(this->m_objectPath.path(), this))
    {
        KLOG_WARNING() << m_sessionID << "can't register object:" << systemConnection.lastError();
    }

    KLOG_DEBUG() << QString("new session authmode(%1),login user switchable(%2),default auth type(%3),auth order(%4)")
                        .arg(m_authMode)
                        .arg(m_loginUserSwitchable)
                        .arg(Utils::authTypeEnum2Str(m_authType))
                        .arg(Utils::authOrderEnum2Str(m_authOrderWaiting).join(","));
}

Session::~Session()
{
    if (m_gencodeProcess)
    {
        if (m_gencodeProcess->state() != QProcess::NotRunning)
        {
            m_gencodeProcess->kill();
            m_gencodeProcess->waitForFinished(1000);
        }
        m_gencodeProcess->deleteLater();
        m_gencodeProcess = nullptr;
    }
}

int Session::getAuthType() const
{
    return m_authType;
}

uint Session::getID() const
{
    return m_sessionID;
}

QString Session::getRSAPublicKey() const
{
    // FIXME:暂时不做加密
    return "";
}

QString Session::getUsername() const
{
    return m_userName;
}

void Session::ResponsePrompt(const QString &text)
{
    RETURN_IF_FALSE(m_waitForResponseFunc);
    m_waitForResponseFunc(text);

    // SOFT_CODE_NO_CAMERA：菜单选择可多次重试，输入授权码为第二阶段，均需保留回调
    if (!(m_authType == KAD_AUTH_TYPE_SOFT_CODE_NO_CAMERA &&
          (m_authCodeStep == AUTH_CODE_STEP_SELECT || m_authCodeStep == AUTH_CODE_STEP_INPUT_CODE)))
    {
        m_waitForResponseFunc = nullptr;
    }
}

void Session::onAuthCodeSelectResponse(const QString &response)
{
    bool toIntOk = false;
    int choice = response.toInt(&toIntOk);
    if (!toIntOk || (choice != 1 && choice != 2))
    {
        // 无效选择：提示后回到菜单；累计 3 次则拒绝登录（不回退密码）
        m_invalidAuthCodeChoiceCount++;
        Q_EMIT this->AuthMessage(tr("Invalid choice"), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        if (m_invalidAuthCodeChoiceCount >= 3)
        {
            KLOG_WARNING() << m_sessionID << "too many invalid auth-code menu choices, reject login";
            this->finishPhaseAuth(SESSION_AUTH_NOT_MATCH);
            return;
        }
        Q_EMIT this->AuthMessage(tr("1. Request an authorization code 2. Input authorization code"),
                                 KADMessageType::KAD_MESSAGE_TYPE_INFO);
        Q_EMIT this->AuthPrompt(tr("please select:"), KADPromptType::KAD_PROMPT_TYPE_QUESTION);
        return;
    }

    m_invalidAuthCodeChoiceCount = 0;

    if (choice == 1)
    {
        // 执行 ks-auth-code-request --auto 命令申请授权码
        m_gencodeProcess = new QProcess(this);
        connect(m_gencodeProcess, static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
                this, &Session::onGencodeProcessFinished);
        m_gencodeProcess->start("ks-auth-code-request", QStringList() << "--auto" << "--user-name" << m_userName);

        if (!m_gencodeProcess->waitForStarted(5000))
        {
            Q_EMIT this->AuthMessage(tr("Failed to request authorization code, please try again."), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
            this->finishPhaseAuth(SESSION_AUTH_NOT_MATCH);
            return;
        }

        Q_EMIT this->AuthMessage(tr("Requesting authorization code, please wait..."), KADMessageType::KAD_MESSAGE_TYPE_INFO);
        m_authCodeStep = AUTH_CODE_STEP_INPUT_CODE;
        // 暂不设置下一阶段回调，进程退出后由 onGencodeProcessFinished 统一处理成功/失败
        m_waitForResponseFunc = nullptr;
    }
    else if (choice == 2)
    {
        Q_EMIT this->AuthMessage(tr("waiting for authorization code..."), KADMessageType::KAD_MESSAGE_TYPE_INFO);

        m_authCodeStep = AUTH_CODE_STEP_INPUT_CODE;
        // 重新设置 m_waitForResponseFunc 以处理下一阶段的输入
        m_waitForResponseFunc = [this](const QString &response)
        {
            onAuthCodeInputResponse(response);
        };
        Q_EMIT this->AuthPrompt(tr("please input authorization code:"), KADPromptType::KAD_PROMPT_TYPE_QUESTION);
    }
}

void Session::onAuthCodeInputResponse(const QString &response)
{
    if (response.trimmed().isEmpty())
    {
        Q_EMIT this->AuthMessage(tr("authorization code cannot be empty"), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        if (!retryAuthCodeInputAfterFailure())
        {
            this->finishPhaseAuth(SESSION_AUTH_NOT_MATCH);
        }
        return;
    }
    QJsonDocument jsonDoc(QJsonObject{{"user_name", m_userName}, {"code", response}});
    m_authStartMs = QDateTime::currentMSecsSinceEpoch();
    startGeneralAuth(jsonDoc.toJson());
}

bool Session::retryAuthCodeInputAfterFailure()
{
    m_authCodeVerifyFailCount++;
    if (m_authCodeVerifyFailCount >= 3)
    {
        KLOG_WARNING() << m_sessionID << "too many authorization code verify failures, reject login";
        return false;
    }

    // 校验失败后回到菜单，由用户重新选择申请或输入
    m_authCodeStep = AUTH_CODE_STEP_SELECT;
    m_waitForResponseFunc = [this](const QString &response)
    {
        if (m_authCodeStep == AUTH_CODE_STEP_SELECT)
        {
            onAuthCodeSelectResponse(response);
        }
        else if (m_authCodeStep == AUTH_CODE_STEP_INPUT_CODE)
        {
            onAuthCodeInputResponse(response);
        }
    };
    Q_EMIT this->AuthMessage(tr("1. Request an authorization code 2. Input authorization code"),
                             KADMessageType::KAD_MESSAGE_TYPE_INFO);
    Q_EMIT this->AuthPrompt(tr("please select:"), KADPromptType::KAD_PROMPT_TYPE_QUESTION);
    return true;
}

void Session::SetAuthType(int authType)
{
    if (this->m_authMode == KADAuthMode::KAD_AUTH_MODE_AND)
    {
        KLOG_WARNING() << m_sessionID << "can't change authentication type in this authentication mode" << m_authMode;
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_FAILED);
    }

    if (authType <= KAD_AUTH_TYPE_NONE || authType >= KAD_AUTH_TYPE_LAST)
    {
        DBUS_ERROR_REPLY_AND_RET(QDBusError::InvalidArgs, KADErrorCode::ERROR_INVALID_ARGUMENT);
    }
    this->m_authType = authType;
    KLOG_DEBUG() << m_sessionID << "session change auth type to:" << this->m_authType;
}

void Session::StartAuth()
{
    if (this->m_verifyInfo.m_requestID != -1)
    {
        KLOG_WARNING() << m_sessionID << "StartAuth rejected: device request still active"
                       << "requestID=" << this->m_verifyInfo.m_requestID
                       << "authType=" << this->m_authType
                       << "inAuth=" << this->m_verifyInfo.m_inAuth;
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_USER_IDENTIFIYING);
    }

    if (this->m_verifyInfo.m_inAuth)
    {
        KLOG_WARNING() << m_sessionID << "StartAuth rejected: auth already in process"
                       << "requestID=" << this->m_verifyInfo.m_requestID
                       << "authType=" << this->m_authType
                       << "inAuth=" << this->m_verifyInfo.m_inAuth;
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_USER_IDENTIFIYING);
    }

    KLOG_INFO() << m_sessionID << "StartAuth"
                << "user=" << m_userName
                << "authType=" << this->m_authType
                << "authMode=" << this->m_authMode;
    this->m_verifyInfo.m_inAuth = true;
    this->m_verifyInfo.m_dbusMessage = this->message();
    m_authStartMs = QDateTime::currentMSecsSinceEpoch();
    this->startPhaseAuth();
}

void Session::StopAuth()
{
    KLOG_INFO() << m_sessionID << "StopAuth"
                << "requestID=" << this->m_verifyInfo.m_requestID
                << "authType=" << this->m_authType
                << "inAuth=" << this->m_verifyInfo.m_inAuth;

    if (m_gencodeProcess && m_gencodeProcess->state() != QProcess::NotRunning)
    {
        m_gencodeProcess->kill();
        m_gencodeProcess->waitForFinished(1000);
        m_gencodeProcess->deleteLater();
        m_gencodeProcess = nullptr;
    }

    m_waitForResponseFunc = nullptr;

    if (this->m_verifyInfo.m_requestID != -1 &&
        this->m_verifyInfo.deviceAdaptor)
    {
        this->m_verifyInfo.deviceAdaptor->stop(this->m_verifyInfo.m_requestID);
    }

    this->m_verifyInfo.m_inAuth = false;
}

bool Session::GetLoginUserSwitchable()
{
    return m_loginUserSwitchable;
}

void Session::SetLoginUserSwitchable(bool switchable)
{
    if (this->m_authMode == KADAuthMode::KAD_AUTH_MODE_AND)
    {
        KLOG_WARNING() << m_sessionID << "can't set login-user-switchable in this authentication mode" << m_authMode;
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_FAILED);
    }

    if (m_verifyInfo.m_inAuth)
    {
        KLOG_WARNING() << m_sessionID << "can't set login-user-switchable when authentication is started";
        DBUS_ERROR_REPLY_AND_RET(QDBusError::AccessDenied, KADErrorCode::ERROR_FAILED);
    }

    RETURN_IF_FALSE(switchable != m_loginUserSwitchable);
    m_loginUserSwitchable = switchable;
    KLOG_DEBUG() << m_sessionID << "set login-user-switchable:" << m_loginUserSwitchable;
}

int32_t Session::getPriority()
{
    return DeviceRequestPriority::DEVICE_REQUEST_PRIORITY_LOW;
}

int64_t Session::getPID()
{
    return DBusDaemonProxy::getDefault()->getConnectionUnixProcessID(this->m_verifyInfo.m_dbusMessage);
}

QString Session::getSpecifiedUser()
{
    return this->m_userName;
}

void Session::queued(QSharedPointer<DeviceRequest> request)
{
    this->m_verifyInfo.m_requestID = request->reqID;
    KLOG_INFO() << m_sessionID << "session (request id:" << request->reqID << ") queued"
                << "authType=" << m_authType
                << "authTypeLocale=" << Utils::authTypeEnum2LocaleStr(m_authType);
    // 认证排队属于内部调度，不向 greeter 展示「录入请求正在处理」类提示，避免覆盖真实错误原因
}

void Session::interrupt()
{
    KLOG_DEBUG() << m_sessionID << "session (request id:" << this->m_verifyInfo.m_requestID << ") interrupt";
}

void Session::cancel()
{
    KLOG_DEBUG() << m_sessionID << "session (request id:" << this->m_verifyInfo.m_requestID << ") cancel";
    this->finishPhaseAuth(SESSION_AUTH_CANCEL);
}

void Session::end()
{
    KLOG_DEBUG() << m_sessionID << "session (request id:" << this->m_verifyInfo.m_requestID << ") end";
    this->m_verifyInfo.m_requestID = -1;
    this->m_verifyInfo.deviceAdaptor.clear();
}

void Session::onIdentifyStatus(const QString &bid, int result, const QString &message)
{
    KLOG_INFO() << m_sessionID << "onIdentifyStatus"
                << "bid=" << bid
                << "result=" << result
                << "message=" << message
                << "authType=" << this->m_verifyInfo.authType
                << "requestID=" << this->m_verifyInfo.m_requestID
                << "inAuth=" << this->m_verifyInfo.m_inAuth;

    // 软驱动认证类型，成功（MATCH）与失败（NOT_MATCH）均上报登录日志
    // 成功时 result=accept；失败时 result=reject（由 D-Bus 服务端按在线/离线决定是否持久化）
    if (result == IdentifyStatus::IDENTIFY_STATUS_MATCH &&
        (this->m_verifyInfo.authType == KAD_AUTH_TYPE_SOFT_FACE ||
         this->m_verifyInfo.authType == KAD_AUTH_TYPE_SOFT_CODE ||
         this->m_verifyInfo.authType == KAD_AUTH_TYPE_SOFT_CODE_NO_CAMERA))
    {
        this->m_verifyInfo.m_authenticatedUserName = this->getSpecifiedUser();
        const QString osUser = this->m_verifyInfo.m_authenticatedUserName;
        KLOG_INFO() << m_sessionID << "soft device authentication successfully, authenticated user name:" << osUser;

        // 构造 JSON 字符串 (C6: ReportLoginLog schema)
        QJsonObject jsonObj;
        jsonObj.insert("os_user", osUser);
        jsonObj.insert("user_name", this->m_userName);
        jsonObj.insert("result", QStringLiteral("accept"));
        jsonObj.insert("logged_at", QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
        jsonObj.insert("duration_ms", static_cast<qint64>(QDateTime::currentMSecsSinceEpoch() - m_authStartMs));
        QJsonDocument jsonDoc(jsonObj);
        this->m_verifyInfo.deviceAdaptor->identifyResultPostProcess(this, QString::fromUtf8(jsonDoc.toJson()));
    }
    else if (!this->matchUser(this->m_verifyInfo.authType, bid) &&
             result == IdentifyStatus::IDENTIFY_STATUS_MATCH)
    {
        KLOG_INFO() << m_sessionID << "feature match successfully, but it isn't a legal user.";
        result = IdentifyStatus::IDENTIFY_STATUS_NOT_MATCH;
    }

    auto verifyResultStr = Utils::identifyResultEnum2Str(result);
    if (result == IdentifyStatus::IDENTIFY_STATUS_MATCH)
    {
        Q_EMIT this->AuthMessage(verifyResultStr, KADMessageType::KAD_MESSAGE_TYPE_INFO);
    }
    else if (result == IdentifyStatus::IDENTIFY_STATUS_NOT_MATCH)
    {
        if (this->m_verifyInfo.authType == KAD_AUTH_TYPE_SOFT_FACE || this->m_verifyInfo.authType == KAD_AUTH_TYPE_SOFT_CODE || this->m_verifyInfo.authType == KAD_AUTH_TYPE_SOFT_CODE_NO_CAMERA)
        {
            // 离线失败：上报 reject 日志（D-Bus 服务端根据在线/离线决定是否持久化；在线时平台已有记录则跳过）
            {
                const QString osUser = this->getSpecifiedUser();
                QJsonObject jsonObj;
                jsonObj.insert("os_user", osUser);
                jsonObj.insert("user_name", this->m_userName);
                jsonObj.insert("result", QStringLiteral("reject"));
                jsonObj.insert("fail_reason", message);
                jsonObj.insert("logged_at", QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
                jsonObj.insert("duration_ms", static_cast<qint64>(QDateTime::currentMSecsSinceEpoch() - m_authStartMs));
                QJsonDocument jsonDoc(jsonObj);
                this->m_verifyInfo.deviceAdaptor->identifyResultPostProcess(this, QString::fromUtf8(jsonDoc.toJson()));
            }
            Q_EMIT this->AuthMessage(message, KADMessageType::KAD_MESSAGE_TYPE_ERROR);
            // 无摄像头授权码：校验失败允许会话内重试，满 3 次再拒绝
            if (this->m_verifyInfo.authType == KAD_AUTH_TYPE_SOFT_CODE_NO_CAMERA &&
                retryAuthCodeInputAfterFailure())
            {
                return;
            }
            this->finishPhaseAuth(SESSION_AUTH_NOT_MATCH);
            return;
        }
        else
        {
            // 优先展示设备上报的具体失败原因(如摄像头不可用/识别超时),
            // 设备未带消息时回退为通用枚举文案(与软类型分支行为一致)
            Q_EMIT this->AuthMessage(message.isEmpty() ? verifyResultStr : message,
                                     KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        }
    }
    else
    {
        Q_EMIT this->AuthMessage(message, KADMessageType::KAD_MESSAGE_TYPE_INFO);
    }

    if (result == IdentifyStatus::IDENTIFY_STATUS_MATCH ||
        result == IdentifyStatus::IDENTIFY_STATUS_NOT_MATCH)
    {
        this->finishPhaseAuth(result == IDENTIFY_STATUS_MATCH ? SESSION_AUTH_MATCH : SESSION_AUTH_NOT_MATCH);
    }
}

void Session::startPhaseAuth()
{
    KLOG_INFO() << m_sessionID << "startPhaseAuth"
                << "authType=" << this->m_authType
                << "requestID=" << this->m_verifyInfo.m_requestID
                << "inAuth=" << this->m_verifyInfo.m_inAuth;
    m_waitForResponseFunc = nullptr;

    // 开始阶段认证前,通知认证类型状态变更
    KLOG_INFO() << m_sessionID << "emit AuthTypeChanged authType=" << this->m_authType;
    emit this->m_dbusAdaptor->AuthTypeChanged(this->m_authType);

    switch (this->m_authType)
    {
    case KAD_AUTH_TYPE_UKEY:
        startUkeyAuth();
        break;
    case KAD_AUTH_TYPE_PASSWORD:
        startPasswdAuth();
        break;
    case KAD_AUTH_TYPE_SOFT_FACE:
        startSoftFaceAuth();
        break;
    case KAD_AUTH_TYPE_SOFT_CODE:
        startSoftCodeAuth();
        break;
    case KAD_AUTH_TYPE_SOFT_CODE_NO_CAMERA:
        startSoftCodeNoCameraAuth();
        break;
    default:
        startGeneralAuth();
        break;
    }
}

void Session::startUkeyAuth()
{
    m_waitForResponseFunc = [this](const QString &response)
    {
        QJsonDocument jsonDoc(QJsonObject{QJsonObject{{"ukey", QJsonObject{{"pin", response}}}}});
        startGeneralAuth(jsonDoc.toJson());
    };

    KLOG_DEBUG() << "auth prompt: input ukey code";
    Q_EMIT this->AuthMessage(tr("Insert the UKey and enter the PIN code"), KADMessageType::KAD_MESSAGE_TYPE_INFO);
    Q_EMIT this->AuthPrompt(tr("please input ukey code."), KADPromptType::KAD_PROMPT_TYPE_SECRET);
}

void Session::startSoftFaceAuth()
{
    QJsonDocument jsonDoc(QJsonObject{{"user_name", m_userName}});

    KLOG_INFO() << m_sessionID << "start soft face auth for user:" << m_userName;
    Q_EMIT this->AuthMessage(tr("Please look at the camera"), KADMessageType::KAD_MESSAGE_TYPE_INFO);

    startGeneralAuth(jsonDoc.toJson());
}

void Session::startSoftCodeAuth()
{
    m_waitForResponseFunc = [this](const QString &response)
    {
        if (response.trimmed().isEmpty())
        {
            Q_EMIT this->AuthMessage(tr("authorization code cannot be empty"), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
            this->finishPhaseAuth(SESSION_AUTH_NOT_MATCH);
            return;
        }
        QJsonDocument jsonDoc(QJsonObject{{"user_name", m_userName}, {"code", response}});
        m_authStartMs = QDateTime::currentMSecsSinceEpoch();
        startGeneralAuth(jsonDoc.toJson());
    };

    KLOG_DEBUG() << "auth prompt: input authorization code";
    Q_EMIT this->AuthMessage(tr("Please request for an authorization code and then enter it"), KADMessageType::KAD_MESSAGE_TYPE_INFO);
    Q_EMIT this->AuthPrompt(tr("please input authorization code."), KADPromptType::KAD_PROMPT_TYPE_QUESTION);
}

void Session::startSoftCodeNoCameraAuth()
{
    m_authCodeStep = AUTH_CODE_STEP_SELECT;
    m_gencodeProcess = nullptr;
    m_invalidAuthCodeChoiceCount = 0;
    m_authCodeVerifyFailCount = 0;

    m_waitForResponseFunc = [this](const QString &response)
    {
        if (m_authCodeStep == AUTH_CODE_STEP_SELECT)
        {
            onAuthCodeSelectResponse(response);
        }
        else if (m_authCodeStep == AUTH_CODE_STEP_INPUT_CODE)
        {
            onAuthCodeInputResponse(response);
        }
    };

    KLOG_DEBUG() << "auth prompt: select auth code mode";
    Q_EMIT this->AuthMessage(tr("1. Request an authorization code 2. Input authorization code"), KADMessageType::KAD_MESSAGE_TYPE_INFO);
    Q_EMIT this->AuthPrompt(tr("please select:"), KADPromptType::KAD_PROMPT_TYPE_QUESTION);
}

void Session::onGencodeProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (!m_gencodeProcess || !m_verifyInfo.m_inAuth)
    {
        if (m_gencodeProcess)
        {
            m_gencodeProcess->deleteLater();
            m_gencodeProcess = nullptr;
        }
        return;
    }

    if (exitCode != 0 || exitStatus != QProcess::NormalExit)
    {
        // 优先读 stdout：gen-code 的错误消息通过 printf 写入 stdout，
        // kiran-log-qt5 的 KLOG 只写 stderr，因此 stdout 是干净的。
        QString detail = QString::fromUtf8(m_gencodeProcess->readAllStandardOutput()).trimmed();
        if (detail.isEmpty())
        {
            detail = QString::fromUtf8(m_gencodeProcess->readAllStandardError()).trimmed();
        }
        KLOG_WARNING() << m_sessionID << "gencode command failed, exit code:" << exitCode << "error:" << detail;
        const QString msg = detail.isEmpty()
                                ? tr("Failed to request authorization code, please try again.")
                                : detail;
        Q_EMIT this->AuthMessage(msg, KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        // 图形终端（LightDM）：AuthFailed，由 greeter 重新认证，不回退密码。
        // 字符终端（SSH）：AuthUnavail → PAM_AUTHINFO_UNAVAIL；在 sshd 示例栈（default=bad/die）
        // 下会拒绝登录、不回退密码（勿再假设会落入 pam_unix）。
        const bool isGraphical = (m_pamServiceName == QLatin1String("lightdm"));
        this->finishPhaseAuth(isGraphical ? SESSION_AUTH_NOT_MATCH : SESSION_AUTH_INTERNAL_ERROR);
    }
    else
    {
        Q_EMIT this->AuthMessage(tr("Authorization code request successful. Please contact the device administrator to obtain it."), KADMessageType::KAD_MESSAGE_TYPE_INFO);
        m_authCodeStep = AUTH_CODE_STEP_INPUT_CODE;
        m_waitForResponseFunc = [this](const QString &response)
        {
            onAuthCodeInputResponse(response);
        };
        Q_EMIT this->AuthPrompt(tr("please input authorization code:"), KADPromptType::KAD_PROMPT_TYPE_QUESTION);
    }
    m_gencodeProcess->deleteLater();
    m_gencodeProcess = nullptr;
}

void Session::startPasswdAuth()
{
    KLOG_DEBUG() << "The authentication service does not take over password authentication,ignore!";

    this->m_verifyInfo.m_inAuth = true;
    if (this->m_verifyInfo.m_authenticatedUserName.isEmpty())
    {
        this->m_verifyInfo.m_authenticatedUserName = m_userName;
    }

    this->finishPhaseAuth(SESSION_AUTH_PASSWD_AUTH_IGNORE);
}

void Session::startGeneralAuth(const QString &extraInfo)
{
    KLOG_INFO() << m_sessionID << "start general auth for auth type:" << m_authType;
    auto deviceType = Utils::authType2DeviceType(this->m_authType);
    if (deviceType == -1)
    {
        auto authTypeStr = Utils::authTypeEnum2Str(this->m_authType);
        KLOG_WARNING() << m_sessionID << "start phase auth failed,invalid auth type:" << m_authType;
        Q_EMIT this->AuthMessage(tr(QString("Auth type %1 invalid").arg(authTypeStr).toStdString().c_str()), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        this->finishPhaseAuth(SESSION_AUTH_INTERNAL_ERROR);
        return;
    }

    auto device = DeviceAdaptorFactory::getInstance()->getDeviceAdaptor(this->m_authType);
    if (!device)
    {
        auto authTypeStr = Utils::authTypeEnum2Str(this->m_authType);
        KLOG_WARNING() << m_sessionID << "start phase auth failed,can not find device,auth type:" << m_authType;
        Q_EMIT this->AuthMessage(QString(tr("can not find %1 device")).arg(Utils::authTypeEnum2LocaleStr(this->m_authType)), KADMessageType::KAD_MESSAGE_TYPE_ERROR);
        this->finishPhaseAuth(SESSION_AUTH_NO_DEVICE);
        return;
    }

    QJsonObject rootObject;
    if (!extraInfo.isEmpty())
    {
        QJsonDocument tempDoc = QJsonDocument::fromJson(extraInfo.toUtf8());
        rootObject = tempDoc.object();
    }

    QJsonDocument doc(rootObject);

    QStringList bids;
    if (!m_loginUserSwitchable)  // 不允许切换用户，则只认证当前用户
    {
        auto user = UserManager::getInstance()->findUser(this->m_userName);
        if (user)
        {
            bids = user->getFeatureIDs(this->m_authType);
        }
    }

    rootObject["feature_ids"] = QJsonArray::fromStringList(bids);

    this->m_verifyInfo.deviceAdaptor = device;
    this->m_verifyInfo.authType = this->m_authType;
    this->m_verifyInfo.deviceAdaptor->identify(this, doc.toJson(QJsonDocument::Compact));
}

void Session::finishPhaseAuth(SessionAuthResult authResult)
{
    auto authResultEnum = QMetaEnum::fromType<Session::SessionAuthResult>();
    auto authResultKey = authResultEnum.valueToKey(authResult);

    KLOG_DEBUG() << m_sessionID
                 << "session finish phase auth, auth type:" << this->m_authType
                 << "auth result:" << (authResultKey ? authResultKey : "NULL");

    switch (authResult)
    {
    case SESSION_AUTH_MATCH:
    case SESSION_AUTH_PASSWD_AUTH_IGNORE:
    {
        if (this->m_authMode == KAD_AUTH_MODE_OR)
        {
            // 多路认证，认证一个通过即算通过
            this->finishAuth(authResult);
        }
        else
        {
            // 检测是否所有认证类型都已通过
            // 存在还未认证，则继续开始认证
            if (this->m_authOrderWaiting.size() > 0)
            {
                this->m_authOrderWaiting.removeOne(this->m_authType);
            }

            if (this->m_authOrderWaiting.size() == 0)
            {
                this->finishAuth(SESSION_AUTH_MATCH);
            }
            else
            {
                this->m_authType = this->m_authOrderWaiting.first();
                this->startPhaseAuth();
            }
        }
        break;
    }
    case SESSION_AUTH_NOT_MATCH:
    case SESSION_AUTH_NO_DEVICE:
    case SESSION_AUTH_CANCEL:
    case SESSION_AUTH_INTERNAL_ERROR:
    {
        KLOG_WARNING() << m_sessionID << "session failed phase auth, auth type:" << this->m_authType << "auth result:" << (authResultKey ? authResultKey : "NULL");
        // 阶段认证失败，则算失败
        this->finishAuth(authResult);
        break;
    }
    default:
        KLOG_ERROR() << m_sessionID << "invalid session auth result:" << authResult << (authResultKey ? authResultKey : "NULL");
        break;
    }
}

void Session::finishAuth(SessionAuthResult authResult)
{
    auto authResultEnum = QMetaEnum::fromType<Session::SessionAuthResult>();
    auto authResultKey = authResultEnum.valueToKey(authResult);
    KLOG_INFO() << m_sessionID << "finishAuth"
                << "authType=" << this->m_authType
                << "authResult=" << (authResultKey ? authResultKey : "NULL")
                << "requestID=" << this->m_verifyInfo.m_requestID
                << "inAuth=" << this->m_verifyInfo.m_inAuth;

    const QString &authenticatedUserName = this->m_verifyInfo.m_authenticatedUserName;
    bool isSuccess = (authResult == SESSION_AUTH_MATCH) || (authResult == SESSION_AUTH_PASSWD_AUTH_IGNORE);
    if (isSuccess)
    {
        if (authenticatedUserName.isEmpty())
        {
            KLOG_ERROR() << "authentication succeeded, but the user name was empty!";
        }
        else
        {
            auto user = UserManager::getInstance()->findUser(authenticatedUserName);
            if (user)
            {
                user->setFailures(0);
            }
            Q_EMIT this->AuthSuccessed(authenticatedUserName);
        }
    }
    else
    {
        // 是否记录内部错误，内部错误达到上限将不能使用生物认证，只能使用密码解锁
        // 只在多路认证情况下，并且是特征不匹配的情况下记录
        bool recordInternalFailure = (this->m_authMode == KAD_AUTH_MODE_OR) &&
                                     (authResult == SESSION_AUTH_NOT_MATCH);

        if (recordInternalFailure)
        {
            // 认证失败，未通过一次阶段认证，记录失败用户为发起登录请求的用户
            const QString &currentUser = authenticatedUserName.isEmpty() ? m_userName : authenticatedUserName;
            auto user = UserManager::getInstance()->findUser(currentUser);
            if (user)
            {
                user->setFailures(user->getFailures() + 1);
            }
        }

        // 是否记录外部failock错误，达到上限，将会锁定账户
        // 多因子认证情况下，任何错误，都将被failock记录
        // 多路认证情况下，只有特征不匹配才被failock记录
        bool recordFailure = (this->m_authMode == KAD_AUTH_MODE_AND) ||
                             (authResult == SESSION_AUTH_NOT_MATCH);

        if (recordFailure)
        {
            KLOG_INFO() << m_sessionID << "finishAuth emit AuthFailed"
                        << "authResult=" << (authResultKey ? authResultKey : "NULL");
            Q_EMIT this->AuthFailed();
        }
        else
        {
            KLOG_INFO() << m_sessionID << "finishAuth emit AuthUnavail"
                        << "authResult=" << (authResultKey ? authResultKey : "NULL");
            Q_EMIT this->AuthUnavail();
        }
    }

    m_verifyInfo.m_inAuth = false;
}

bool Session::matchUser(int32_t authType, const QString &dataID)
{
    RETURN_VAL_IF_TRUE(dataID.isEmpty(), false);

    // 特征匹配到的用户
    auto userName = FeatureDB::getInstance()->getUserNameByFetureID(dataID);
    KLOG_INFO() << m_sessionID << "match user:" << userName << "for feature id:" << dataID;

    RETURN_VAL_IF_TRUE(userName.isEmpty(), false);

    // 发起认证的用户
    auto specifiedUser = this->getSpecifiedUser();

    // 发起认证用户和特征匹配到的用户不一致 并且 登录用户切换功能未开启
    RETURN_VAL_IF_TRUE((userName != specifiedUser) && !m_loginUserSwitchable, false);

    // 用户切换功能只在第一阶段认证中生效，第一阶段认证通过后，后面的认证用户匹配必需和第一次一样
    RETURN_VAL_IF_TRUE(!this->m_verifyInfo.m_authenticatedUserName.isEmpty() && this->m_verifyInfo.m_authenticatedUserName != userName, false);

    // TODO: 会话复用时需要清理变量
    this->m_verifyInfo.m_authenticatedUserName = userName;
    return true;
}

}  // namespace Kiran
