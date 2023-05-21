#include "user-config.h"
#include "auxiliary.h"
#include "config-daemon.h"
#include "kas-authentication-i.h"
#include "src/utils/utils.h"

#include <qt5-log-i.h>
#include <QFile>
#include <QSettings>

#define INIFILE_GENERAL_GROUP_KEY_IIDS "IIDs"
// 连续认证失败次数计数
#define INIFILE_GENERAL_GROUP_KEY_FAILURES "Failures"

#define INIFILE_IID_GROUP_KEY_AUTH_TYPE "AuthType"
#define INIFILE_IID_GROUP_KEY_NAME "Name"
#define INIFILE_IID_GROUP_KEY_BID "Bid"

using namespace Kiran;

UserConfig::UserConfig(const QString& name, QObject* parent)
    : QObject(parent),
      m_userName(name)
{
    this->m_settings = new QSettings(QString(KDA_UESR_DATA_DIR "/").append(name), QSettings::IniFormat, this);
    init();
}

UserConfig::~UserConfig()
{
    // 如果缓存已经被清理，则删除文件
    if (this->m_settings->childGroups().size() == 0)
    {
        QFile file(this->m_settings->fileName());
        file.remove();
        this->m_settings = nullptr;
    }
}

void UserConfig::removeCache()
{
    this->m_settings->remove(QString());
}

bool UserConfig::deleteIID(const QString& iid)
{
    RETURN_VAL_IF_FALSE(this->m_settings->childGroups().contains(iid), false);

    this->m_iids.removeOne(iid);
    this->m_IIDAuthInfoMap.remove(iid);

    m_settings->setValue(INIFILE_GENERAL_GROUP_KEY_IIDS, this->m_iids);

    this->m_settings->beginGroup(iid);
    this->m_settings->remove("");
    this->m_settings->endGroup();

    return true;
}

bool UserConfig::renameIID(const QString& iid, const QString& name)
{
    RETURN_VAL_IF_FALSE(this->m_settings->childGroups().contains(iid), false);

    this->m_settings->beginGroup(iid);
    this->m_settings->setValue(INIFILE_IID_GROUP_KEY_NAME, name);
    this->m_settings->endGroup();

    m_IIDAuthInfoMap[iid].name = name;
    return true;
}

QStringList UserConfig::getIIDs()
{
    return m_iids;
}

QStringList UserConfig::getIIDs(int authType)
{
    QStringList iids;

    for (auto iter = this->m_IIDAuthInfoMap.begin(); iter != this->m_IIDAuthInfoMap.end(); iter++)
    {
        if (iter->authType == authType)
        {
            iids << iter.key();
        }
    }

    return iids;
}

QStringList UserConfig::getBIDs(int authType)
{
    QStringList bids;

    for (auto iter = this->m_IIDAuthInfoMap.begin(); iter != this->m_IIDAuthInfoMap.end(); iter++)
    {
        if (iter->authType == authType)
        {
            bids << iter->bid;
        }
    }

    return bids;
}

QString UserConfig::getIIDName(const QString& iid)
{
    auto iter = m_IIDAuthInfoMap.find(iid);

    if (iter == m_IIDAuthInfoMap.end())
    {
        // 正常逻辑,不应进入到该处
        return "";
    }

    return iter->name;
}

QString UserConfig::getIIDBid(const QString& iid)
{
    auto iter = m_IIDAuthInfoMap.find(iid);

    if (iter == m_IIDAuthInfoMap.end())
    {
        // 正常逻辑,不应进入到该处
        return "";
    }

    return iter->bid;
}

int UserConfig::getIIDAuthType(const QString& iid)
{
    auto iter = m_IIDAuthInfoMap.find(iid);

    if (iter == m_IIDAuthInfoMap.end())
    {
        // 正常逻辑不应进入到该处
        return KAD_AUTH_TYPE_NONE;
    }

    return iter->authType;
}

int UserConfig::getFailures()
{
    return m_failures;
}

void UserConfig::init()
{
    KLOG_DEBUG() << "user config:" << m_userName;

    auto iids = m_settings->value(INIFILE_GENERAL_GROUP_KEY_IIDS, QStringList()).toStringList();
    KLOG_DEBUG() << "iids:" << iids;

    // NOTE:错误次数记录只针对与多路认证模式
    // FIXME: 若多路认证模式错误次数过多，切换到多因子认证是否清理掉错误次数?
    this->m_failures = m_settings->value(INIFILE_GENERAL_GROUP_KEY_FAILURES, 0).toInt();
    KLOG_DEBUG() << "failures:" << this->m_failures;

    for (auto iid : iids)
    {
        m_settings->beginGroup(iid);

        auto name = m_settings->value(INIFILE_IID_GROUP_KEY_NAME, QString("")).toString();
        auto authTypeStr = m_settings->value(INIFILE_IID_GROUP_KEY_AUTH_TYPE, "").toString();
        auto bid = m_settings->value(INIFILE_IID_GROUP_KEY_BID, QString("")).toString();
        int authType = Utils::authTypeStr2Enum(authTypeStr);
        if (name.isEmpty() || authTypeStr.isEmpty() || authType == KAD_AUTH_MODE_NONE)
        {
            KLOG_WARNING() << "user config:" << m_settings->fileName() << "iid:" << iid << " value is invalid!";
            this->m_settings->remove(QString());
            m_settings->endGroup();
            continue;
        }
        IIDInfo iidInfo{
            .name = name,
            .authType = authType,
            .bid = bid};

        KLOG_DEBUG("feature name(%s) auth type(%s) iid(%s) bid(%s)",
                   name.toStdString().c_str(),
                   Utils::authTypeEnum2Str(authType).toStdString().c_str(),
                   iid.toStdString().c_str(),
                   bid.toStdString().c_str());

        m_IIDAuthInfoMap[iid] = iidInfo;
        m_iids << iid;

        m_settings->endGroup();
    }
}

bool UserConfig::addIID(int authType, const QString& iid, const QString& name, const QString& bid)
{
    RETURN_VAL_IF_FALSE(!this->m_settings->childGroups().contains(iid), false);

    QString authTypeStr = Utils::authTypeEnum2Str(authType);

    m_iids << iid;
    m_IIDAuthInfoMap[iid] = {.name = name, .authType = authType, .bid = bid};

    m_settings->setValue(INIFILE_GENERAL_GROUP_KEY_IIDS, m_iids);

    m_settings->beginGroup(iid);
    m_settings->setValue(INIFILE_IID_GROUP_KEY_AUTH_TYPE, authTypeStr);
    m_settings->setValue(INIFILE_IID_GROUP_KEY_NAME, name);
    m_settings->setValue(INIFILE_IID_GROUP_KEY_BID, bid);
    m_settings->endGroup();

    return true;
}

void UserConfig::changeIIDName(const QString& iid, const QString& name)
{
    if (!m_iids.contains(iid) || !m_IIDAuthInfoMap.contains(iid))
    {
        KLOG_ERROR() << "change iid name failed,can not find iid:" << iid;
        return;
    }

    m_IIDAuthInfoMap.find(iid)->name = name;

    m_settings->beginGroup(iid);
    m_settings->setValue(INIFILE_IID_GROUP_KEY_NAME, name);
    m_settings->endGroup();
}

void UserConfig::setFailures(int failures)
{
    RETURN_IF_TRUE(failures == m_failures);
    m_settings->setValue(INIFILE_GENERAL_GROUP_KEY_FAILURES, failures);
    m_failures = failures;
}