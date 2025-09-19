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
#include <QFile>
#include <QSettings>

#include "auxiliary.h"
#include "config-daemon.h"
#include "kas-authentication-i.h"
#include "lib/utils.h"
#include "user-config.h"

// 连续认证失败次数计数
#define INIFILE_GENERAL_GROUP_KEY_FAILURES "Failures"

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

int UserConfig::getFailures()
{
    return m_failures;
}

void UserConfig::init()
{
    KLOG_DEBUG() << "user config:" << m_userName;
    // NOTE:错误次数记录只针对与多路认证模式
    // FIXME: 若多路认证模式错误次数过多，切换到多因子认证是否清理掉错误次数?
    this->m_failures = m_settings->value(INIFILE_GENERAL_GROUP_KEY_FAILURES, 0).toInt();
    KLOG_DEBUG() << "failures:" << this->m_failures;
}

void UserConfig::setFailures(int failures)
{
    RETURN_IF_TRUE(failures == m_failures);
    m_settings->setValue(INIFILE_GENERAL_GROUP_KEY_FAILURES, failures);
    m_failures = failures;
}