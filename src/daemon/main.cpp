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
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDBusMetaType>
#include <QFileInfo>
#include <QString>
#include <QTranslator>

#include "auth-config.h"
#include "auth-manager.h"
#include "config-daemon.h"
#include "device/device-adaptor-factory.h"
#include "kas-authentication-i.h"
#include "lib/feature-db.h"
#include "user-manager.h"
#include "config.h"

int main(int argc, char *argv[])
{
    auto argv0 = QFileInfo(argv[0]);
    auto programName = argv0.baseName();

    if (klog_qt5_init(KAS_ZLOG_CONFIG_FILE, "kylinsec-system", PROJECT_NAME, programName) < 0)
    {
        fprintf(stderr, "Failed to init kiran-log.");
    }

    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(programName);
    QCoreApplication::setApplicationVersion(PROJECT_VERSION);

    QTranslator translator;
    if (!translator.load(QLocale(), qAppName(), ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        KLOG_WARNING() << "Load translator failed!";
    }
    else
    {
        app.installTranslator(&translator);
    }

    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();
    parser.process(app);

    Kiran::FeatureDB::globalInit();
    Kiran::AuthConfig::globalInit();
    Kiran::UserManager::globalInit();
    Kiran::AuthManager::globalInit(Kiran::UserManager::getInstance(), Kiran::AuthConfig::getInstance());
    Kiran::DeviceAdaptorFactory::globalInit(Kiran::AuthManager::getInstance());

    KLOG_INFO() << Kiran::AuthConfig::getInstance();
    auto retval = app.exec();

    Kiran::DeviceAdaptorFactory::globalDeinit();
    Kiran::AuthManager::globalDeinit();
    Kiran::UserManager::globalDeinit();
    Kiran::AuthConfig::globalDeinit();

    return retval;
}
