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
#include <QCoreApplication>
#include <QDBusMetaType>
#include <QFileInfo>
#include <QLocale>
#include <QTranslator>

#include "config.h"
#include "kas-authentication-i.h"
#include "lib/feature-data.h"
#include "lib/feature-db.h"
#include "manager.h"

int main(int argc, char *argv[])
{
    auto argv0 = QFileInfo(argv[0]);
    auto programName = argv0.baseName();

    QCoreApplication a(argc, argv);
    QCoreApplication::setApplicationName(programName);
    QCoreApplication::setApplicationVersion(PROJECT_VERSION);

    if (klog_qt5_init(KAS_ZLOG_CONFIG_FILE, "kylinsec-system", PROJECT_NAME, programName) < 0)
    {
        fprintf(stderr, "Failed to init kiran-log.");
    }

    QTranslator translator;
    QLocale locale;
    if (translator.load(locale, qAppName(), ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        a.installTranslator(&translator);
    }
    else
    {
        KLOG_WARNING() << "Load translator failed! Locale:" << locale.name();
    }

    Kiran::FeatureDB::globalInit();
    Kiran::Manager::globalInit();

    auto retval = a.exec();

    Kiran::Manager::globalDeint();
    Kiran::FeatureDB::globalDeinit();
    return retval;
}
