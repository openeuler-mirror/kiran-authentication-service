/**
 * Copyright (c) 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     licheng <licheng@kylinsec.com.cn>
 */

#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QFileInfo>
#include <QTranslator>
#include <QDebug>

#include "config.h"
#include "gen-code-dialog.h"

static bool hasAutoFlag(int argc, char *argv[])
{
    for (int i = 1; i < argc; ++i)
    {
        if (QLatin1String(argv[i]) == QLatin1String("--auto"))
        {
            return true;
        }
    }
    return false;
}

int main(int argc, char *argv[])
{
    auto argv0 = QFileInfo(argv[0]);
    auto programName = argv0.baseName();
    QCoreApplication::setApplicationName(programName);
    QCoreApplication::setApplicationVersion(PROJECT_VERSION);

    if (hasAutoFlag(argc, argv))
    {
        QCoreApplication coreApp(argc, argv);

        QCommandLineParser parser;
        parser.setApplicationDescription("Kiran authorization code request tool");
        parser.addHelpOption();
        parser.addOption(QCommandLineOption("auto", "Request authorization code with default parameters and exit"));
        parser.process(coreApp);

        QString errorMsg = GenCodeDialog::requestAuthCodeCli();
        if (!errorMsg.isEmpty())
        {
            qCritical() << errorMsg;
            return 1;
        }
        return 0;
    }

    QApplication app(argc, argv);

    QCommandLineParser parser;
    parser.setApplicationDescription("Kiran authorization code request tool");
    parser.addHelpOption();
    parser.addOption(QCommandLineOption("auto", "Request authorization code with default parameters and exit"));
    parser.process(app);

    QTranslator translator;
    if (translator.load(QLocale(), qAppName(), ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        app.installTranslator(&translator);
    }

    GenCodeDialog dlg;
    dlg.exec();
    return 0;
}
